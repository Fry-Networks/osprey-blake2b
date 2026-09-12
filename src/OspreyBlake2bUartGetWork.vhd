-- Copyright (c) 2026, Fry Networks.
-- Adapted from pedrorivera/SiaFpgaMiner Example/UartGetWork.vhd (MIT, 2017, Pedro Rivera).
--
-- === OspreyBlake2bUartGetWork.vhd ===
--
-- Byte-count-parameterised UART work interface. The Sia original hard-coded an
-- 80-byte RX header and an 8-byte (nonce-only) TX reply. The Knots BLAKE2b
-- pipeline needs a larger work item and a wider result, so kRxBytes/kTxBytes are
-- generics here and the TX payload is supplied as a flat vector instead of being
-- hard-wired to the nonce.
--
-- Framing is unchanged from the original: 8N1, LSB-first, no flow control.
-- The receiver shifts right, so the FIRST byte received ends up in the HIGH end
-- of workData. Slice constants in OspreyBlake2bUartTop.vhd depend on that.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

entity OspreyBlake2bUartGetWork is
  generic(
    -- Cycles per UART bit. Default: 250 MHz / 115200 baud = 2170.
    kBitTimeInClks : positive := 2170;
    kRxBytes       : positive := 168;
    kTxBytes       : positive := 17
  );
  port(
    aReset     : in  std_logic;
    Clk        : in  std_logic;
    aRx        : in  std_logic;
    Tx         : out std_logic;
    -- Pulses high for one cycle when a complete work item has been received.
    NewWork    : out boolean;
    WorkData   : out std_logic_vector(kRxBytes*8-1 downto 0);
    -- Rising edge latches ResultData and starts the reply transmission.
    Success    : in  boolean;
    ResultData : in  std_logic_vector(kTxBytes*8-1 downto 0);
    -- True while the transmitter is idle and will accept a Success THIS cycle.
    -- Without it there is no backpressure at all: a Success asserted while a
    -- frame is in flight is silently discarded, which is measurable throughput
    -- loss even at one core and becomes unfair starvation with several.
    -- This is a pure read of an existing state register -- it adds no logic to
    -- the RX or TX datapaths and cannot affect framing.
    ResultReady : out boolean
  );
end OspreyBlake2bUartGetWork;

architecture rtl of OspreyBlake2bUartGetWork is

  type RxState_t is (Idle, ShiftByte);
  type TxState_t is (Idle, LoadByte, ShiftOut);
  signal rxState : RxState_t;
  signal txState : TxState_t;

  signal rx, rx_ms, rx_dly : std_logic;
  signal bitTime      : boolean;   -- RX cell timing; re-phased on every start bit
  signal txBitTime    : boolean;   -- TX cell timing; free-running, never re-phased
  signal restartBaud  : boolean;
  signal rxBitCount, txBitCount   : natural;
  signal rxByteCount, txByteCount : natural;
  signal workDataLcl  : std_logic_vector(kRxBytes*8-1 downto 0);
  signal resultLcl    : std_logic_vector(kTxBytes*8-1 downto 0);
  signal byteOut      : std_logic_vector(9 downto 0); -- 1 start, 8 data, 1 stop
  signal clkCount     : integer := 0;
  signal txClkCount   : integer := 0;

begin

  -- Double-flop the async RX line, plus a delayed copy for start-bit edge detect.
  DS: process(aReset, Clk)
  begin
    if aReset = '1' then
      rx_ms  <= '1';
      rx     <= '1';
      rx_dly <= '1';
    elsif rising_edge(Clk) then
      rx_ms  <= aRx;
      rx     <= rx_ms;
      rx_dly <= rx;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- Baud generator. restartBaud preloads a negative count so the first bitTime
  -- lands 1.5 bit periods later, i.e. mid-cell of the first DATA bit.
  ---------------------------------------------------------------------------
  BaudGen: process(aReset, Clk)
  begin
    if aReset = '1' then
      bitTime  <= false;
      clkCount <= 0;
    elsif rising_edge(Clk) then
      bitTime  <= false;
      clkCount <= clkCount + 1;
      if restartBaud then
        clkCount <= -1*(kBitTimeInClks/2);
      elsif clkCount = kBitTimeInClks then
        bitTime  <= true;
        clkCount <= 0;
      end if;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- TX baud generator, deliberately SEPARATE from the RX one.
  --
  -- The transmitter used to share bitTime. But restartBaud is asserted by the
  -- RECEIVER on every start-bit edge and preloads clkCount to -(kBitTimeInClks/2)
  -- to centre RX sampling -- which also yanks the phase out from under any TX
  -- byte that happens to be in flight, shifting its remaining bit cells by up to
  -- half a cell. A 168-byte work item does that 168 times across 14.58 ms.
  --
  -- With one core and rare candidates the two almost never overlap, and the
  -- host's "three unparseable frames in a row -> resync" papers over the times
  -- they do. Once the result path is busy -- more cores, or simply a looser
  -- bring-up target -- a reception landing inside a frame stops being unlucky
  -- and becomes routine, and the corruption is silent: a shifted bit cell yields
  -- a well-formed frame carrying wrong bytes.
  --
  -- This counter free-runs and is never re-phased. TX cell width is therefore
  -- always exactly kBitTimeInClks regardless of what the receiver is doing. The
  -- RX path below is untouched.
  ---------------------------------------------------------------------------
  TxBaudGen: process(aReset, Clk)
  begin
    if aReset = '1' then
      txBitTime  <= false;
      txClkCount <= 0;
    elsif rising_edge(Clk) then
      txBitTime  <= false;
      txClkCount <= txClkCount + 1;
      if txClkCount = kBitTimeInClks then
        txBitTime  <= true;
        txClkCount <= 0;
      end if;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- Receiver: kRxBytes bytes, LSB-first, shifted in from the top.
  ---------------------------------------------------------------------------
  Receiver: process(aReset, Clk)
  begin
    if aReset = '1' then
      NewWork     <= false;
      restartBaud <= false;
      workDataLcl <= (others => '0');
      rxState     <= Idle;
      rxBitCount  <= 0;
      rxByteCount <= 0;
    elsif rising_edge(Clk) then

      NewWork <= false;

      case rxState is

        when Idle =>
          rxBitCount <= 0;
          if rx = '0' and rx_dly = '1' then   -- start bit
            rxState     <= ShiftByte;
            restartBaud <= true;
          end if;

        when ShiftByte =>
          restartBaud <= false;
          if rxBitCount < 8 then
            if bitTime then
              workDataLcl <= rx & workDataLcl(workDataLcl'high downto 1);
              rxBitCount  <= rxBitCount + 1;
            end if;
          else
            if rxByteCount = kRxBytes-1 then
              NewWork     <= true;
              rxByteCount <= 0;
            else
              rxByteCount <= rxByteCount + 1;
            end if;
            rxState <= Idle;
          end if;

      end case;
    end if;
  end process;

  WorkData <= workDataLcl;

  ---------------------------------------------------------------------------
  -- Transmitter: on Success, shift ResultData out LSB-byte first.
  ---------------------------------------------------------------------------
  Transmitter: process(aReset, Clk)
  begin
    if aReset = '1' then
      byteOut     <= (others => '1');  -- idle line high
      resultLcl   <= (others => '0');
      txState     <= Idle;
      txByteCount <= 0;
      txBitCount  <= 0;
    elsif rising_edge(Clk) then

      case txState is

        when Idle =>
          if Success then
            resultLcl   <= ResultData;
            txByteCount <= 0;
            txState     <= LoadByte;
          end if;

        when LoadByte =>
          if txBitTime then
            byteOut     <= '1' & resultLcl(7 downto 0) & '0';  -- stop & data & start
            resultLcl   <= x"00" & resultLcl(resultLcl'high downto 8);
            txByteCount <= txByteCount + 1;
            txBitCount  <= txBitCount + 1;
            txState     <= ShiftOut;
          end if;

        when ShiftOut =>
          if txBitTime then
            byteOut    <= '1' & byteOut(byteOut'high downto 1);
            txBitCount <= txBitCount + 1;
            if txBitCount = byteOut'length then
              txBitCount <= 0;
              if txByteCount < kTxBytes then
                txState <= LoadByte;
              else
                txState <= Idle;
              end if;
            end if;
          end if;

      end case;
    end if;
  end process;

  Tx <= byteOut(0);  -- LSB first

  ResultReady <= (txState = Idle);

end rtl;
