/* AXI UART Lite over UIO.
 *
 * The Zynq PL exposes three UartLite cores at 0x42c0_0000 / 0x42c1_0000 /
 * 0x42c2_0000, bound compatible="generic-uio" so the kernel's uartlite driver
 * never attaches and there is NO /dev/ttyUL* node. Userspace owns the registers.
 * DTB probe order puts them at /dev/uio8, uio9, uio10; board 0 is uio8.
 *
 * Line format is fixed in hardware at 115200 8N1 (xlnx,baudrate=115200,
 * data-bits=8, use-parity=0) — there is no divisor register to program.
 *
 * Register map is the Xilinx pg142 standard, corroborated by the DTB params and
 * the AXI UART Lite product guide shipped in the vendor's E300_development repo.
 */
#ifndef OSPREY_UIO_UART_H
#define OSPREY_UIO_UART_H

#include <stddef.h>
#include <stdint.h>

#define UARTLITE_RX     0x00
#define UARTLITE_TX     0x04
#define UARTLITE_STAT   0x08
#define UARTLITE_CTRL   0x0C

#define STAT_RX_VALID   (1u << 0)
#define STAT_RX_FULL    (1u << 1)
#define STAT_TX_EMPTY   (1u << 2)
#define STAT_TX_FULL    (1u << 3)
#define STAT_OVERRUN    (1u << 5)
#define STAT_FRAME_ERR  (1u << 6)
#define STAT_PARITY_ERR (1u << 7)

#define CTRL_RST_TX     (1u << 0)
#define CTRL_RST_RX     (1u << 1)

#define UIO_MAP_SIZE    0x10000

typedef struct {
    int      fd;
    void    *base;
    uint64_t tx_stall_us;    /* cumulative spin time waiting on TX_FULL */
    uint64_t overruns;       /* STAT_OVERRUN seen during reads */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
} uio_uart_t;

int      uart_open(uio_uart_t *u, const char *dev);
void     uart_close(uio_uart_t *u);
uint32_t uart_stat(uio_uart_t *u);
void     uart_reset_fifos(uio_uart_t *u);

/* Blocking single-byte write, gated on TX_FULL.
 *
 * UartLite silently DISCARDS a write to a full TX FIFO — there is no
 * backpressure and no error. Our FPGA receiver has no framing and a
 * free-running mod-168 byte counter, so a single dropped byte permanently
 * rotates every subsequent work item. Never write without this gate.
 * Returns 0, or -1 if the FIFO stayed full past timeout_us. */
int uart_put(uio_uart_t *u, uint8_t b, unsigned timeout_us);

/* Non-blocking read. Returns 1 and sets *b, or 0 if RX is empty. */
int uart_get_nb(uio_uart_t *u, uint8_t *b);

/* Write a whole buffer, TX_FULL-gated per byte. */
int uart_write(uio_uart_t *u, const uint8_t *buf, size_t len, unsigned timeout_us);

/* Drain and discard everything currently in RX. */
void uart_purge_rx(uio_uart_t *u);

/* Block until TX_EMPTY, i.e. the last queued byte has reached the wire.
 * Returns -1 on timeout. */
int  uart_drain_tx(uio_uart_t *u, unsigned timeout_us);

/* True once RX has been empty for at least idle_us.
 *
 * Quiet gate: OspreyBlake2bUartGetWork.vhd shares one baud counter between the
 * receiver and the transmitter, and an RX start bit asserts restartBaud, which
 * resets it. Transmitting while the FPGA is mid-reply garbles that reply. */
int uart_wait_quiet(uio_uart_t *u, unsigned idle_us, unsigned timeout_us);

#endif /* OSPREY_UIO_UART_H */
