#include "uio_uart.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static volatile uint32_t *reg(uio_uart_t *u, unsigned off)
{
    return (volatile uint32_t *)((char *)u->base + off);
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

int uart_open(uio_uart_t *u, const char *dev)
{
    memset(u, 0, sizeof *u);
    u->fd = open(dev, O_RDWR | O_SYNC);
    if (u->fd < 0) {
        fprintf(stderr, "uart_open: cannot open %s: %s\n", dev, strerror(errno));
        return -1;
    }
    u->base = mmap(NULL, UIO_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, u->fd, 0);
    if (u->base == MAP_FAILED) {
        fprintf(stderr, "uart_open: Cannot mmap UART %s\n", dev);
        close(u->fd);
        u->fd = -1;
        u->base = NULL;
        return -1;
    }
    return 0;
}

void uart_close(uio_uart_t *u)
{
    if (u->base) munmap(u->base, UIO_MAP_SIZE);
    if (u->fd >= 0) close(u->fd);
    u->base = NULL;
    u->fd = -1;
}

uint32_t uart_stat(uio_uart_t *u) { return *reg(u, UARTLITE_STAT); }

void uart_reset_fifos(uio_uart_t *u)
{
    *reg(u, UARTLITE_CTRL) = CTRL_RST_TX | CTRL_RST_RX;
}

int uart_put(uio_uart_t *u, uint8_t b, unsigned timeout_us)
{
    uint64_t start = now_us();
    uint64_t spun = 0;

    while (uart_stat(u) & STAT_TX_FULL) {
        spun = now_us() - start;
        if (spun > timeout_us) {
            u->tx_stall_us += spun;
            return -1;
        }
    }
    if (spun) u->tx_stall_us += spun;

    *reg(u, UARTLITE_TX) = b;
    u->tx_bytes++;
    return 0;
}

int uart_get_nb(uio_uart_t *u, uint8_t *b)
{
    uint32_t s = uart_stat(u);
    if (s & STAT_OVERRUN) u->overruns++;
    if (!(s & STAT_RX_VALID)) return 0;
    *b = (uint8_t)(*reg(u, UARTLITE_RX) & 0xff);
    u->rx_bytes++;
    return 1;
}

int uart_write(uio_uart_t *u, const uint8_t *buf, size_t len, unsigned timeout_us)
{
    for (size_t i = 0; i < len; ++i)
        if (uart_put(u, buf[i], timeout_us) != 0) return -1;
    return 0;
}

/* Wait until the transmitter has actually put every queued byte on the wire.
 *
 * uart_write returns once the bytes are in the 16-deep FIFO, which for a
 * 168-byte work item is about 14.6ms before the last one is clocked out at
 * 115200 8N1. Anything that resets or re-drives TX in that window truncates the
 * item, and the FPGA's receiver -- a free-running byte counter with no framing --
 * then silently shifts by an unpredictable amount. */
int uart_drain_tx(uio_uart_t *u, unsigned timeout_us)
{
    uint64_t start = now_us();
    while (!(uart_stat(u) & STAT_TX_EMPTY)) {
        if (now_us() - start > timeout_us) return -1;
    }
    return 0;
}

void uart_purge_rx(uio_uart_t *u)
{
    uint8_t b;
    while (uart_get_nb(u, &b)) { /* discard */ }
}

int uart_wait_quiet(uio_uart_t *u, unsigned idle_us, unsigned timeout_us)
{
    uint64_t start = now_us();
    uint64_t last_activity = start;
    uint8_t b;

    for (;;) {
        if (uart_get_nb(u, &b)) {
            last_activity = now_us();          /* still talking; keep waiting */
        } else if (now_us() - last_activity >= idle_us) {
            return 0;
        }
        if (now_us() - start > timeout_us) return -1;
    }
}
