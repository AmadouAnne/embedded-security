#include "uart.h"
#include <stdint.h>

/* QEMU virt machine's ns16550a UART, byte-addressed (reg-shift 0),
 * confirmed via the machine's own device tree (serial@10000000,
 * compatible = "ns16550a", reg = <0x10000000 0x100>). */
#define UART_BASE 0x10000000UL
#define UART_THR  (*(volatile uint8_t *)(UART_BASE + 0))
#define UART_LSR  (*(volatile uint8_t *)(UART_BASE + 5))
#define UART_LSR_THRE 0x20u /* Transmit-holding-register-empty bit */

void uart_init(void)
{
    /* QEMU's ns16550a model accepts polled byte-at-a-time TX with no
     * divisor-latch/baud-rate programming needed for output to appear on
     * the emulated serial console -- nothing to configure here. A real
     * ns16550a on physical hardware would need that setup. */
}

void uart_putc(char c)
{
    while ((UART_LSR & UART_LSR_THRE) == 0) {
        /* wait for the transmit holding register to be empty */
    }
    UART_THR = (uint8_t)c;
}

void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

void uart_print_hex(const char *label, uintptr_t val)
{
    static const char digits[] = "0123456789abcdef";
    uart_puts(label);
    uart_puts(": 0x");
    for (int shift = (int)(sizeof(uintptr_t) * 8) - 4; shift >= 0; shift -= 4) {
        uart_putc(digits[(val >> shift) & 0xF]);
    }
    uart_puts("\n");
}
