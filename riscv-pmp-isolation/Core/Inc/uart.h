#ifndef UART_H
#define UART_H

#include <stdint.h>

void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);

/* Prints "<label>: 0x<16 hex digits>\n" -- the only numeric formatting
 * this freestanding build needs (no libc, no printf). */
void uart_print_hex(const char *label, uintptr_t val);

#endif /* UART_H */
