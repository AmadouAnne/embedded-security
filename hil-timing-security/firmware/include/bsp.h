/* Board support: NUCLEO-F411RE, USART2 (ST-LINK VCP, PA2/PA3). */
#ifndef BSP_H
#define BSP_H

#include <stddef.h>
#include <stdint.h>

void bsp_init(void);

/* Blocking send through DMA; the caller sleeps until completion. */
void bsp_uart_send(const uint8_t *buf, size_t len);

/* Bytes received by the USART ISR, single producer / single consumer. */
size_t bsp_uart_read(uint8_t *dst, size_t max);
void bsp_uart_rx_enable(int on);

typedef struct {
    uint32_t rx_bytes;
    uint32_t rx_overflow;   /* bytes lost because the ring was full */
    uint32_t rx_hw_errors;  /* any of the three below */
    uint32_t rx_ore;        /* overrun: a byte arrived before the previous one was read */
    uint32_t rx_fe;         /* framing error: missing stop bit */
    uint32_t rx_ne;         /* noise detected on the line */
} uart_stats_t;

extern volatile uart_stats_t g_uart_stats;

void bsp_led(int on);

#endif
