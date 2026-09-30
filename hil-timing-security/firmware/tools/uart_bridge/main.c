/*
 * Diagnostic UART bridge (not part of the experiment firmware).
 *
 * Forwards USART1 (PA10 RX / PA9 TX, wired to Raspberry Pi GPIO14/15) to
 * USART2 (ST-LINK virtual COM port) and back, at 115200 baud, so the Pi's
 * serial console can be read on the PC as /dev/ttyACM0. Runs on the 16 MHz
 * HSI with plain polling: nothing else to do, no RTOS needed.
 */
#include "stm32f4xx.h"

#define HSI_HZ 16000000u
#define BAUD   115200u

static void pin_af7(uint32_t pin)
{
    GPIOA->MODER = (GPIOA->MODER & ~(3u << (2u * pin))) | (2u << (2u * pin));
    GPIOA->AFR[pin >> 3] = (GPIOA->AFR[pin >> 3] & ~(0xFu << (4u * (pin & 7u)))) | (7u << (4u * (pin & 7u)));
}

static void uart_init(USART_TypeDef *u)
{
    u->BRR = (HSI_HZ + BAUD / 2u) / BAUD;
    u->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

int main(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN;
    RCC->APB1ENR |= RCC_APB1ENR_USART2EN;
    RCC->APB2ENR |= RCC_APB2ENR_USART1EN;
    (void)RCC->APB2ENR;

    pin_af7(2);  pin_af7(3);     /* USART2: ST-LINK VCP */
    pin_af7(9);  pin_af7(10);    /* USART1: Raspberry Pi */
    GPIOA->PUPDR |= GPIO_PUPDR_PUPD3_0 | GPIO_PUPDR_PUPD10_0;   /* idle-high RX */
    GPIOA->MODER = (GPIOA->MODER & ~GPIO_MODER_MODER5) | GPIO_MODER_MODER5_0;

    uart_init(USART1);
    uart_init(USART2);

    uint32_t blink = 0;
    for (;;) {
        /* 115200 baud = 1 byte / 87 us; the loop is far faster, so polling
           cannot drop bytes in either direction. Overrun flags are cleared by
           the SR-then-DR read sequence. */
        if (USART1->SR & (USART_SR_RXNE | USART_SR_ORE)) {
            uint8_t b = (uint8_t)USART1->DR;
            while (!(USART2->SR & USART_SR_TXE)) {}
            USART2->DR = b;
            GPIOA->ODR ^= GPIO_ODR_OD5;          /* LD2 flickers on Pi traffic */
        }
        if (USART2->SR & (USART_SR_RXNE | USART_SR_ORE)) {
            uint8_t b = (uint8_t)USART2->DR;
            while (!(USART1->SR & USART_SR_TXE)) {}
            USART1->DR = b;
        }
        if (++blink == 2000000u) {               /* heartbeat when idle */
            blink = 0;
            GPIOA->ODR ^= GPIO_ODR_OD5;
        }
    }
}
