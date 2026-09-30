#include "bsp.h"
#include "app_config.h"
#include "stm32f4xx.h"
#include "FreeRTOS.h"
#include "task.h"

#define RX_RING_SIZE 1024u   /* power of two */

static volatile uint8_t  rx_ring[RX_RING_SIZE];
static volatile uint32_t rx_head;   /* written by ISR */
static volatile uint32_t rx_tail;   /* written by reader */
static TaskHandle_t tx_waiter;

volatile uart_stats_t g_uart_stats;

/* HSI 16 MHz -> PLL -> 100 MHz SYSCLK, APB1 50 MHz, APB2 100 MHz. */
static void clock_init(void)
{
    RCC->APB1ENR |= RCC_APB1ENR_PWREN;
    PWR->CR |= PWR_CR_VOS;                          /* scale 1 (required for 100 MHz) */

    /* Keep the reserved bits at their reset value (RM0383 6.3.2). */
    RCC->PLLCFGR = (RCC->PLLCFGR & 0xF0BC8000u)
                 | (16u << RCC_PLLCFGR_PLLM_Pos)    /* 16/16  = 1 MHz */
                 | (200u << RCC_PLLCFGR_PLLN_Pos)   /* 1*200  = 200 MHz VCO */
                 | (0u << RCC_PLLCFGR_PLLP_Pos)     /* /2     = 100 MHz */
                 | (4u << RCC_PLLCFGR_PLLQ_Pos)     /* unused (no USB) */
                 | RCC_PLLCFGR_PLLSRC_HSI;
    RCC->CR |= RCC_CR_PLLON;
    while (!(RCC->CR & RCC_CR_PLLRDY)) {}

    /* 3 wait states at 100 MHz / 3.3 V; ART caches and prefetch on (reported in paper). */
    FLASH->ACR = FLASH_ACR_LATENCY_3WS | FLASH_ACR_PRFTEN
               | FLASH_ACR_ICEN | FLASH_ACR_DCEN;
    while ((FLASH->ACR & FLASH_ACR_LATENCY) != FLASH_ACR_LATENCY_3WS) {}

    RCC->CFGR = RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV2 | RCC_CFGR_PPRE2_DIV1
              | RCC_CFGR_SW_PLL;
    while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_PLL) {}

    SystemCoreClock = CPU_HZ;
}

/*
 * Host link selection (CMake option LINK_UART):
 *   2 = USART2 PA2/PA3, routed to the ST-LINK virtual COM port (USB bridge)
 *   1 = USART1 PA9 (TX, Arduino D8) / PA10 (RX, Arduino D2), direct 3.3 V
 *       UART to the Raspberry Pi GPIO14/15: no USB in the measurement path.
 */
#if LINK_UART == 1
#define LUART            USART1
#define LUART_IRQn       USART1_IRQn
#define LUART_IRQHandler USART1_IRQHandler
#define LUART_PCLK       CPU_HZ                 /* APB2 */
#define LDMA             DMA2
#define LSTREAM          DMA2_Stream7           /* channel 4 = USART1_TX */
#define LDMA_IRQn        DMA2_Stream7_IRQn
#define LDMA_IRQHandler  DMA2_Stream7_IRQHandler
#define LDMA_TC          DMA_HISR_TCIF7
#define LDMA_CLR_ALL     (DMA_HIFCR_CTCIF7 | DMA_HIFCR_CHTIF7 | DMA_HIFCR_CTEIF7 | DMA_HIFCR_CDMEIF7 | DMA_HIFCR_CFEIF7)
#define LDMA_CLR_TC      DMA_HIFCR_CTCIF7
#elif LINK_UART == 2
#define LUART            USART2
#define LUART_IRQn       USART2_IRQn
#define LUART_IRQHandler USART2_IRQHandler
#define LUART_PCLK       (CPU_HZ / 2u)          /* APB1 */
#define LDMA             DMA1
#define LSTREAM          DMA1_Stream6           /* channel 4 = USART2_TX */
#define LDMA_IRQn        DMA1_Stream6_IRQn
#define LDMA_IRQHandler  DMA1_Stream6_IRQHandler
#define LDMA_TC          DMA_HISR_TCIF6
#define LDMA_CLR_ALL     (DMA_HIFCR_CTCIF6 | DMA_HIFCR_CHTIF6 | DMA_HIFCR_CTEIF6 | DMA_HIFCR_CDMEIF6 | DMA_HIFCR_CFEIF6)
#define LDMA_CLR_TC      DMA_HIFCR_CTCIF6
#else
#error "LINK_UART must be 1 or 2"
#endif

static void pin_af7(uint32_t pin)
{
    GPIOA->MODER = (GPIOA->MODER & ~(3u << (2u * pin))) | (2u << (2u * pin));
    GPIOA->OSPEEDR |= 3u << (2u * pin);
    GPIOA->AFR[pin >> 3] = (GPIOA->AFR[pin >> 3] & ~(0xFu << (4u * (pin & 7u)))) | (7u << (4u * (pin & 7u)));
}

static void uart_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN | RCC_AHB1ENR_DMA1EN | RCC_AHB1ENR_DMA2EN;
#if LINK_UART == 1
    RCC->APB2ENR |= RCC_APB2ENR_USART1EN;
    (void)RCC->APB2ENR;
    pin_af7(9);
    pin_af7(10);
    GPIOA->PUPDR = (GPIOA->PUPDR & ~GPIO_PUPDR_PUPD10) | GPIO_PUPDR_PUPD10_0;   /* RX idle high */
#else
    RCC->APB1ENR |= RCC_APB1ENR_USART2EN;
    (void)RCC->APB1ENR;
    pin_af7(2);
    pin_af7(3);
    GPIOA->PUPDR = (GPIOA->PUPDR & ~GPIO_PUPDR_PUPD3) | GPIO_PUPDR_PUPD3_0;
#endif
    /* PA5 = LD2 output. */
    GPIOA->MODER = (GPIOA->MODER & ~GPIO_MODER_MODER5) | GPIO_MODER_MODER5_0;

    LUART->BRR = (LUART_PCLK + LINK_BAUD / 2u) / LINK_BAUD;
    LUART->CR3 = USART_CR3_DMAT;
    LUART->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE | USART_CR1_RXNEIE;

    LSTREAM->CR = 0;
    while (LSTREAM->CR & DMA_SxCR_EN) {}
    LSTREAM->PAR = (uint32_t)&LUART->DR;
    LSTREAM->CR = (4u << DMA_SxCR_CHSEL_Pos) | DMA_SxCR_MINC
                | DMA_SxCR_DIR_0 | DMA_SxCR_TCIE;

    /* Below configMAX_SYSCALL_INTERRUPT_PRIORITY so FromISR APIs are legal. */
    NVIC_SetPriority(LUART_IRQn, 6);
    NVIC_SetPriority(LDMA_IRQn, 7);
    NVIC_EnableIRQ(LUART_IRQn);
    NVIC_EnableIRQ(LDMA_IRQn);
}

void bsp_init(void)
{
    clock_init();
    uart_init();
}

void bsp_led(int on)
{
    GPIOA->BSRR = on ? GPIO_BSRR_BS5 : GPIO_BSRR_BR5;
}

void LUART_IRQHandler(void)
{
    uint32_t sr = LUART->SR;

    if (sr & (USART_SR_ORE | USART_SR_FE | USART_SR_NE)) {
        g_uart_stats.rx_hw_errors++;
        if (sr & USART_SR_ORE) g_uart_stats.rx_ore++;
        if (sr & USART_SR_FE)  g_uart_stats.rx_fe++;
        if (sr & USART_SR_NE)  g_uart_stats.rx_ne++;
    }
    if (sr & (USART_SR_RXNE | USART_SR_ORE)) {
        uint8_t b = (uint8_t)LUART->DR;   /* SR then DR read also clears ORE */
        uint32_t h = rx_head;
        g_uart_stats.rx_bytes++;
        if (h - rx_tail < RX_RING_SIZE) {
            rx_ring[h & (RX_RING_SIZE - 1u)] = b;
            rx_head = h + 1u;
        } else {
            g_uart_stats.rx_overflow++;
        }
    }
}

size_t bsp_uart_read(uint8_t *dst, size_t max)
{
    uint32_t t = rx_tail;
    uint32_t avail = rx_head - t;
    size_t n = avail < max ? avail : max;

    for (size_t i = 0; i < n; i++)
        dst[i] = rx_ring[(t + i) & (RX_RING_SIZE - 1u)];
    rx_tail = t + n;
    return n;
}

void bsp_uart_rx_enable(int on)
{
    if (on) {
        (void)LUART->SR;
        (void)LUART->DR;
        LUART->CR1 |= USART_CR1_RXNEIE;
    } else {
        LUART->CR1 &= ~USART_CR1_RXNEIE;
    }
}

void bsp_uart_send(const uint8_t *buf, size_t len)
{
    if (len == 0)
        return;
    tx_waiter = xTaskGetCurrentTaskHandle();
    LDMA->HIFCR = LDMA_CLR_ALL;
    LSTREAM->M0AR = (uint32_t)buf;
    LSTREAM->NDTR = len;
    LUART->SR &= ~USART_SR_TC;
    LSTREAM->CR |= DMA_SxCR_EN;
    /* Worst case at LINK_BAUD: 4 KiB take ~45 ms. */
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(200));
    tx_waiter = NULL;
}

void LDMA_IRQHandler(void)
{
    BaseType_t woken = pdFALSE;

    if (LDMA->HISR & LDMA_TC) {
        LDMA->HIFCR = LDMA_CLR_TC;
        if (tx_waiter)
            vTaskNotifyGiveFromISR(tx_waiter, &woken);
    }
    LDMA->HIFCR = LDMA_CLR_ALL & ~LDMA_CLR_TC;
    portYIELD_FROM_ISR(woken);
}
