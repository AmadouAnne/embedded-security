#include "timing.h"
#include "app_config.h"
#include "FreeRTOS.h"
#include "task.h"

exec_acct_t g_acct[TID_COUNT];

volatile uint32_t g_epoch_tick = UINT32_MAX;
volatile uint32_t g_epoch_cyc;

void timing_init(void)
{
    DCB->DEMCR |= DCB_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

void acct_switch_in(void *tag)
{
    exec_acct_t *a = tag;
    if (a)
        a->in_stamp = DWT->CYCCNT;
}

void acct_switch_out(void *tag)
{
    exec_acct_t *a = tag;
    if (a)
        a->acc += DWT->CYCCNT - a->in_stamp;
}

/*
 * Returns the tick count of the current SysTick period and the CYCCNT value
 * at which that period began (the hardware reload instant). SysTick runs on
 * the core clock, so tick t + j starts exactly j * CYC_PER_TICK cycles later.
 * Read from hardware rather than from the tick hook, because the kernel calls
 * the hook with a stale tick count while the scheduler is suspended.
 */
void timing_tick_origin(uint32_t *tick, uint32_t *cyc)
{
    taskENTER_CRITICAL();
    uint32_t c = DWT->CYCCNT;
    uint32_t val = SysTick->VAL;
    uint32_t pending = SCB->ICSR & SCB_ICSR_PENDSTSET_Msk;
    uint32_t t = xTaskGetTickCount();
    /* A reload that happened before VAL was sampled is not yet counted. */
    if (pending && val > SysTick->LOAD / 2u)
        t++;
    *tick = t;
    *cyc = c - (SysTick->LOAD - val);
    taskEXIT_CRITICAL();
}

void vApplicationTickHook(void)
{
    extern void mitigation_tick(uint32_t tick);
    mitigation_tick(xTaskGetTickCountFromISR());
}

uint32_t link_timestamp(void)
{
    return DWT->CYCCNT;
}
