#include "stm32f4xx_hal.h"
#include "fault_handlers.h"
#include <stdio.h>
#include <string.h>

extern UART_HandleTypeDef huart2;

/* Raw polling UART write -- deliberately does not go through the FreeRTOS
 * mutex/HAL abstractions used elsewhere: fault handlers run with interrupts
 * masked at a priority above the scheduler, so we only rely on direct
 * register-level busy-waiting (what HAL_UART_Transmit already reduces to in
 * blocking mode) and never touch RTOS primitives. */
static void fault_uart_print(const char *msg)
{
    HAL_UART_Transmit(&huart2, (uint8_t *)msg, strlen(msg), 200);
}

static void report_and_reset(const char *name)
{
    char buf[160];
    uint32_t cfsr  = SCB->CFSR;
    uint32_t mmfar = SCB->MMFAR;
    uint32_t bfar  = SCB->BFAR;

    snprintf(buf, sizeof(buf),
        "\r\n[SECURITY] %s trapped by MPU/fault unit\r\n"
        "  CFSR=0x%08lX MMFAR=0x%08lX BFAR=0x%08lX\r\n"
        "  -> illegal access blocked in hardware, resetting for isolation\r\n",
        name, (unsigned long)cfsr, (unsigned long)mmfar, (unsigned long)bfar);
    fault_uart_print(buf);

    /* Give the UART time to physically flush before the reset tears down
     * the peripheral clocks. */
    for (volatile uint32_t i = 0; i < 200000; i++) { __NOP(); }
    NVIC_SystemReset();
}

void MemManage_Handler(void)
{
    report_and_reset("MemManage fault (unauthorized memory access)");
}

void BusFault_Handler(void)
{
    report_and_reset("Bus fault");
}

void UsageFault_Handler(void)
{
    report_and_reset("Usage fault");
}

void FaultHandlers_Init(void)
{
    /* Make sure MemManage/BusFault/UsageFault are enabled as separate
     * exceptions instead of escalating straight to HardFault -- required
     * for MemManage_Handler above to actually be the one that runs. */
    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk |
                  SCB_SHCSR_BUSFAULTENA_Msk |
                  SCB_SHCSR_USGFAULTENA_Msk;
}
