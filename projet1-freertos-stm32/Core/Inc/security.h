#ifndef SECURITY_H
#define SECURITY_H
#include "FreeRTOS.h"
#include "task.h"
#include <stdint.h>

/* --- Stack canaries --------------------------------------------------- */
void        Security_StackGuard_Init(void);
void        Security_RegisterTask(const char *name, uint32_t *stack_top);
void        Security_CheckCanaries(void);
UBaseType_t Security_GetStackWatermark(const char *task_name);
void        Security_PrintReport(void);

/* --- MPU (static regions used before the scheduler starts) ------------ */
void        Security_MPU_Init(void);

/* --- Hardware watchdog (IWDG) -----------------------------------------
 * The IWDG counts down from an independent ~32kHz RC oscillator that is
 * NOT derived from the CPU clock and keeps running even if the core is
 * stuck in an infinite loop or the scheduler has died -- unlike a FreeRTOS
 * software timer, which only fires if the tick interrupt and scheduler are
 * still alive. Configured below for a ~1.6s timeout (< 2s requirement).
 *
 * Liveness model: every monitored task calls Security_Heartbeat() with its
 * own bit once per loop iteration. Security_KickIfHealthy(), called from
 * the fastest-period task, only refreshes the IWDG if *all* monitored bits
 * have been set since the last check -- so a single hung task is enough to
 * starve the refresh and force a reset within one timeout window. */
#define SECURITY_TASK_LED    (1U << 0)
#define SECURITY_TASK_UART   (1U << 1)
#define SECURITY_TASK_SENSOR (1U << 2)
#define SECURITY_TASK_ALL    (SECURITY_TASK_LED | SECURITY_TASK_UART | SECURITY_TASK_SENSOR)

void Security_IWDG_Init(void);
void Security_Heartbeat(uint32_t task_bit);
void Security_KickIfHealthy(void);

#endif
