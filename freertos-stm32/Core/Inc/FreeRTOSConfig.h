#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION                    1
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     1
#define configUSE_MALLOC_FAILED_HOOK            1
#define configCHECK_FOR_STACK_OVERFLOW          2
#define configCPU_CLOCK_HZ                      100000000UL
#define configTICK_RATE_HZ                      1000
#define configMAX_PRIORITIES                    7
#define configMINIMAL_STACK_SIZE                128
#define configTOTAL_HEAP_SIZE                   (20 * 1024)
#define configMAX_TASK_NAME_LEN                 16
#define configUSE_TRACE_FACILITY                1
#define configUSE_STATS_FORMATTING_FUNCTIONS    1
#define configUSE_16_BIT_TICKS                  0
#define configIDLE_SHOULD_YIELD                 1
#define configUSE_MUTEXES                       1
#define configUSE_COUNTING_SEMAPHORES           1
#define configQUEUE_REGISTRY_SIZE               8
#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               3
#define configTIMER_QUEUE_LENGTH                10
#define configTIMER_TASK_STACK_DEPTH            (configMINIMAL_STACK_SIZE * 2)
#define configSUPPORT_DYNAMIC_ALLOCATION        1
#define configSUPPORT_STATIC_ALLOCATION         0

/* --- MPU (memory protection) ---------------------------------------------
 * Enables the FreeRTOS-MPU "restricted task" API (xTaskCreateRestricted):
 * each task can be granted its own private RAM region on top of the kernel
 * and shared regions, enforced by the Cortex-M4 MPU hardware, not just by
 * convention. See security.c / tasks.c for the untrusted task demo. */
#define configTOTAL_MPU_REGIONS                          8
#define configTEX_S_C_B_FLASH                            (0x07UL)
#define configTEX_S_C_B_SRAM                             (0x07UL)
#define configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY      1
#define configINCLUDE_APPLICATION_DEFINED_PRIVILEGED_FUNCTIONS 0
#define configUSE_MPU_WRAPPERS_V1                        1
#define configALLOW_UNPRIVILEGED_CRITICAL_SECTIONS       0

#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY         15
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY    5
#define configKERNEL_INTERRUPT_PRIORITY         (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << 4)
#define configMAX_SYSCALL_INTERRUPT_PRIORITY    (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << 4)

#define configASSERT(x) if((x)==0){taskDISABLE_INTERRUPTS();for(;;);}

#define vPortSVCHandler     SVC_Handler
#define xPortPendSVHandler  PendSV_Handler
#define xPortSysTickHandler SysTick_Handler

#define INCLUDE_vTaskDelay                      1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_uxTaskGetStackHighWaterMark     1
#define INCLUDE_xTaskGetHandle                  1
#define INCLUDE_xTimerPendFunctionCall          1

#endif
