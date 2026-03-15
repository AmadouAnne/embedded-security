
#include "stm32f4xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "security.h"
#include <string.h>
#include <stdio.h>

extern UART_HandleTypeDef huart2;

#define CANARY_VALUE   0xDEADBEEF
#define MAX_TASKS      8

typedef struct { char name[16]; uint32_t *stack_top; } TaskGuard_t;
static TaskGuard_t guards[MAX_TASKS];
static uint8_t     guard_count = 0;

void Security_MPU_Init(void)
{
    MPU_Region_InitTypeDef r = {0};
    HAL_MPU_Disable();
    r.Enable=MPU_REGION_ENABLE; r.Number=MPU_REGION_NUMBER0;
    r.BaseAddress=0x08000000; r.Size=MPU_REGION_SIZE_512KB;
    r.AccessPermission=MPU_REGION_PRIV_RO_URO; r.DisableExec=MPU_INSTRUCTION_ACCESS_ENABLE;
    r.TypeExtField=MPU_TEX_LEVEL0; r.IsCacheable=MPU_ACCESS_CACHEABLE;
    r.IsShareable=MPU_ACCESS_NOT_SHAREABLE; r.IsBufferable=MPU_ACCESS_NOT_BUFFERABLE;
    r.SubRegionDisable=0x00;
    HAL_MPU_ConfigRegion(&r);
    r.Number=MPU_REGION_NUMBER1; r.BaseAddress=0x20000000; r.Size=MPU_REGION_SIZE_128KB;
    r.AccessPermission=MPU_REGION_FULL_ACCESS; r.DisableExec=MPU_INSTRUCTION_ACCESS_DISABLE;
    HAL_MPU_ConfigRegion(&r);
    r.Number=MPU_REGION_NUMBER2; r.BaseAddress=0x40000000; r.Size=MPU_REGION_SIZE_512MB;
    r.AccessPermission=MPU_REGION_FULL_ACCESS; r.DisableExec=MPU_INSTRUCTION_ACCESS_DISABLE;
    r.TypeExtField=MPU_TEX_LEVEL0; r.IsShareable=MPU_ACCESS_SHAREABLE;
    r.IsCacheable=MPU_ACCESS_NOT_CACHEABLE; r.IsBufferable=MPU_ACCESS_BUFFERABLE;
    HAL_MPU_ConfigRegion(&r);
    HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
}

void Security_StackGuard_Init(void) { memset(guards,0,sizeof(guards)); guard_count=0; }

void Security_RegisterTask(const char *name, uint32_t *stack_top)
{
    if(guard_count>=MAX_TASKS) return;
    strncpy(guards[guard_count].name,name,15);
    guards[guard_count].stack_top=stack_top;
    *stack_top=CANARY_VALUE;
    guard_count++;
}

void Security_CheckCanaries(void)
{
    char msg[128];
    for(uint8_t i=0;i<guard_count;i++){
        if(*guards[i].stack_top!=CANARY_VALUE){
            snprintf(msg,sizeof(msg),"[SECURITY] STACK OVERFLOW: %s
",guards[i].name);
            HAL_UART_Transmit(&huart2,(uint8_t*)msg,strlen(msg),100);
            NVIC_SystemReset();
        }
    }
}

UBaseType_t Security_GetStackWatermark(const char *name)
{
    TaskHandle_t h=xTaskGetHandle(name);
    return h ? uxTaskGetStackHighWaterMark(h) : 0;
}

void Security_PrintReport(void)
{
    char msg[256];
    snprintf(msg,sizeof(msg),
        "
=== SECURITY REPORT ===
"
        "  Heap free : %u
  MPU : ACTIVE
  Canaries : %u tasks
",
        (unsigned)xPortGetFreeHeapSize(),(unsigned)guard_count);
    HAL_UART_Transmit(&huart2,(uint8_t*)msg,strlen(msg),200);
}
