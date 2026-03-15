#ifndef SECURITY_H
#define SECURITY_H
#include "FreeRTOS.h"
#include "task.h"
void        Security_MPU_Init(void);
void        Security_StackGuard_Init(void);
void        Security_RegisterTask(const char *name, uint32_t *stack_top);
void        Security_CheckCanaries(void);
UBaseType_t Security_GetStackWatermark(const char *task_name);
void        Security_PrintReport(void);
#endif
