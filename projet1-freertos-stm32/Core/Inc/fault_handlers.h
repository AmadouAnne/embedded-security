#ifndef FAULT_HANDLERS_H
#define FAULT_HANDLERS_H

/* Overrides the weak MemManage_Handler/BusFault_Handler/UsageFault_Handler
 * provided by the CMSIS startup file. On a fault, dumps CFSR/MMFAR/BFAR
 * over UART (polling mode, safe to call from fault context) then performs
 * a controlled reset -- this is what makes the MPU violation demo visible
 * and safe to run repeatedly on real hardware instead of hanging forever. */
void FaultHandlers_Init(void);

#endif /* FAULT_HANDLERS_H */
