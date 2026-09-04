#ifndef PMP_H
#define PMP_H

#include <stdint.h>

/* Phase 2: configures two fixed PMP-enforced regions for the single
 * U-mode "untrusted" task:
 *   1. Its own code (.text.untrusted)      -- Read+Execute
 *   2. Its own scratch data + stack (.data.scratch) -- Read+Write
 * Every other address is denied to U-mode by PMP's fail-closed default
 * (no matching entry => access denied for U/S-mode; M-mode is exempt
 * unless an entry's lock bit is set, which none of these are). Kept for
 * reference alongside the real captured Phase 2 output documented in
 * README.md; superseded by pmp_configure_for_task() below for Phase 3's
 * multi-task scheduler, which needs to reprogram these same 4 PMP entries
 * for a *different* task on every context switch instead of once at boot. */
void pmp_configure(void);

/* Phase 3: same two-region shape as pmp_configure() above (own code R+X,
 * own data+stack R+W), but for an arbitrary task's bounds, reprogrammed on
 * every scheduler context switch (scheduler.c) -- the RISC-V/PMP structural
 * equivalent of FreeRTOS-MPU's per-task MemoryRegions being swapped in on
 * every context switch (see freertos-stm32's xTaskCreateRestricted()). */
void pmp_configure_for_task(uintptr_t code_start, uintptr_t code_end,
                             uintptr_t data_start, uintptr_t data_end);

#endif /* PMP_H */
