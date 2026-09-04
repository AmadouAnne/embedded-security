#ifndef TRAP_H
#define TRAP_H

#include <stdint.h>

/* Installs `handler` as mtvec (direct mode: all traps vector to it exactly,
 * no offsetting by cause). Call once, before dropping to U-mode.
 * Phase 2 passed trap_handler (below, a plain C function using GCC's
 * "interrupt" attribute to auto-generate the save/restore prologue, since
 * it never resumes a DIFFERENT context -- it always halts). Phase 3 passes
 * trap_entry (context_switch.S) instead, which needs hand-written
 * assembly because it genuinely context-switches to a different task's
 * saved registers, something the "interrupt" attribute's generated
 * epilogue can't do. */
void trap_init(uintptr_t handler);

/* Phase 2's fault handler: reports the fault over UART, then powers off.
 * Kept for reference alongside the real captured Phase 2 output in
 * README.md; Phase 3 no longer installs it. */
void __attribute__((interrupt("machine"), aligned(4))) trap_handler(void);

#endif /* TRAP_H */
