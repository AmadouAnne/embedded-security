/* Machine-mode trap entry for the Phase 3 round-robin scheduler.
 *
 * Handles BOTH real PMP access faults (a task overstepped its granted
 * regions) and ordinary machine-timer interrupts (a normal preemption
 * tick) -- scheduler_on_trap() (scheduler.c) tells them apart by reading
 * mcause itself and decides what runs next either way. This file only
 * does the mechanical part: save every GPR of whichever task was
 * interrupted into ITS OWN context_t (so a genuinely different task can be
 * resumed afterwards, not just the one that trapped), call into C on a
 * dedicated M-mode stack, then restore whichever context scheduler_on_trap()
 * pointed `next_ctx` at.
 *
 * `mscratch` always holds the address of the CURRENTLY RUNNING task's
 * task_context_t while that task is executing in U-mode -- set once by
 * scheduler_start() before the very first mret, and re-set by the restore
 * path below before every subsequent mret, so the very next trap can find
 * it again with a single `csrrw`.
 *
 * The classic problem with saving x2 (sp) itself -- needing a spare
 * register to hold its value while using sp to address the save area --
 * is sidestepped on the save side by saving x5 first (freeing it as scratch)
 * and on the restore side with `ld sp, CTX_OFF_X2(sp)`, which is valid
 * RISC-V semantics: the load address is computed from sp's OLD value
 * before sp itself is overwritten with the result. No spare register
 * needed in either direction.
 */
#include "ctx_offsets.h"

.section .text
.global trap_entry
.extern scheduler_on_trap
.extern next_ctx

.align 4
trap_entry:
    /* sp <-> mscratch: sp now points at the interrupted task's
     * task_context_t; mscratch (temporarily) holds its real sp value. */
    csrrw   sp, mscratch, sp

    /* Save x5 (t0) first so it's immediately free to use as scratch for
     * everything else, including recovering the real sp value from
     * mscratch. */
    sd      x5, CTX_OFF_X5(sp)

    csrr    t0, mscratch
    sd      t0, CTX_OFF_X2(sp)     /* real x2 (sp) */

    sd      x1,  CTX_OFF_X1(sp)
    sd      x3,  CTX_OFF_X3(sp)
    sd      x4,  CTX_OFF_X4(sp)
    sd      x6,  CTX_OFF_X6(sp)
    sd      x7,  CTX_OFF_X7(sp)
    sd      x8,  CTX_OFF_X8(sp)
    sd      x9,  CTX_OFF_X9(sp)
    sd      x10, CTX_OFF_X10(sp)
    sd      x11, CTX_OFF_X11(sp)
    sd      x12, CTX_OFF_X12(sp)
    sd      x13, CTX_OFF_X13(sp)
    sd      x14, CTX_OFF_X14(sp)
    sd      x15, CTX_OFF_X15(sp)
    sd      x16, CTX_OFF_X16(sp)
    sd      x17, CTX_OFF_X17(sp)
    sd      x18, CTX_OFF_X18(sp)
    sd      x19, CTX_OFF_X19(sp)
    sd      x20, CTX_OFF_X20(sp)
    sd      x21, CTX_OFF_X21(sp)
    sd      x22, CTX_OFF_X22(sp)
    sd      x23, CTX_OFF_X23(sp)
    sd      x24, CTX_OFF_X24(sp)
    sd      x25, CTX_OFF_X25(sp)
    sd      x26, CTX_OFF_X26(sp)
    sd      x27, CTX_OFF_X27(sp)
    sd      x28, CTX_OFF_X28(sp)
    sd      x29, CTX_OFF_X29(sp)
    sd      x30, CTX_OFF_X30(sp)
    sd      x31, CTX_OFF_X31(sp)

    csrr    t0, mepc
    sd      t0, CTX_OFF_MEPC(sp)
    csrr    t0, mstatus
    sd      t0, CTX_OFF_MSTATUS(sp)

    /* Done saving -- sp still points at the (now fully populated) context
     * struct we just saved into. Switch to the scheduler's own M-mode
     * stack before calling into C: we must not run C code on a task's own
     * (small, PMP-limited-in-principle) stack any longer than necessary. */
    la      sp, scheduler_stack_top
    call    scheduler_on_trap

    /* scheduler_on_trap() has set next_ctx -- resume from there. */
    la      t0, next_ctx
    ld      sp, 0(t0)

    ld      t0, CTX_OFF_MEPC(sp)
    csrw    mepc, t0
    ld      t0, CTX_OFF_MSTATUS(sp)
    csrw    mstatus, t0

    ld      x1,  CTX_OFF_X1(sp)
    ld      x3,  CTX_OFF_X3(sp)
    ld      x4,  CTX_OFF_X4(sp)
    ld      x5,  CTX_OFF_X5(sp)
    ld      x6,  CTX_OFF_X6(sp)
    ld      x7,  CTX_OFF_X7(sp)
    ld      x8,  CTX_OFF_X8(sp)
    ld      x9,  CTX_OFF_X9(sp)
    ld      x10, CTX_OFF_X10(sp)
    ld      x11, CTX_OFF_X11(sp)
    ld      x12, CTX_OFF_X12(sp)
    ld      x13, CTX_OFF_X13(sp)
    ld      x14, CTX_OFF_X14(sp)
    ld      x15, CTX_OFF_X15(sp)
    ld      x16, CTX_OFF_X16(sp)
    ld      x17, CTX_OFF_X17(sp)
    ld      x18, CTX_OFF_X18(sp)
    ld      x19, CTX_OFF_X19(sp)
    ld      x20, CTX_OFF_X20(sp)
    ld      x21, CTX_OFF_X21(sp)
    ld      x22, CTX_OFF_X22(sp)
    ld      x23, CTX_OFF_X23(sp)
    ld      x24, CTX_OFF_X24(sp)
    ld      x25, CTX_OFF_X25(sp)
    ld      x26, CTX_OFF_X26(sp)
    ld      x27, CTX_OFF_X27(sp)
    ld      x28, CTX_OFF_X28(sp)
    ld      x29, CTX_OFF_X29(sp)
    ld      x30, CTX_OFF_X30(sp)
    ld      x31, CTX_OFF_X31(sp)

    /* mscratch = this context's address, ready for the NEXT trap's csrrw;
     * then load the real sp last, using sp's OLD (context-pointer) value
     * to address the load before it's overwritten by the result. */
    csrw    mscratch, sp
    ld      sp, CTX_OFF_X2(sp)
    mret

/* A dedicated 2KB M-mode stack for scheduler_on_trap() -- never touched by
 * either task, so a task's own (much smaller) stack is never at risk of
 * being clobbered by scheduler bookkeeping. */
.section .bss
.align 4
scheduler_stack_bottom:
    .space 2048
scheduler_stack_top:
