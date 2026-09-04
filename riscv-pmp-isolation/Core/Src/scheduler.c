#include "scheduler.h"
#include "pmp.h"
#include "uart.h"
#include "clint.h"
#include "sifive_test.h"
#include "trap.h"
#include <stddef.h>

_Static_assert(offsetof(task_context_t, gprs) == 0, "ctx_offsets.h out of sync");
_Static_assert(offsetof(task_context_t, mepc) == CTX_OFF_MEPC, "ctx_offsets.h out of sync");
_Static_assert(offsetof(task_context_t, mstatus) == CTX_OFF_MSTATUS, "ctx_offsets.h out of sync");
_Static_assert(sizeof(task_context_t) == CTX_SIZE, "ctx_offsets.h out of sync");

sched_task_t sched_tasks[SCHED_NUM_TASKS];
task_context_t *next_ctx;

static volatile int sched_current;

/* Provided by the linker script -- exact bounds of each task's own code
 * and data (data includes that task's own stack, same convention as
 * Phase 2's .text.untrusted/.data.scratch). */
extern char _taska_text_start[], _taska_text_end[];
extern char _taska_data_start[], _taska_data_end[];
extern char _taskb_text_start[], _taskb_text_end[];
extern char _taskb_data_start[], _taskb_data_end[];

extern void task_a_entry(void);
extern void task_b_entry(void);
extern const uintptr_t task_a_stack_top;
extern const uintptr_t task_b_stack_top;
extern volatile uint32_t task_a_counter;
extern volatile uint32_t task_b_counter;

extern void trap_entry(void); /* context_switch.S */

static const char *describe_mcause(uintptr_t cause)
{
    switch (cause) {
        case 1: return "Instruction access fault (PMP denied fetch)";
        case 5: return "Load access fault (PMP denied read)";
        case 7: return "Store/AMO access fault (PMP denied write)";
        default: return "Unexpected trap (not a PMP access fault)";
    }
}

static void init_task(int idx, const char *name, void (*entry)(void),
                       uintptr_t stack_top, uintptr_t code_start, uintptr_t code_end,
                       uintptr_t data_start, uintptr_t data_end, uintptr_t mstatus_u)
{
    sched_task_t *t = &sched_tasks[idx];
    t->name = name;
    t->code_start = code_start;
    t->code_end   = code_end;
    t->data_start = data_start;
    t->data_end   = data_end;
    t->alive = 1;
    t->ctx.mepc = (uintptr_t)entry;
    t->ctx.mstatus = mstatus_u;
    t->ctx.gprs[CTX_OFF_X2 / sizeof(uintptr_t)] = stack_top; /* x2 = sp */
}

void scheduler_init(void)
{
    uintptr_t mstatus_val;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus_val));
    mstatus_val &= ~(uintptr_t)(3u << 11); /* MPP = 00 (U-mode) for both tasks */

    init_task(0, "TaskA", task_a_entry, task_a_stack_top,
              (uintptr_t)_taska_text_start, (uintptr_t)_taska_text_end,
              (uintptr_t)_taska_data_start, (uintptr_t)_taska_data_end,
              mstatus_val);
    init_task(1, "TaskB", task_b_entry, task_b_stack_top,
              (uintptr_t)_taskb_text_start, (uintptr_t)_taskb_text_end,
              (uintptr_t)_taskb_data_start, (uintptr_t)_taskb_data_end,
              mstatus_val);

    sched_current = 0;

    /* PMP resets with every entry disabled (A=OFF), under which U-mode's
     * fail-closed default denies EVERYTHING -- including fetching the
     * very first instruction of whichever task mret drops into. Must be
     * configured for task 0 before scheduler_start()'s first mret, not
     * only from inside scheduler_on_trap() (which only runs starting from
     * the *second* trap onward). Confirmed via QEMU + GDB: without this,
     * mret itself is immediately followed by an instruction access fault,
     * before ever reaching task_a_entry. */
    pmp_configure_for_task(sched_tasks[0].code_start, sched_tasks[0].code_end,
                            sched_tasks[0].data_start, sched_tasks[0].data_end);

    trap_init((uintptr_t)trap_entry);
    clint_init();
}

void __attribute__((noreturn)) scheduler_start(void)
{
    /* mscratch must point at the FIRST task's context before its very
     * first mret -- every later trap finds it there via context_switch.S's
     * csrrw, but nothing has run yet to set it up until now. */
    __asm__ volatile("csrw mscratch, %0" :: "r"(&sched_tasks[sched_current].ctx));

    uart_puts("[sched] starting TaskA (U-mode), TaskB waiting in the run queue\n");

    task_context_t *first = &sched_tasks[sched_current].ctx;
    __asm__ volatile(
        "mv   t0, %0\n"
        "ld   t1, %1(t0)\n"      /* mepc */
        "csrw mepc, t1\n"
        "ld   t1, %2(t0)\n"      /* mstatus */
        "csrw mstatus, t1\n"
        "ld   sp, %3(t0)\n"      /* x2 (sp) -- last, same "load through old value" trick */
        "mret\n"
        :: "r"(first), "i"(CTX_OFF_MEPC), "i"(CTX_OFF_MSTATUS), "i"(CTX_OFF_X2)
        : "t0", "t1", "memory"
    );
    __builtin_unreachable();
}

void scheduler_on_trap(void)
{
    uintptr_t mcause, mepc, mtval;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));

    uintptr_t int_bit = (uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1);
    int is_interrupt = (mcause & int_bit) != 0;
    uintptr_t code = mcause & ~int_bit;

    if (!is_interrupt) {
        uart_puts("\n=== TRAP: PMP violation ===\n");
        uart_puts("Task: ");
        uart_puts(sched_tasks[sched_current].name);
        uart_puts("\n");
        uart_puts(describe_mcause(code));
        uart_puts("\n");
        uart_print_hex("mepc ", mepc);
        uart_print_hex("mtval", mtval);
        sched_tasks[sched_current].alive = 0;
    } else {
        uart_puts("[sched] tick -- TaskA=");
        uart_print_hex("counter", task_a_counter);
        uart_puts("[sched]         TaskB=");
        uart_print_hex("counter", task_b_counter);
    }

    int next = -1;
    for (int i = 1; i <= SCHED_NUM_TASKS; i++) {
        int idx = (sched_current + i) % SCHED_NUM_TASKS;
        if (sched_tasks[idx].alive) {
            next = idx;
            break;
        }
    }

    if (next < 0) {
        uart_puts("\n[sched] no tasks left alive -- halting.\n");
        sifive_poweroff();
    }

    sched_current = next;
    pmp_configure_for_task(sched_tasks[sched_current].code_start, sched_tasks[sched_current].code_end,
                            sched_tasks[sched_current].data_start, sched_tasks[sched_current].data_end);
    clint_rearm();
    next_ctx = &sched_tasks[sched_current].ctx;
}
