# P7 — RISC-V PMP Task Isolation

**Status: Phases 1-3 complete and tested in QEMU. Phase 4 (real hardware) blocked — no RISC-V board on hand yet.**

A comparative counterpart to [`freertos-stm32`](../freertos-stm32): that project isolates an untrusted task from the rest of the system using ARM Cortex-M4's MPU (`xTaskCreateRestricted`, per-task memory regions, `MemManage_Handler`). This project asks the same question on RISC-V, whose privilege/isolation model is structurally different — no NVIC, no MPU in the ARM sense, and the mechanism is Physical Memory Protection (PMP): a set of M-mode-only CSRs (`pmpaddr0-15`, `pmpcfg0-3`) that bound what U-mode code may read/write/execute.

The research question isn't "does isolation work on RISC-V too" (it does, by construction) — it's **how the same threat model (an untrusted task, a deliberate out-of-bounds access, a caught fault instead of silent corruption) translates across two genuinely different privilege/region mechanisms**, and at what cost in complexity and region granularity.

## Why QEMU first

No RISC-V board was on hand at the start of this project. Rather than wait, Phases 1-2 are built and validated against QEMU's `virt` machine (memory map, UART and finisher-device addresses all confirmed against the machine's own device tree, not assumed — see comments in `linker.ld`/`uart.c`/`sifive_test.c`). Real hardware (e.g. an ESP32-C3, cheap and widely available) is planned as a later validation step, honestly labelled as pending until it happens — same approach as [`side-channel`](../side-channel)'s simulated-vs-real-traces distinction.

## Phase plan

- **Phase 1 — Bring-up (done).** Minimal bare-metal M-mode program: toolchain (`riscv64-elf-gcc`), linker script, boot code, polled NS16550A UART driver.
- **Phase 2 — PMP regions + trap handling (done).** Two PMP-enforced regions granted to a U-mode "untrusted task" (its own code: R+X; its own scratch data + stack: R+W). The task legally touches its scratch buffer, then deliberately writes to `g_secure_secret` — outside every U-mode grant. Real, captured output below.
- **Phase 3 — Minimal multi-task scheduler (done).** A small M-mode round-robin scheduler (timer-driven, hand-written context save/restore) that reconfigures PMP on every context switch — the real structural parallel to `xTaskCreateRestricted()`'s per-task regions. Two structurally identical sibling tasks; one deliberately corrupts the other's memory once it's had a few scheduled turns; the scheduler catches it, kills only the offender, and the sibling keeps running untouched. Real, captured output below.
- **Phase 4 — Real hardware validation.** Blocked: no RISC-V board on hand yet (checked for a connected board via `lsusb` — only found this machine's unrelated ST-Link for the ARM side of this comparison). Planned once one is available (e.g. an ESP32-C3).

## Phase 2 result (real captured output, not illustrative)

```
$ make run
=== RISC-V PMP Isolation -- Phase 2 ===
Configuring PMP: untrusted task gets R+X on its own code, R+W on its own scratch+stack.
g_secure_secret (before): 0x0000000000c0ffee
Dropping to U-mode, jumping into the untrusted task...

=== TRAP CAUGHT (M-mode) ===
Store/AMO access fault (PMP denied write)
mcause: 0x0000000000000007
mepc  : 0x0000000080000074
mtval : 0x0000000080000660
PMP blocked the untrusted task's out-of-region access before it landed.
```

Cross-checked against the linked ELF's own symbol table (`riscv64-elf-nm`):

```
0000000080000660 D g_secure_secret        <- mtval matches exactly
0000000080000560 D _scratch_start
0000000080000660 D _scratch_end           <- g_secure_secret sits immediately
                                              past the granted region's end
0000000080000044 T _untrusted_text_start
0000000080000084 T _untrusted_text_end    <- mepc (0x80000074) falls inside
```

`mtval` is the exact address of `g_secure_secret`, and `g_secure_secret` sits at the very next byte after the scratch region's PMP-granted end — the boundary is enforced precisely, not with some margin of slop. `mepc` falls inside the untrusted task's own granted code region, confirming the fault was raised from code actually running in U-mode, not from some other context.

## Phase 3 result (real captured output, not illustrative)

Two structurally identical sibling tasks (TaskA, TaskB), each with its own PMP-granted code+data region, preempted by a real timer interrupt (QEMU virt's CLINT) every 20ms and context-switched with a full hand-written register save/restore (`context_switch.S`). TaskA does legitimate work for a few scheduling quanta (both counters climbing, genuinely interleaved — not just alternating in lockstep, proof the round-robin preemption is real), then deliberately writes into TaskB's own counter: memory neither task shares, isolated from the other by nothing but the PMP regions the scheduler swaps in and out.

```
[sched] tick -- TaskA=counter: 0x0000000000000004
[sched]         TaskB=counter: 0x0000000000000005

=== TRAP: PMP violation ===
Task: TaskA
Store/AMO access fault (PMP denied write)
mepc : 0x0000000080000078
mtval: 0x0000000080000d00
[sched] tick -- TaskA=counter: 0x0000000000000005
[sched]         TaskB=counter: 0x0000000000000005
[sched] tick -- TaskA=counter: 0x0000000000000005
[sched]         TaskB=counter: 0x0000000000000006
```

Cross-checked against the linked ELF's own symbol table:

```
0000000080000d00 D task_b_counter          <- mtval matches exactly
0000000080000d00 D _taskb_data_start       <- and is the very first byte
0000000080000d00 D _taska_data_end            of TaskB's own region --
                                               i.e. one byte past where
                                               TaskA's own grant ends
```

TaskA is marked dead the instant this fault is caught and never runs again (its counter is frozen at 5 in every subsequent tick); TaskB, granted nothing by TaskA's PMP configuration and never touched by it, keeps incrementing on schedule, completely unaffected. The violation was contained to its source, not merely detected.

**A debugging note worth keeping**: getting here required finding two real bugs, neither of which was a logic error in the scheduling algorithm itself. First, PMP resets with every entry disabled, so U-mode's fail-closed default denies *everything* — including a task's own first instruction fetch — unless the very first task's region is configured before the first `mret`, not only reactively from inside the trap handler (which only runs starting from the *second* trap onward). Second, and more subtly: an early test build appeared to hang with both tasks' counters frozen after their first increment, which looked exactly like a context-switch correctness bug (wrong register restored, stale PC, ...) — hours were nearly spent chasing that theory via GDB. The actual cause was mundane: the tasks' busy-wait loop bound (200000 iterations) was reasonable for real silicon but not for QEMU's TCG software emulation, where a trivial `volatile` loop is far slower than on hardware; the loop was still running correctly, just taking several real seconds per pass, far longer than any test window used to observe it. Shrinking the bound made the "bug" disappear instantly. Documented here because it's a genuinely easy trap: a timing-sensitive symptom that looks identical to a correctness bug is not evidence the algorithm is wrong.

## Build & run

```bash
make        # produces build/riscv_pmp.elf
make run    # boots it under QEMU virt, UART on stdio
```

Phase 3 (the current default `main.c`) does not power off on its own: TaskB is designed to keep running forever after TaskA is killed, to prove the surviving sibling's progress is real and unbounded, not just "didn't crash immediately". Stop it with `Ctrl+A X`. Phase 2's single-task demo (which *does* power off automatically once its one task's violation is caught) is preserved unmodified in `untrusted_task.c` / `pmp_configure()` / `trap_handler()` for reference, alongside its exact captured output above, but is no longer wired into `main()`.

## Layout

- `Core/Src/start.S` — reset entry point: hart-0 gating, stack setup, `.bss` zeroing, default trap vector, jump to `main`.
- `Core/Src/uart.c` / `Core/Inc/uart.h` — polled NS16550A driver (QEMU virt's UART at `0x10000000`, byte-addressed) + a freestanding hex-print helper (no libc).
- `Core/Src/pmp.c` / `Core/Inc/pmp.h` — `pmp_configure()` (Phase 2, fixed single-task layout, kept for reference) and `pmp_configure_for_task()` (Phase 3, reprogrammed for an arbitrary task's bounds on every context switch) — both configure the same two-region TOR shape from linker-provided symbols, never hardcoded addresses.
- `Core/Src/trap.c` / `Core/Inc/trap.h` — `trap_init(handler)` installs any handler as `mtvec` (direct mode); `trap_handler` is Phase 2's plain-C fault reporter (GCC's `interrupt("machine")` attribute generates its save/restore prologue — fine since it never resumes a different context, only ever halts).
- `Core/Src/untrusted_task.c` / `Core/Inc/untrusted_task.h` — Phase 2's single U-mode task, kept for reference alongside its captured output above; no longer called from `main()`.
- `Core/Src/sifive_test.c` / `Core/Inc/sifive_test.h` — clean QEMU poweroff via the `virt` machine's `sifive_test` finisher device (`0x100000`).
- `Core/Inc/ctx_offsets.h` — plain `#define` byte offsets into `task_context_t`, shared between `scheduler.h` (checked against the real struct layout with `_Static_assert`) and `context_switch.S` (which can't parse a C struct).
- `Core/Inc/scheduler.h` / `Core/Src/scheduler.c` — the task table, `scheduler_init()`/`scheduler_start()`, and `scheduler_on_trap()` (called from `context_switch.S` after a context is saved): tells a genuine PMP fault from an ordinary timer tick, kills a faulting task, round-robins to the next alive one, reprograms its PMP region, rearms the timer.
- `Core/Src/context_switch.S` — the real, hand-written trap entry: saves every GPR of whichever task was interrupted into its own `task_context_t` (using `mscratch` to always point at the currently-running task's context, swapped atomically via `csrrw` at entry), calls into C on a dedicated M-mode stack, restores whichever context `scheduler_on_trap()` picked next. The classic "need a spare register to save/restore sp itself" problem is sidestepped with `ld sp, CTX_OFF_X2(sp)`/`sd`-via-a-freed-register tricks documented inline — no spare register needed in either direction.
- `Core/Inc/clint.h` / `Core/Src/clint.c` — QEMU virt's CLINT timer (confirmed base address and 10MHz `timebase-frequency` via the machine's own device tree, not assumed): enables the machine-timer interrupt and arms/rearms the next 20ms deadline.
- `Core/Src/task_a.c` / `Core/Src/task_b.c` — the two Phase 3 sibling tasks, each with its own counter + stack in its own `.data.taskN` and its own `.text.taskN`; TaskA deliberately corrupts TaskB's counter once it's run long enough, TaskB never misbehaves.
- `linker.ld` — places code/data in RAM at `0x80000000` (QEMU virt's RAM base); carves out `.text.untrusted`/`.data.scratch` (Phase 2) and `.text.taskA`/`.text.taskB`/`.data.taskA`/`.data.taskB` (Phase 3) as their own output sections (matched before the generic `.text*`/`.data*` wildcards) with linker-provided boundary symbols that `pmp.c` reads directly.
- `Makefile` — cross-compiles with `-march=rv64imac_zicsr_zifencei` (the `_zicsr` extension is required explicitly by current binutils for `csrr`/`csrw`, no longer implied by the base ISA).
