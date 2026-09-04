# P7 — RISC-V PMP Task Isolation

**Status: Phases 1-2 complete and tested. Phase 3 in progress.**

A comparative counterpart to [`freertos-stm32`](../freertos-stm32): that project isolates an untrusted task from the rest of the system using ARM Cortex-M4's MPU (`xTaskCreateRestricted`, per-task memory regions, `MemManage_Handler`). This project asks the same question on RISC-V, whose privilege/isolation model is structurally different — no NVIC, no MPU in the ARM sense, and the mechanism is Physical Memory Protection (PMP): a set of M-mode-only CSRs (`pmpaddr0-15`, `pmpcfg0-3`) that bound what U-mode code may read/write/execute.

The research question isn't "does isolation work on RISC-V too" (it does, by construction) — it's **how the same threat model (an untrusted task, a deliberate out-of-bounds access, a caught fault instead of silent corruption) translates across two genuinely different privilege/region mechanisms**, and at what cost in complexity and region granularity.

## Why QEMU first

No RISC-V board was on hand at the start of this project. Rather than wait, Phases 1-2 are built and validated against QEMU's `virt` machine (memory map, UART and finisher-device addresses all confirmed against the machine's own device tree, not assumed — see comments in `linker.ld`/`uart.c`/`sifive_test.c`). Real hardware (e.g. an ESP32-C3, cheap and widely available) is planned as a later validation step, honestly labelled as pending until it happens — same approach as [`side-channel`](../side-channel)'s simulated-vs-real-traces distinction.

## Phase plan

- **Phase 1 — Bring-up (done).** Minimal bare-metal M-mode program: toolchain (`riscv64-elf-gcc`), linker script, boot code, polled NS16550A UART driver.
- **Phase 2 — PMP regions + trap handling (done).** Two PMP-enforced regions granted to a U-mode "untrusted task" (its own code: R+X; its own scratch data + stack: R+W). The task legally touches its scratch buffer, then deliberately writes to `g_secure_secret` — outside every U-mode grant. Real, captured output below.
- **Phase 3 — Minimal multi-task scheduler (in progress).** A small M-mode round-robin scheduler that reconfigures PMP on every context switch — the real structural parallel to `xTaskCreateRestricted()`'s per-task regions.
- **Phase 4 — Real hardware validation.** Once a RISC-V board is available.

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

## Build & run

```bash
make        # produces build/riscv_pmp.elf
make run    # boots it under QEMU virt, UART on stdio; powers off on its own after the trap
```

## Layout

- `Core/Src/start.S` — reset entry point: hart-0 gating, stack setup, `.bss` zeroing, default trap vector, jump to `main`.
- `Core/Src/uart.c` / `Core/Inc/uart.h` — polled NS16550A driver (QEMU virt's UART at `0x10000000`, byte-addressed) + a freestanding hex-print helper (no libc).
- `Core/Src/pmp.c` / `Core/Inc/pmp.h` — configures two PMP TOR regions from linker-provided symbols (never hardcoded addresses).
- `Core/Src/trap.c` / `Core/Inc/trap.h` — `mtvec`-installed M-mode trap handler (GCC's `interrupt("machine")` attribute generates the save/restore prologue) that decodes `mcause`/`mepc`/`mtval` and reports them over UART.
- `Core/Src/untrusted_task.c` / `Core/Inc/untrusted_task.h` — the U-mode task: its own scratch buffer + stack (`.data.scratch`), its own code (`.text.untrusted`), and `g_secure_secret` (deliberately outside both).
- `Core/Src/sifive_test.c` / `Core/Inc/sifive_test.h` — clean QEMU poweroff via the `virt` machine's `sifive_test` finisher device (`0x100000`), so the demo terminates on its own instead of needing `Ctrl+A X`.
- `linker.ld` — places code/data in RAM at `0x80000000` (QEMU virt's RAM base); carves out `.text.untrusted` and `.data.scratch` as their own output sections (matched before the generic `.text*`/`.data*` wildcards) with linker-provided boundary symbols that `pmp.c` reads directly.
- `Makefile` — cross-compiles with `-march=rv64imac_zicsr_zifencei` (the `_zicsr` extension is required explicitly by current binutils for `csrr`/`csrw`, no longer implied by the base ISA).
