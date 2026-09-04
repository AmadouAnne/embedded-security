# P7 — RISC-V PMP Task Isolation

**Status: Phase 1 (bring-up) complete. Phases 2-3 in progress.**

A comparative counterpart to [`freertos-stm32`](../freertos-stm32): that project isolates an untrusted task from the rest of the system using ARM Cortex-M4's MPU (`xTaskCreateRestricted`, per-task memory regions, `MemManage_Handler`). This project asks the same question on RISC-V, whose privilege/isolation model is structurally different — no NVIC, no MPU in the ARM sense, and the mechanism is Physical Memory Protection (PMP): a set of M-mode-only CSRs (`pmpaddr0-15`, `pmpcfg0-3`) that bound what U-mode code may read/write/execute.

The research question isn't "does isolation work on RISC-V too" (it does, by construction) — it's **how the same threat model (an untrusted task, a deliberate out-of-bounds access, a caught fault instead of silent corruption) translates across two genuinely different privilege/region mechanisms**, and at what cost in complexity and region granularity.

## Why QEMU first

No RISC-V board was on hand at the start of this project. Rather than wait, Phase 1-2 are built and validated against QEMU's `virt` machine (memory map and UART address confirmed against the machine's own device tree, not assumed — see comments in `linker.ld`/`uart.c`). Real hardware (e.g. an ESP32-C3, cheap and widely available) is planned as a later validation step, honestly labelled as pending until it happens — same approach as [`side-channel`](../side-channel)'s simulated-vs-real-traces distinction.

## Phase plan

- **Phase 1 — Bring-up (done).** Minimal bare-metal M-mode program: toolchain (`riscv64-elf-gcc`), linker script, boot code, polled NS16550A UART driver. Proves the whole chain (cross-compile → linked M-mode ELF → QEMU) produces a running, observable program before anything security-relevant is built on it.
- **Phase 2 — Single PMP region + trap handling.** Configure one PMP region, drop to U-mode, demonstrate an in-bounds access succeeding and an out-of-bounds access trapping back to M-mode with a diagnostic (RISC-V equivalent of `fault_handlers.c`'s `MemManage_Handler`).
- **Phase 3 — Minimal multi-task scheduler.** A small M-mode round-robin scheduler that reconfigures PMP on every context switch — the real structural parallel to `xTaskCreateRestricted()`'s per-task regions.
- **Phase 4 — Real hardware validation.** Once a RISC-V board is available.

## Build & run

```bash
make        # produces build/riscv_pmp_phase1.elf
make run    # boots it under QEMU virt, UART on stdio (Ctrl+A X to exit)
```

Expected output:
```
=== RISC-V PMP Isolation -- Phase 1 ===
Boot bring-up OK: M-mode, QEMU virt machine, polled UART.
No PMP configured yet -- see README.md for the phase plan.
```

## Layout

- `Core/Src/start.S` — reset entry point: hart-0 gating, stack setup, `.bss` zeroing, default trap vector, jump to `main`.
- `Core/Src/uart.c` / `Core/Inc/uart.h` — polled NS16550A driver (QEMU virt's UART at `0x10000000`, byte-addressed).
- `Core/Src/main.c` — Phase 1 entry point.
- `linker.ld` — places code/data in RAM at `0x80000000` (QEMU virt's RAM base), 16KB stack.
- `Makefile` — cross-compiles with `-march=rv64imac_zicsr_zifencei` (the `_zicsr` extension is required explicitly by current binutils for `csrr`/`csrw`, no longer implied by the base ISA).
