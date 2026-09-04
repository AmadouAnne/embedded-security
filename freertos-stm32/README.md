# P1 — FreeRTOS Hardened on STM32

FreeRTOS-MPU (Cortex-M4, MPU_WRAPPERS_V1) hardening demo on a Nucleo-F411RE: memory-isolated tasks, a hardware watchdog fed by a multi-task health check, HMAC-SHA256 UART challenge-response, and a deliberately unprivileged "Untrusted" task meant to trigger a real, caught MPU fault instead of silently corrupting other tasks' state.

**Status: builds and runs stably on real hardware (Nucleo-F411RE, ST-Link V2.1). The core system (scheduler, UART reporting, ADC sensor, hardware watchdog) has been verified over multiple 15-20s continuous runs with zero faults. The "VIOLATE" MPU-trap demo does not yet complete correctly — see Known Issues.**

## What real hardware testing found

This project compiled cleanly and was believed working before it was ever flashed to a real board. Flashing it immediately exposed a chain of real, previously-undiscovered bugs — each one only visible once the previous one was fixed:

1. **Fault-handler UART deadlock** (`fault_handlers.c`): `HAL_UART_Transmit()`'s timeout is measured with `HAL_GetTick()`, which depends on the SysTick interrupt — but fault handlers run at a priority that blocks SysTick. The 200ms timeout could never expire, so the "diagnostic + reset" fault handler hung forever instead of resetting. Fixed with a raw register-polling UART write with no tick dependency.
2. **USART2 never actually initialized**: `MX_GPIO_Init()`/`MX_USART2_UART_Init()` never enabled the USART2 clock or muxed PA2/PA3 to AF7 — the peripheral was configured while still plain GPIO. Nothing was ever physically transmitted.
3. **LED/UART/Sensor tasks silently unprivileged**: created via `xTaskCreate(..., priority, ...)` without `portPRIVILEGE_BIT`, which FreeRTOS-MPU requires explicitly — every one of these ordinary system tasks was unprivileged by accident, causing an MPU fault storm on their very first context switch.
4. **Canary planted before the stack it guards was zero-filled**: `Security_RegisterTask()` wrote the stack-overflow canary *before* `xTaskCreateRestricted()`, whose own `prvInitialiseNewTask()` fills the whole stack buffer with FreeRTOS's `0xA5` debug pattern — wiping the canary out immediately and causing a permanent false-positive "stack overflow" reset loop.
5. **Watchdog-timing/task-priority mismatch**: `vTask_Sensor`'s 2000ms period was longer than the IWDG's ~1.6s timeout, so the "all tasks healthy" watchdog-kick condition could never be satisfied inside a single window — guaranteed periodic resets by construction, independent of any real hang.
6. **ADC1 clock never enabled** — same class of bug as #2, for the temperature sensor.
7. **`xQueueOverwrite()` used on a length-8 queue** instead of length-1 (FreeRTOS asserts this): `configASSERT()` permanently halted the system with interrupts disabled on every single run, which from the outside looked identical to another IWDG reset loop.
8. **`configUSE_TICK_HOOK` was 0**: FreeRTOS owns `SysTick_Handler` entirely, so nothing ever called the STM32 HAL's `HAL_IncTick()` — every `HAL_GetTick()`-based timeout (UART receive, ADC polling) blocked forever whenever the underlying hardware condition wasn't immediately true.
9. **Linker script's privileged-region padding didn't work**: `. = start + SIZE;` placed *after* a section's closing brace only moves the symbolic location counter — it doesn't reserve that space for the *next* section's placement. `.data` (and every initialized global in it, including HAL's own `uwTickFreq`) ended up physically inside the "privileged-only, zero-filled-on-boot" RAM carve-out, so `Reset_Handler`'s own zero-fill of that region silently wiped every initialized global back to 0 right after the `.data` copy loop had just set them correctly. Fixed by making the padding its own region-tagged (`NOLOAD`) section, which does correctly advance the region's real allocation cursor.
10. **Unprivileged-callable syscall gateway placed behind the privileged-only wall**: `.freertos_system_calls` (the `MPU_xxx` wrapper functions unprivileged tasks must be able to branch into to reach the `svc` instruction that raises their privilege — see `vSVCHandler_C` in `port.c`) was inside the same "privileged-only, execute-denied-to-everyone-else" flash carve-out as the real kernel implementation. Self-defeating by construction: unprivileged code can't fetch the wrapper's first instruction, so it can never reach the `svc` that would let it in. Confirmed via a real `IACCVIOL` fault the moment the (previously-starved, see Known Issues) "Untrusted" task got to run and called `vTaskDelay()`. Fixed by moving `.freertos_system_calls` to after the privileged-only carve-out, where it's covered by the general "unprivileged R+X across all of flash" region instead — verified via `objdump -h` that it now sits outside `[__privileged_functions_start__, __privileged_functions_end__)`.

Each of these was found by attaching GDB over the ST-Link's SWD interface, reading live memory/registers, and cross-referencing against the actual FreeRTOS-MPU port source and the linker script — not by inspection alone.

## Known Issues (not yet resolved)

- **The "VIOLATE" MPU-trap demo doesn't complete.** The unprivileged "Untrusted" task is permanently starved at priority 1 by UART/Sensor's busy-polling HAL calls (same root cause as bug #5's watchdog-starvation, just for a different task) — confirmed by sending `VIOLATE` over UART and finding the request flag never consumed. Raising it to priority 2 lets it actually run (and fixing bug #10 above resolves the IACCVIOL that used to follow immediately), but a **second, deeper bug** appears the moment it calls `vTaskDelay()`: `vApplicationStackOverflowHook()` fires for `"Untrusted"`, every time, with no exception. This was *not* a simple undersized stack — `UNTRUSTED_STACK_WORDS` was tried at 128, 256, and 512 words (512B/1KB/2KB) and all three failed identically, which a genuine "just needs a bit more" case would not do. More tellingly, reading the task's TCB at the moment of failure (`pxTopOfStack`, the struct's first field) showed a value nowhere near `untrusted_stack[]`'s actual address range — it pointed into the heap instead. That rules out ordinary stack exhaustion and points at something more fundamental in how this specific restricted task's context/stack pointer is tracked across the SVC privilege-raise → real `vTaskDelay()` → privilege-lower round trip. Root-causing this needs focused, uninterrupted low-level debugging (stepping the actual SVC/PendSV assembly path instruction-by-instruction) that a follow-up session should budget real time for. Priority is left at 1 (starved but stable) until then, rather than ship a crash loop — see the comments in `Core/Src/main.c` for the full trail.
- Not yet tested: real MemManage fault handling end-to-end (blocked on the above), the HMAC-SHA256 UART challenge-response protocol under real timing.

## Build & flash

```bash
make
openocd -f openocd/stm32f4.cfg -c "program build/freertos_hardened.bin 0x08000000 verify reset exit"
```

UART: `/dev/ttyACM0` (ST-Link VCP) at 115200 8N1.
