#ifndef UNTRUSTED_TASK_H
#define UNTRUSTED_TASK_H

#include <stdint.h>

/* Runs entirely in U-mode inside its own PMP-granted regions (see
 * pmp_configure()): touches its own scratch buffer (legal), then
 * deliberately writes to g_secure_secret, which is outside every region
 * granted to U-mode -- demonstrating the PMP trapping that access instead
 * of silently corrupting it. Never returns (the trap it triggers hands
 * control to trap_handler in M-mode, which powers off). */
void untrusted_task_entry(void) __attribute__((noreturn));

/* Small stack carved out of the untrusted task's own .data.scratch
 * region -- main() points sp at untrusted_stack + sizeof(untrusted_stack)
 * before `mret`ing into U-mode, so any stack access the task does
 * (spilled locals, etc.) stays inside its own granted region. */
#define UNTRUSTED_STACK_BYTES 192
extern uint8_t untrusted_stack[UNTRUSTED_STACK_BYTES];

/* Deliberately NOT part of any U-mode PMP grant -- the target of the
 * illegal write. main() prints this before/after to show it survives
 * because the write never lands (trap_handler powers off instead of
 * letting the store complete or resuming the task). */
extern volatile uint32_t g_secure_secret;

#endif /* UNTRUSTED_TASK_H */
