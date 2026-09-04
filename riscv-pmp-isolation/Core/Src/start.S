/* Reset entry point for the QEMU RISC-V "virt" machine.
 *
 * With `-bios none`, QEMU jumps straight here in M-mode with a0=hartid,
 * a1=dtb pointer -- no OpenSBI/S-mode layer involved, which is what we
 * want: PMP configuration (Phase 2+) is an M-mode-only privilege, so
 * staying in M-mode for this whole experiment keeps the privilege model
 * simple and explicit.
 */
.section .text.start
.global _start

_start:
    /* Only hart 0 proceeds; park any other hart QEMU might start. */
    csrr    t0, mhartid
    bnez    t0, hang

    la      sp, _stack_top

    /* Zero .bss (word at a time; linker script aligns both ends to 8). */
    la      t0, _bss_start
    la      t1, _bss_end
clear_bss:
    bge     t0, t1, done_bss
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       clear_bss
done_bss:

    /* Any trap before main installs a real handler lands here instead of
     * running off into undefined behaviour. */
    la      t0, default_trap_handler
    csrw    mtvec, t0

    call    main

hang:
    wfi
    j       hang

default_trap_handler:
    j       default_trap_handler
