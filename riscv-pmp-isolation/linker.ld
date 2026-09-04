/* QEMU RISC-V "virt" machine memory map: RAM starts at 0x80000000.
 * (Confirmed against QEMU's own device tree: qemu-system-riscv64 -M virt
 * -bios none -machine dumpdtb=virt.dtb, then `dtc -I dtb -O dts virt.dtb`.)
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
    .text.start : {
        *(.text.start)
    } > RAM

    /* The untrusted task's code, isolated into its own output section
     * (matched here, before the generic .text* wildcard below, so it
     * doesn't get swept into it) with word-aligned start/end symbols that
     * pmp_configure() uses directly -- whatever the linker actually places
     * here is exactly what gets the PMP's R+X grant, nothing assumed. */
    .text.untrusted : {
        . = ALIGN(4);
        _untrusted_text_start = .;
        *(.text.untrusted)
        . = ALIGN(4);
        _untrusted_text_end = .;
    } > RAM

    .text : {
        *(.text*)
    } > RAM

    .rodata : {
        *(.rodata*)
    } > RAM

    /* Same idea as .text.untrusted: the task's scratch data + its own
     * U-mode stack, carved out before the generic .data* wildcard so
     * pmp_configure()'s R+W grant covers exactly this range. */
    .data.scratch : {
        . = ALIGN(4);
        _scratch_start = .;
        *(.data.scratch)
        . = ALIGN(4);
        _scratch_end = .;
    } > RAM

    .data : {
        _data_start = .;
        *(.data*)
        _data_end = .;
    } > RAM

    .bss : {
        . = ALIGN(8);
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    } > RAM

    . = ALIGN(16);
    . = . + 0x4000; /* 16KB stack */
    _stack_top = .;
}
