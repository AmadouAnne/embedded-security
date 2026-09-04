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
    .text : {
        *(.text.start)
        *(.text*)
    } > RAM

    .rodata : {
        *(.rodata*)
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
