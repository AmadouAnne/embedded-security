/* Linker script STM32F411RETx -- Flash 512KB, RAM 128KB
 *
 * Extended for FreeRTOS-MPU (ARM_CM4_MPU port): carves out a privileged-only
 * flash region (isr_vector + kernel code marked PRIVILEGED_FUNCTION +
 * freertos_system_calls gateway) and a privileged-only RAM region (kernel
 * globals + the heap_4 arena, marked PRIVILEGED_DATA) so that unprivileged
 * tasks -- created via xTaskCreateRestricted() without the privilege bit,
 * see vTask_Untrusted() in tasks.c -- cannot read or corrupt kernel state,
 * only their own granted regions. Both carve-outs are sized to a power of
 * two and start aligned to their own size, as required by the Cortex-M4
 * MPU's base-address/size encoding (see prvSetupMPU() in port.c).
 */
ENTRY(Reset_Handler)
_estack = ORIGIN(RAM) + LENGTH(RAM);
_Min_Heap_Size  = 0x400;
_Min_Stack_Size = 0x800;

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   (xrw) : ORIGIN = 0x20000000, LENGTH = 128K
}

/* Whole-chip bounds, used by prvSetupMPU() to grant unprivileged code
 * read+execute access to all of flash and to set up the default "cover
 * everything" SRAM region before per-task regions are layered on top. */
__FLASH_segment_start__ = ORIGIN(FLASH);
__FLASH_segment_end__   = ORIGIN(FLASH) + LENGTH(FLASH);
__SRAM_segment_start__  = ORIGIN(RAM);
__SRAM_segment_end__    = ORIGIN(RAM) + LENGTH(RAM);

/* Size of the privileged-only flash and RAM carve-outs. Generous relative to
 * this project's actual FreeRTOS-MPU kernel footprint (build/*.map shows the
 * real usage) -- if the kernel ever grows past this, the linker will fail
 * with "dot moved backwards" on the ". = __privileged_..._start__ + N"
 * assignment below instead of silently corrupting the layout. */
PRIVILEGED_FLASH_SIZE = 64K;
PRIVILEGED_RAM_SIZE   = 32K;

SECTIONS
{
  __privileged_functions_start__ = ORIGIN(FLASH);

  .isr_vector : { . = ALIGN(4); KEEP(*(.isr_vector)) . = ALIGN(4); } >FLASH

  /* FreeRTOS-MPU kernel internals (tasks.c/queue.c/list.c/timers.c/
   * event_groups.c/stream_buffer.c/port.c/mpu_wrappers.c) mark their code
   * PRIVILEGED_FUNCTION, which places it in this named section. */
  .privileged_functions :
  {
    . = ALIGN(4);
    *(privileged_functions)
    . = ALIGN(4);
  } >FLASH

  /* Pad out to the full carve-out size as its OWN region-tagged section,
   * not a bare ". = X" assignment after a closing brace -- that form only
   * moves the symbolic location counter, it does NOT advance the FLASH
   * region's real allocation cursor used to place the *next* >FLASH
   * section, so .text below started partway through this "privileged-only"
   * range instead of after it (confirmed on real hardware: __privileged_
   * functions_end__ computed correctly as a symbol, but .text's actual
   * start address did not move to match it -- verified via
   * `arm-none-eabi-objdump -h`, .privileged_data's real recorded size was
   * only its content's size, not PRIVILEGED_RAM_SIZE). SIZEOF()/ADDR() on
   * the already-closed preceding section is well-defined and relative, so
   * this avoids the absolute-address arithmetic that overflowed when tried
   * directly inside a section body. */
  .privileged_functions_pad (NOLOAD) :
  {
    . = . + ( PRIVILEGED_FLASH_SIZE - SIZEOF(.privileged_functions) );
  } >FLASH

  __privileged_functions_end__ = __privileged_functions_start__ + PRIVILEGED_FLASH_SIZE;

  /* The handful of API entry points unprivileged tasks are allowed to SVC
   * into (MPU_xxx wrappers in mpu_wrappers.c) -- vSVCHandler_C in port.c
   * checks the caller's PC against __syscalls_flash_start__/end__ before
   * honouring portSVC_RAISE_PRIVILEGE. Deliberately placed AFTER (not
   * inside) the privileged-only carve-out: this is the entry point
   * UNPRIVILEGED code branches into to reach the "svc" instruction that
   * raises its privilege -- confirmed on real hardware that putting it
   * inside the privileged-execute-only range is self-defeating: an
   * unprivileged caller faults (IACCVIOL) trying to fetch the wrapper's
   * first instruction and can never reach the svc that would have let it
   * in. Covered instead by the general unprivileged R+X region that spans
   * all of flash (see prvSetupMPU() in port.c). */
  .freertos_system_calls :
  {
    . = ALIGN(4);
    __syscalls_flash_start__ = .;
    *(freertos_system_calls)
    __syscalls_flash_end__ = .;
    . = ALIGN(4);
  } >FLASH

  .text :
  {
    . = ALIGN(4); *(.text) *(.text*) *(.glue_7) *(.glue_7t) *(.eh_frame)
    KEEP(*(.init)) KEEP(*(.fini)) . = ALIGN(4); _etext = .;
  } >FLASH
  .rodata : { . = ALIGN(4); *(.rodata) *(.rodata*) . = ALIGN(4); } >FLASH
  .ARM.extab : { *(.ARM.extab* .gnu.linkonce.armextab.*) } >FLASH
  .ARM : { __exidx_start = .; *(.ARM.exidx*) __exidx_end = .; } >FLASH
  .preinit_array : { PROVIDE_HIDDEN(__preinit_array_start = .); KEEP(*(.preinit_array*)) PROVIDE_HIDDEN(__preinit_array_end = .); } >FLASH
  .init_array    : { PROVIDE_HIDDEN(__init_array_start = .); KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*)) PROVIDE_HIDDEN(__init_array_end = .); } >FLASH
  .fini_array    : { PROVIDE_HIDDEN(__fini_array_start = .); KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*)) PROVIDE_HIDDEN(__fini_array_end = .); } >FLASH

  __privileged_data_start__ = ORIGIN(RAM);

  /* Kernel globals (pxCurrentTCB, tick count, ready lists, ...) and the
   * heap_4 arena (ucHeap[]) are all marked PRIVILEGED_DATA and are all
   * zero-initialised -- Reset_Handler's second zero-fill loop clears this
   * whole span, so it is declared NOLOAD here (no flash-resident init data
   * needed). */
  .privileged_data (NOLOAD) :
  {
    . = ALIGN(4);
    *(privileged_data)
    . = ALIGN(4);
  } >RAM

  /* Same fix as .privileged_functions_pad above -- see that comment. */
  .privileged_data_pad (NOLOAD) :
  {
    . = . + ( PRIVILEGED_RAM_SIZE - SIZEOF(.privileged_data) );
  } >RAM

  __privileged_data_end__ = __privileged_data_start__ + PRIVILEGED_RAM_SIZE;

  _sidata = LOADADDR(.data);
  .data : { . = ALIGN(4); _sdata = .; *(.data) *(.data*) *(.RamFunc) *(.RamFunc*) . = ALIGN(4); _edata = .; } >RAM AT> FLASH
  .bss  : { . = ALIGN(4); _sbss = .; __bss_start__ = _sbss; *(.bss) *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; __bss_end__ = _ebss; } >RAM
  ._user_heap_stack : { . = ALIGN(8); PROVIDE(end = .); PROVIDE(_end = .); . = . + _Min_Heap_Size; . = . + _Min_Stack_Size; . = ALIGN(8); } >RAM
  /DISCARD/ : { libc.a(*) libm.a(*) libgcc.a(*) }
  .ARM.attributes 0 : { *(.ARM.attributes) }
}
