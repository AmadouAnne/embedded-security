TARGET    = riscv_pmp_phase1
BUILD_DIR = build

CROSS   = riscv64-elf-
CC      = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
SIZE    = $(CROSS)size

ARCH_FLAGS = -march=rv64imac_zicsr_zifencei -mabi=lp64 -mcmodel=medany

C_SOURCES   = Core/Src/main.c Core/Src/uart.c
ASM_SOURCES = Core/Src/start.S

C_INCLUDES = -ICore/Inc

CFLAGS = $(ARCH_FLAGS) $(C_INCLUDES) -Wall -O2 -ffreestanding -fno-builtin -nostdlib -g

LDSCRIPT = linker.ld
LDFLAGS  = $(ARCH_FLAGS) -nostdlib -T$(LDSCRIPT) -Wl,--gc-sections

OBJECTS  = $(addprefix $(BUILD_DIR)/,$(C_SOURCES:.c=.o))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(ASM_SOURCES:.S=.o))

QEMU       = qemu-system-riscv64
QEMU_FLAGS = -M virt -bios none -nographic -m 128M

all: $(BUILD_DIR)/$(TARGET).elf

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -x assembler-with-cpp $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SIZE) $@

run: $(BUILD_DIR)/$(TARGET).elf
	$(QEMU) $(QEMU_FLAGS) -kernel $(BUILD_DIR)/$(TARGET).elf

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run clean
