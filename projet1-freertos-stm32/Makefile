TARGET    = freertos_hardened
BUILD_DIR = build

CC      = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size

MCU_FLAGS = -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard

DEFINES = -DSTM32F411xE -DUSE_HAL_DRIVER

C_SOURCES =     Core/Src/main.c     Core/Src/tasks.c     Core/Src/security.c     Drivers/STM32F4xx/Src/stm32f4xx_hal.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_rcc.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_rcc_ex.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_gpio.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_uart.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_adc.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_adc_ex.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_cortex.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_dma.c     Drivers/STM32F4xx/Src/stm32f4xx_hal_pwr_ex.c     Drivers/CMSIS/Source/system_stm32f4xx.c     FreeRTOS/tasks.c     FreeRTOS/queue.c     FreeRTOS/list.c     FreeRTOS/timers.c     FreeRTOS/event_groups.c     FreeRTOS/stream_buffer.c     FreeRTOS/portable/GCC/ARM_CM4F/port.c     FreeRTOS/portable/MemMang/heap_4.c

ASM_SOURCES = Drivers/CMSIS/Source/startup_stm32f411xe.s

C_INCLUDES =     -ICore/Inc     -IDrivers/CMSIS/Include     -IDrivers/CMSIS/Device/ST/STM32F4xx/Include     -IDrivers/STM32F4xx/Inc     -IFreeRTOS/include     -IFreeRTOS/portable/GCC/ARM_CM4F

CFLAGS = $(MCU_FLAGS) $(DEFINES) $(C_INCLUDES) -Wall -fdata-sections -ffunction-sections -Os -g3

LDSCRIPT = STM32F411RETx_FLASH.ld
LDFLAGS  = $(MCU_FLAGS) -specs=nano.specs -T$(LDSCRIPT) -Wl,--gc-sections -lc -lm -lnosys

OBJECTS  = $(addprefix $(BUILD_DIR)/,$(C_SOURCES:.c=.o))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(ASM_SOURCES:.s=.o))

all: $(BUILD_DIR)/$(TARGET).elf

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.s
	@mkdir -p $(dir $@)
	$(CC) -c $(MCU_FLAGS) -x assembler-with-cpp $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(OBJCOPY) -O ihex $@ $(BUILD_DIR)/$(TARGET).hex
	$(OBJCOPY) -O binary -S $@ $(BUILD_DIR)/$(TARGET).bin
	$(SIZE) $@

flash: $(BUILD_DIR)/$(TARGET).elf
	openocd -f openocd/stm32f4.cfg -c "program $(BUILD_DIR)/$(TARGET).elf verify reset exit"

debug:
	openocd -f openocd/stm32f4.cfg

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all flash debug clean
