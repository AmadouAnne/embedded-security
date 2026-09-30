cmake_minimum_required(VERSION 3.20)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/arm-none-eabi.cmake CACHE FILEPATH "")
project(uart_bridge C ASM)
set(TP ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party)
set(DEV ${TP}/cmsis-device-f4)
set(MCU -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard)
add_executable(uart_bridge.elf main.c ../../src/syscalls.c
  ${DEV}/Source/Templates/system_stm32f4xx.c
  ${DEV}/Source/Templates/gcc/startup_stm32f411xe.s)
target_include_directories(uart_bridge.elf PRIVATE ${DEV}/Include ${TP}/CMSIS_6/CMSIS/Core/Include)
target_compile_definitions(uart_bridge.elf PRIVATE STM32F411xE)
target_compile_options(uart_bridge.elf PRIVATE ${MCU} -O2 -Wall -Wextra)
target_link_options(uart_bridge.elf PRIVATE ${MCU} -T${CMAKE_CURRENT_SOURCE_DIR}/../../ld/stm32f411re.ld
  --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections -Wl,--no-warn-rwx-segments)
add_custom_command(TARGET uart_bridge.elf POST_BUILD
  COMMAND arm-none-eabi-objcopy -O binary uart_bridge.elf uart_bridge.bin
  COMMAND arm-none-eabi-size uart_bridge.elf)
