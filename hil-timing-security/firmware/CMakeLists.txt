cmake_minimum_required(VERSION 3.20)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/arm-none-eabi.cmake CACHE FILEPATH "")
project(sare_fw C ASM)

set(TP ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
set(RTOS ${TP}/FreeRTOS-Kernel)
set(DEV ${TP}/cmsis-device-f4)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(MCU_FLAGS -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard)

add_executable(sare_fw.elf
  src/main.c src/bsp_stm32f411.c src/timing.c src/trace.c src/link.c
  src/tasks.c src/workload.c src/syscalls.c src/monitor.c src/attack.c
  ${DEV}/Source/Templates/system_stm32f4xx.c
  ${DEV}/Source/Templates/gcc/startup_stm32f411xe.s
  ${RTOS}/tasks.c ${RTOS}/list.c ${RTOS}/queue.c
  ${RTOS}/portable/GCC/ARM_CM4F/port.c
  ${RTOS}/portable/MemMang/heap_4.c)

add_custom_target(build_id
  COMMAND ${CMAKE_COMMAND} -DSRC_DIR=${CMAKE_CURRENT_SOURCE_DIR}
          -DOUT=${CMAKE_CURRENT_BINARY_DIR}/gen/build_id.h -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_id.cmake
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/gen/build_id.h)
add_dependencies(sare_fw.elf build_id)

target_include_directories(sare_fw.elf PRIVATE
  include config ${CMAKE_CURRENT_BINARY_DIR}/gen
  ${RTOS}/include ${RTOS}/portable/GCC/ARM_CM4F
  ${DEV}/Include ${TP}/CMSIS_6/CMSIS/Core/Include)

set(LINK_UART 2 CACHE STRING "Host link: 1 = USART1 direct to Raspberry Pi GPIO, 2 = ST-LINK VCP")
target_compile_definitions(sare_fw.elf PRIVATE STM32F411xE LINK_UART=${LINK_UART}
  BUILD_FLAGS="-O2 -ffp-contract=off LINK_UART=${LINK_UART}")
# -O2 and no LTO: timing results depend on code generation, so the flags are
# part of the experimental setup and must be reported in the paper.
target_compile_options(sare_fw.elf PRIVATE ${MCU_FLAGS} -O2 -g3
  -ffunction-sections -fdata-sections -fno-common
  # No fused multiply-add: the monitor's float arithmetic must be bit-identical
  # to its host replay (analysis/monitor_replay.py).
  -ffp-contract=off
  $<$<COMPILE_LANGUAGE:C>:-std=gnu11 -Wall -Wextra -Wno-unused-parameter>)
target_link_options(sare_fw.elf PRIVATE ${MCU_FLAGS}
  -T${CMAKE_CURRENT_SOURCE_DIR}/ld/stm32f411re.ld
  -Wl,--gc-sections -Wl,-Map=sare_fw.map -Wl,--print-memory-usage -Wl,--no-warn-rwx-segments
  --specs=nano.specs --specs=nosys.specs)
target_link_libraries(sare_fw.elf PRIVATE m)

add_custom_command(TARGET sare_fw.elf POST_BUILD
  COMMAND ${CMAKE_OBJCOPY} -O binary sare_fw.elf sare_fw.bin
  COMMAND ${CMAKE_SIZE} sare_fw.elf)
