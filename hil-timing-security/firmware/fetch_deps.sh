#!/bin/sh
# Fetch pinned third-party sources (reproducible builds). Run from firmware/.
set -e
mkdir -p third_party && cd third_party
fetch() { # dir url commit
    [ -d "$1" ] || git clone -q "$2" "$1"
    git -C "$1" fetch -q --depth 1 origin "$3" 2>/dev/null || true
    git -C "$1" checkout -q "$3"
}
fetch FreeRTOS-Kernel https://github.com/FreeRTOS/FreeRTOS-Kernel.git dbf70559b27d39c1fdb68dfb9a32140b6a6777a0   # V11.1.0
fetch cmsis-device-f4 https://github.com/STMicroelectronics/cmsis-device-f4.git a833f4af71410f25b01468f976560d7ff63a2fc9
fetch CMSIS_6 https://github.com/ARM-software/CMSIS_6.git 26206e47dcf0abfbdc64eb753a0b6334b24439f6
