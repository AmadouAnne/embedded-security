/* Shared run-time state of one experiment run. */
#ifndef RUNTIME_H
#define RUNTIME_H

#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "link.h"
#include "app_config.h"

extern run_config_t g_cfg;
extern TaskHandle_t g_task[TID_COUNT];
extern volatile uint32_t g_end_tick;

/* Latest decoded sensor frame and its receive statistics. */
extern link_rx_t g_link_rx;

#endif
