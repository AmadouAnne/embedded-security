/*
 * Avionics-inspired synthetic workload. Each job returns trace flags
 * (TF_SLOW_PATH, TF_DATA_REJECT) describing data-dependent behaviour.
 */
#ifndef WORKLOAD_H
#define WORKLOAD_H

#include <stdint.h>

void workload_init(void);

uint8_t job_sensor(uint32_t k);
uint8_t job_control(uint32_t k);
uint8_t job_nav(uint32_t k);
uint8_t job_health(uint32_t k);
uint8_t job_security(uint32_t k);
uint8_t job_logging(uint32_t k);

typedef struct {
    uint32_t sec_passes;
    uint32_t sec_failures;
    uint32_t data_rejects;
} workload_stats_t;

extern volatile workload_stats_t g_wl_stats;

#endif
