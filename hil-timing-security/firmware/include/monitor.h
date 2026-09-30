/*
 * E5 timing monitor: EWMA mean/variance of each monitored task's response
 * time, alarm when R > mu + k*sigma or R > guard_ratio * D, optional
 * mitigation after alarm_consec consecutive alarms.
 */
#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>

typedef struct {
    uint32_t alarms;
    uint32_t mitigations;
} mon_stats_t;

extern volatile mon_stats_t g_mon_stats;

void monitor_init(void);
/* Returns TF_ALARM / TF_MITIGATING flags for the trace record. */
uint8_t monitor_update(uint8_t tid, uint32_t response, uint32_t deadline);
uint8_t mitigation_active(void);
void mitigation_tick(uint32_t tick);   /* from the tick hook */

#endif
