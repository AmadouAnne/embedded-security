/*
 * Static parameters of the avionics-inspired workload.
 * Everything that may vary between experiments lives in run_config_t
 * (link.h) and is sent by the HIL orchestrator before each run.
 */
#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <stdint.h>

#define FW_VERSION          0x0100u
#define PROTO_VERSION       6u

#define CPU_HZ              100000000u
#define TICK_HZ             1000u
#define CYC_PER_TICK        (CPU_HZ / TICK_HZ)
#define MS_TO_CYC(ms)       ((uint32_t)(ms) * (CPU_HZ / 1000u))

#define LINK_BAUD           921600u

/* Task identifiers: also the index used in trace records. */
enum task_id {
    TID_SENSOR = 0,
    TID_CONTROL,
    TID_NAV,
    TID_HEALTH,
    TID_SECURITY,
    TID_LOGGING,
    TID_ATTACK,     /* untrusted / compromised partition (E2) */
    TID_IDLE,
    TID_COUNT
};

#define N_WORKLOAD_TASKS    6u

/*
 * FreeRTOS priorities (higher number = higher priority), rate-monotonic.
 * Gaps leave room for the E2 attack task between any two workload tasks:
 * 15 above Sensor, 13 between Sensor and Control, 9 between Nav and Health,
 * 3 below Logging.
 */
#define PRIO_BOOT           17u
#define PRIO_SENSOR         14u
#define PRIO_CONTROL        12u
#define PRIO_NAV            10u
#define PRIO_HEALTH         8u
#define PRIO_SECURITY       6u
#define PRIO_LOGGING        4u
#define PRIO_DEMOTED        1u  /* priority given to untrusted tasks by mitigation */

#endif
