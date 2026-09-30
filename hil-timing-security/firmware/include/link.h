/*
 * Host link protocol (DUT <-> Raspberry Pi).
 *
 * Frame on the wire: COBS( type | payload | crc16-ccitt LE ) 0x00
 * The Python mirror of every struct lives in hil/protocol.py; keep both in
 * sync and bump PROTO_VERSION on any layout change.
 */
#ifndef LINK_H
#define LINK_H

#include <stddef.h>
#include <stdint.h>

#define LINK_MAX_FRAME 128u   /* decoded size limit for received frames */

enum msg_type {
    /* host -> DUT */
    MSG_SENSOR  = 0x01,
    MSG_CONFIG  = 0x10,
    MSG_START   = 0x11,
    /* DUT -> host */
    MSG_HELLO   = 0x80,
    MSG_TRACE   = 0x81,
    MSG_STATS   = 0x82,
    MSG_END     = 0x83,
    MSG_ACK     = 0x84,
    MSG_CALIB   = 0x85,
    MSG_INFO    = 0x86,   /* ASCII build description */
};

enum mitigation_bits {
    MIT_DEMOTE      = 1u << 0,  /* demote the untrusted partition */
    MIT_RX_THROTTLE = 1u << 1,  /* mask the link RX interrupt for a cool-down */
};

enum monitor_mode {
    MON_OFF = 0,
    MON_DETECT = 1,
    MON_MITIGATE = 2,
};

typedef struct __attribute__((packed)) {
    uint16_t scenario_id;
    uint16_t run_id;
    uint32_t duration_ms;
    /* E2: untrusted CPU-exhaustion task */
    uint8_t  attack_enable;
    uint8_t  attack_prio;
    uint16_t attack_period_ms;
    uint16_t attack_load_permille;
    /* E5: timing monitor */
    uint8_t  monitor_mode;
    uint8_t  monitor_frozen;      /* 1: stop adapting after warm-up */
    uint8_t  monitor_task_mask;   /* bit i = task i monitored */
    uint8_t  mitigation_mask;
    uint8_t  alarm_consec;        /* consecutive alarms before mitigation */
    uint8_t  data_guard;          /* E4 mitigation: sensor plausibility check */
    uint16_t warmup_jobs;
    uint16_t cooldown_ms;
    float    ewma_alpha;
    float    k_sigma;
    float    guard_ratio;         /* alarm if R > guard_ratio * D */
    float    sigma_floor;         /* sigma >= sigma_floor * mu (calibrated in C0) */
    /* workload knobs */
    uint32_t sec_chunk_bytes;
    uint16_t work_units[6];
} run_config_t;

typedef struct __attribute__((packed)) {
    uint32_t seq;
    float    accel[3];
    float    gyro[3];
    float    baro_alt;
} sensor_msg_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;               /* 'SARE' */
    uint16_t fw_version;
    uint16_t proto_version;
    uint32_t cpu_hz;
    uint8_t  n_tasks;
    uint8_t  record_size;
    uint16_t config_size;
} hello_msg_t;

/* Instrumentation cost measured on the target at start of run (cycles). */
typedef struct __attribute__((packed)) {
    uint32_t dwt_read_min, dwt_read_max;        /* back-to-back CYCCNT reads */
    uint32_t trace_push_min, trace_push_max;
    uint32_t acct_hooks_min, acct_hooks_max;    /* switch_out + switch_in pair */
    uint32_t samples;
} calib_msg_t;

typedef struct __attribute__((packed)) {
    uint32_t cyc;                 /* CYCCNT at the end of the window */
    uint32_t window_cyc;
    uint32_t idle_cyc;
    uint32_t rx_bytes;
    uint32_t rx_frames_ok;
    uint32_t rx_frames_bad;
    uint32_t rx_overflow;
    uint32_t rx_hw_errors;        /* USART overrun / framing / noise */
    uint32_t rx_ore, rx_fe, rx_ne;
    uint32_t rx_bad_cobs;
    uint32_t rx_bad_crc;
    uint32_t rx_overlong;
    uint32_t sensor_seq_lost;     /* sensor frames missing from the host sequence */
    uint32_t rx_last_bad_cyc;
    uint32_t rx_last_bad_len;
    uint32_t trace_drops;
    uint32_t alarms;
    uint32_t mitigations;
    uint32_t sec_passes;
    uint32_t sec_failures;
    uint32_t data_rejects;
    uint8_t  mitigation_active;
    uint8_t  pad[3];
} stats_msg_t;

typedef struct {
    uint8_t  buf[LINK_MAX_FRAME + 2];
    size_t   len;
    uint8_t  overlong;
    uint32_t frames_ok;
    uint32_t frames_bad;          /* = bad_cobs + bad_crc + overlong + runt */
    uint32_t bad_cobs, bad_crc, overlong_frames, runt;
    uint32_t last_bad_cyc;        /* CYCCNT when the last bad frame was seen */
    uint32_t last_bad_len;        /* its encoded length */
} link_rx_t;

typedef void (*link_handler_t)(uint8_t type, const uint8_t *payload, size_t len, void *ctx);

/* Feed received bytes; handler is called for every valid frame. */
void link_rx_feed(link_rx_t *rx, const uint8_t *data, size_t n, link_handler_t h, void *ctx);

/* Encode one frame into dst; returns bytes written or 0 if it does not fit. */
size_t link_encode(uint8_t *dst, size_t cap, uint8_t type, const void *payload, size_t len);

/* Convenience: encode and send immediately (not for the trace path). */
void link_send(uint8_t type, const void *payload, size_t len);

uint16_t crc16_ccitt(uint16_t crc, const uint8_t *p, size_t n);

/* Provided by the platform (timing.c on target, the test harness on host). */
uint32_t link_timestamp(void);

#endif
