#include "workload.h"
#include "runtime.h"
#include "trace.h"
#include "timing.h"
#include "bsp.h"
#include "monitor.h"
#include <math.h>
#include <string.h>

volatile workload_stats_t g_wl_stats;

/* ---------------------------------------------------------------- sensor */

#define N_CH       7
#define HIST_LEN   512u  /* max FIR taps; work_units[TID_SENSOR] selects the length */

typedef struct {
    float accel[3], gyro[3], alt;
    uint32_t seq;
} nav_input_t;

static sensor_msg_t   raw_latest;
static uint8_t        raw_fresh;
static nav_input_t    last_good;
static nav_input_t    sensor_out;      /* written by Sensor, read by Control/Nav */
static float          hist[N_CH][HIST_LEN];
static float          fir[HIST_LEN];

static const float cal_a[3][3] = {
    { 1.0021f, -0.0013f, 0.0008f }, { 0.0011f, 0.9987f, -0.0021f }, { -0.0004f, 0.0017f, 1.0009f },
};
static const float cal_g[3][3] = {
    { 0.9993f, 0.0006f, -0.0012f }, { -0.0009f, 1.0014f, 0.0003f }, { 0.0015f, -0.0002f, 0.9991f },
};

static uint32_t sensor_seq_next, sensor_seq_lost;
static uint8_t  sensor_seq_valid;

static void on_frame(uint8_t type, const uint8_t *p, size_t len, void *ctx)
{
    (void)ctx;
    if (type == MSG_SENSOR && len == sizeof(sensor_msg_t)) {
        memcpy(&raw_latest, p, sizeof raw_latest);
        raw_fresh = 1;
        if (sensor_seq_valid && raw_latest.seq > sensor_seq_next)
            sensor_seq_lost += raw_latest.seq - sensor_seq_next;
        sensor_seq_next = raw_latest.seq + 1u;
        sensor_seq_valid = 1;
    }
    /* Any other frame during a run is ignored (counted as ok but unused). */
}

/* Physical plausibility envelope of the simulated airframe. */
static int plausible(const sensor_msg_t *m)
{
    for (int i = 0; i < 3; i++) {
        if (!isfinite(m->accel[i]) || fabsf(m->accel[i]) > 16.0f * 9.81f) return 0;
        if (!isfinite(m->gyro[i]) || fabsf(m->gyro[i]) > 35.0f) return 0;   /* rad/s */
    }
    return isfinite(m->baro_alt) && m->baro_alt > -500.0f && m->baro_alt < 20000.0f;
}

uint8_t job_sensor(uint32_t k)
{
    static uint8_t chunk[128];
    uint8_t flags = 0;
    size_t n;

    /* Acquisition: drain the link ring (bounded by its size). */
    while ((n = bsp_uart_read(chunk, sizeof chunk)) > 0)
        link_rx_feed(&g_link_rx, chunk, n, on_frame, NULL);

    if (raw_fresh) {
        raw_fresh = 0;
        if (g_cfg.data_guard && !plausible(&raw_latest)) {
            flags |= TF_DATA_REJECT;
            g_wl_stats.data_rejects++;
        } else {
            memcpy(last_good.accel, raw_latest.accel, sizeof last_good.accel);
            memcpy(last_good.gyro, raw_latest.gyro, sizeof last_good.gyro);
            last_good.alt = raw_latest.baro_alt;
            last_good.seq = raw_latest.seq;
        }
    }

    /* Calibration + FIR low-pass over the channel history. */
    float x[N_CH];
    for (int i = 0; i < 3; i++) {
        x[i]     = cal_a[i][0] * last_good.accel[0] + cal_a[i][1] * last_good.accel[1] + cal_a[i][2] * last_good.accel[2];
        x[3 + i] = cal_g[i][0] * last_good.gyro[0] + cal_g[i][1] * last_good.gyro[1] + cal_g[i][2] * last_good.gyro[2];
    }
    x[6] = last_good.alt;

    uint32_t taps = g_cfg.work_units[TID_SENSOR];
    if (taps > HIST_LEN) taps = HIST_LEN;
    uint32_t slot = k % HIST_LEN;
    nav_input_t out;
    float *dst[N_CH] = { &out.accel[0], &out.accel[1], &out.accel[2],
                         &out.gyro[0], &out.gyro[1], &out.gyro[2], &out.alt };
    for (int c = 0; c < N_CH; c++) {
        hist[c][slot] = x[c];
        float acc = 0.0f;
        for (uint32_t t = 0; t < taps; t++)
            acc += fir[t] * hist[c][(slot + HIST_LEN - t) % HIST_LEN];
        *dst[c] = acc;
    }
    out.seq = last_good.seq;

    taskENTER_CRITICAL();
    sensor_out = out;
    taskEXIT_CRITICAL();
    return flags;
}

static nav_input_t sensor_snapshot(void)
{
    nav_input_t s;
    taskENTER_CRITICAL();
    s = sensor_out;
    taskEXIT_CRITICAL();
    return s;
}

/* --------------------------------------------------------------- control */

#define ROBUST_WIN 32u

static float ctrl_integ[3], ctrl_prev[3];
static float ctrl_out[4];
static float innov_hist[3][ROBUST_WIN];
static float model[6][6];
static float model_state[6];

/*
 * Iteratively reweighted (Huber) location estimate; its iteration count grows
 * with how far the input lies outside the nominal envelope. This is the
 * data-dependent branch exercised by E4.
 */
static float robust_estimate(const float *w, uint32_t iters)
{
    float m = 0.0f;
    for (uint32_t i = 0; i < ROBUST_WIN; i++) m += w[i];
    m /= ROBUST_WIN;
    for (uint32_t it = 0; it < iters; it++) {
        float num = 0.0f, den = 0.0f;
        for (uint32_t i = 0; i < ROBUST_WIN; i++) {
            float r = fabsf(w[i] - m);
            float wt = r <= 1.0f ? 1.0f : 1.0f / r;
            num += wt * w[i];
            den += wt;
        }
        m = num / den;
    }
    return m;
}

uint8_t job_control(uint32_t k)
{
    static const float kp = 1.8f, ki = 0.35f, kd = 0.05f, dt = 0.010f, lim = 4.0f;
    nav_input_t s = sensor_snapshot();
    uint8_t flags = 0;

    for (int ax = 0; ax < 3; ax++) {
        float e = -s.gyro[ax];
        innov_hist[ax][k % ROBUST_WIN] = e;

        if (!isfinite(e) || fabsf(e) > lim) {
            uint32_t iters = 64;
            if (isfinite(e)) {
                iters = 4u + 4u * (uint32_t)log2f(fabsf(e) / lim + 1.0f);
                if (iters > 64u) iters = 64u;
            }
            e = robust_estimate(innov_hist[ax], iters);
            if (!isfinite(e)) e = 0.0f;
            flags |= TF_SLOW_PATH;
        }

        ctrl_integ[ax] += e * dt;
        if (ctrl_integ[ax] > 1.0f) ctrl_integ[ax] = 1.0f;       /* anti-windup */
        if (ctrl_integ[ax] < -1.0f) ctrl_integ[ax] = -1.0f;
        float u = kp * e + ki * ctrl_integ[ax] + kd * (e - ctrl_prev[ax]) / dt;
        ctrl_prev[ax] = e;
        ctrl_out[ax] = u;
    }
    ctrl_out[3] = s.alt * 0.001f;

    /* Reference-model propagation: work_units x (6x6 matrix-vector). */
    for (uint32_t r = 0; r < g_cfg.work_units[TID_CONTROL]; r++) {
        float nx[6];
        for (int i = 0; i < 6; i++) {
            float a = 0.0f;
            for (int j = 0; j < 6; j++) a += model[i][j] * model_state[j];
            nx[i] = a + 0.001f * ctrl_out[i % 4];
        }
        memcpy(model_state, nx, sizeof nx);
    }
    return flags;
}

/* ------------------------------------------------------------ navigation */

static float quat[4] = { 1.0f, 0.0f, 0.0f, 0.0f };
static float lat = 0.7854f, lon = 0.0262f;   /* rad */
static volatile float nav_dist;

uint8_t job_nav(uint32_t k)
{
    nav_input_t s = sensor_snapshot();
    uint32_t steps = g_cfg.work_units[TID_NAV];
    if (steps == 0) steps = 1;
    float h = 0.020f / (float)steps;

    for (uint32_t i = 0; i < steps; i++) {
        float wx = s.gyro[0], wy = s.gyro[1], wz = s.gyro[2];
        float q0 = quat[0], q1 = quat[1], q2 = quat[2], q3 = quat[3];
        quat[0] += 0.5f * h * (-q1 * wx - q2 * wy - q3 * wz);
        quat[1] += 0.5f * h * ( q0 * wx + q2 * wz - q3 * wy);
        quat[2] += 0.5f * h * ( q0 * wy - q1 * wz + q3 * wx);
        quat[3] += 0.5f * h * ( q0 * wz + q1 * wy - q2 * wx);
        float n = sqrtf(quat[0] * quat[0] + quat[1] * quat[1] + quat[2] * quat[2] + quat[3] * quat[3]);
        if (n > 1e-6f && isfinite(n))
            for (int j = 0; j < 4; j++) quat[j] /= n;
        else
            quat[0] = 1.0f, quat[1] = quat[2] = quat[3] = 0.0f;
    }

    /* Haversine distance to the active waypoint. */
    static const float wp_lat = 0.7900f, wp_lon = 0.0300f;
    lat += 1e-7f;
    lon += 1e-7f;
    float dlat = wp_lat - lat, dlon = wp_lon - lon;
    float a = sinf(dlat / 2) * sinf(dlat / 2) + cosf(lat) * cosf(wp_lat) * sinf(dlon / 2) * sinf(dlon / 2);
    nav_dist = 2.0f * 6371000.0f * atan2f(sqrtf(a), sqrtf(1.0f - a));
    (void)k;
    return 0;
}

/* ---------------------------------------------------------------- health */

extern uint32_t _sdata, _ebss;
static volatile uint32_t health_sig;
static volatile UBaseType_t stack_min[TID_COUNT];

uint8_t job_health(uint32_t k)
{
    for (int t = 0; t < TID_COUNT; t++)
        if (g_task[t])
            stack_min[t] = uxTaskGetStackHighWaterMark(g_task[t]);

    /* Scrub a sliding window of SRAM (work_units x 64 bytes). */
    uint32_t words = g_cfg.work_units[TID_HEALTH] * 16u;
    uint32_t span = (uint32_t)(&_ebss - &_sdata);
    uint32_t base = (k * words) % (span > words ? span - words : 1u);
    uint32_t sig = 0;
    for (uint32_t i = 0; i < words && i < span; i++)
        sig = (sig << 1 | sig >> 31) ^ (&_sdata)[base + i];
    health_sig = sig;
    (void)xPortGetFreeHeapSize();
    return 0;
}

/* -------------------------------------------------------------- security */

extern uint32_t _image_end;
#define IMAGE_START ((const uint8_t *)0x08000000u)

static uint32_t crc32_table[256];
static uint32_t sec_crc = 0xFFFFFFFFu, sec_golden;
static uint32_t sec_off;
static uint8_t  sec_have_golden;

uint8_t job_security(uint32_t k)
{
    const uint8_t *end = (const uint8_t *)&_image_end;
    uint32_t len = (uint32_t)(end - IMAGE_START);
    uint32_t n = g_cfg.sec_chunk_bytes;

    if (n > len - sec_off) n = len - sec_off;
    const uint8_t *p = IMAGE_START + sec_off;
    uint32_t c = sec_crc;
    for (uint32_t i = 0; i < n; i++)
        c = crc32_table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    sec_crc = c;
    sec_off += n;

    if (sec_off >= len) {
        uint32_t final = ~sec_crc;
        if (!sec_have_golden) {
            sec_golden = final;
            sec_have_golden = 1;
        } else if (final != sec_golden) {
            g_wl_stats.sec_failures++;
        }
        g_wl_stats.sec_passes++;
        sec_off = 0;
        sec_crc = 0xFFFFFFFFu;
    }
    (void)k;
    return 0;
}

/* --------------------------------------------------------------- logging */

#define TRACE_BATCH 32u

static uint8_t  tx_buf[4096];
static trace_rec_t batch[TRACE_BATCH];

static void send_stats(void)
{
    static uint32_t prev_cyc, prev_idle;
    stats_msg_t st = { 0 };
    uint32_t now = cyc_now();
    uint32_t idle = g_acct[TID_IDLE].acc;

    st.cyc = now;
    st.window_cyc = now - prev_cyc;
    st.idle_cyc = idle - prev_idle;
    prev_cyc = now;
    prev_idle = idle;
    st.rx_bytes = g_uart_stats.rx_bytes;
    st.rx_frames_ok = g_link_rx.frames_ok;
    st.rx_frames_bad = g_link_rx.frames_bad;
    st.rx_overflow = g_uart_stats.rx_overflow;
    st.rx_hw_errors = g_uart_stats.rx_hw_errors;
    st.rx_ore = g_uart_stats.rx_ore;
    st.rx_fe = g_uart_stats.rx_fe;
    st.rx_ne = g_uart_stats.rx_ne;
    st.rx_bad_cobs = g_link_rx.bad_cobs;
    st.rx_bad_crc = g_link_rx.bad_crc;
    st.rx_overlong = g_link_rx.overlong_frames;
    st.sensor_seq_lost = sensor_seq_lost;
    st.rx_last_bad_cyc = g_link_rx.last_bad_cyc;
    st.rx_last_bad_len = g_link_rx.last_bad_len;
    st.trace_drops = trace_drops();
    st.alarms = g_mon_stats.alarms;
    st.mitigations = g_mon_stats.mitigations;
    st.sec_passes = g_wl_stats.sec_passes;
    st.sec_failures = g_wl_stats.sec_failures;
    st.data_rejects = g_wl_stats.data_rejects;
    st.mitigation_active = mitigation_active();
    link_send(MSG_STATS, &st, sizeof st);
}

void logging_flush(void)
{
    size_t used = 0;
    uint32_t n;

    while ((n = trace_pop(batch, TRACE_BATCH)) > 0) {
        size_t w = link_encode(tx_buf + used, sizeof tx_buf - used, MSG_TRACE, batch, n * sizeof(trace_rec_t));
        if (w == 0) {
            bsp_uart_send(tx_buf, used);
            used = 0;
            w = link_encode(tx_buf, sizeof tx_buf, MSG_TRACE, batch, n * sizeof(trace_rec_t));
        }
        used += w;
    }
    bsp_uart_send(tx_buf, used);
}

uint8_t job_logging(uint32_t k)
{
    logging_flush();
    send_stats();
    (void)k;
    return 0;
}

/* ------------------------------------------------------------------ init */

void workload_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc32_table[i] = c;
    }
    /* Hann-windowed moving average, normalised for the configured length. */
    uint32_t taps = g_cfg.work_units[TID_SENSOR];
    if (taps == 0 || taps > HIST_LEN) taps = HIST_LEN;
    float sum = 0.0f;
    for (uint32_t t = 0; t < taps; t++) {
        fir[t] = 0.5f - 0.5f * cosf(2.0f * 3.14159265f * (float)(t + 1) / (float)(taps + 1));
        sum += fir[t];
    }
    for (uint32_t t = 0; t < taps; t++)
        fir[t] /= sum;
    for (int i = 0; i < 6; i++)
        for (int j = 0; j < 6; j++)
            model[i][j] = (i == j) ? 0.98f : 0.002f * (float)((i + j) % 3);
    last_good.accel[2] = -9.81f;
}
