#include "tasks.h"
#include "runtime.h"
#include "timing.h"
#include "trace.h"
#include "workload.h"
#include "monitor.h"
#include "bsp.h"
#include "build_id.h"
#include <stdio.h>
#include <string.h>

run_config_t g_cfg;
TaskHandle_t g_task[TID_COUNT];
volatile uint32_t g_end_tick;
link_rx_t g_link_rx;

void attack_payload(uint32_t k);
void logging_flush(void);

typedef uint8_t (*job_fn_t)(uint32_t k);

typedef struct {
    const char *name;
    uint8_t     tid;
    uint8_t     prio;
    uint16_t    period_ms;   /* implicit deadline: D = T */
    uint16_t    stack_words;
    job_fn_t    job;
} task_desc_t;

static const task_desc_t workload[N_WORKLOAD_TASKS] = {
    { "Sensor",   TID_SENSOR,   PRIO_SENSOR,   5,   384, job_sensor },
    { "Control",  TID_CONTROL,  PRIO_CONTROL,  10,  384, job_control },
    { "Nav",      TID_NAV,      PRIO_NAV,      20,  384, job_nav },
    { "Health",   TID_HEALTH,   PRIO_HEALTH,   50,  384, job_health },
    { "Security", TID_SECURITY, PRIO_SECURITY, 100, 384, job_security },
    { "Logging",  TID_LOGGING,  PRIO_LOGGING,  500, 512, job_logging },
};

static task_desc_t attack_desc = { "Attack", TID_ATTACK, 0, 0, 256, NULL };

static uint8_t attack_job(uint32_t k)
{
    attack_payload(k);
    return 0;
}

static volatile uint32_t tasks_done;

/*
 * Generic periodic job wrapper. Release k happens at tick epoch + k*T, which
 * in cycles is epoch_cyc + k*T_cyc (exact because SysTick runs on the core
 * clock). A late job is not skipped: xTaskDelayUntil returns immediately and
 * the backlog shows up as growing response times.
 */
static void periodic_task(void *arg)
{
    const task_desc_t *d = arg;
    const TickType_t period = pdMS_TO_TICKS(d->period_ms);
    const uint32_t period_cyc = MS_TO_CYC(d->period_ms);
    const exec_acct_t *acct = &g_acct[d->tid];
    /* Block until the common epoch. The reference must be the current tick:
       a previous-wake time in the future is taken by xTaskDelayUntil as a
       tick-count overflow and the call would not block. */
    TickType_t wake = xTaskGetTickCount();
    configASSERT((int32_t)(g_epoch_tick - wake) > 0);
    xTaskDelayUntil(&wake, g_epoch_tick - wake);

    for (uint32_t k = 0; (int32_t)(wake - g_end_tick) < 0; k++) {
        uint32_t release = g_epoch_cyc + k * period_cyc;
        /* start/end and the execution counter come from the same CYCCNT
           sample, so an ISR at the boundary cannot be counted in exec
           without also being inside [start, end]. */
        uint32_t start, end;
        uint32_t e0 = acct_exec_sample(acct, &start);

        uint8_t flags = d->job(k);

        uint32_t exec = acct_exec_sample(acct, &end) - e0;
        uint32_t response = end - release;

        if (response > period_cyc)
            flags |= TF_DEADLINE_MISS;

        uint32_t m0 = cyc_now();
        flags |= monitor_update(d->tid, response, period_cyc);
        uint32_t mon_cost = cyc_now() - m0;

        trace_rec_t r = {
            .task = d->tid, .flags = flags,
            .mon_cost = mon_cost > 0xFFFFu ? 0xFFFFu : (uint16_t)mon_cost,
            .seq = k, .release = release, .start_lat = start - release,
            .response = response, .exec = exec,
        };
        trace_push(&r);

        xTaskDelayUntil(&wake, period);
    }

    taskENTER_CRITICAL();
    tasks_done++;
    taskEXIT_CRITICAL();

    if (d->tid == TID_LOGGING) {
        /* Let the other tasks finish their last job, then drain and report. */
        uint32_t expected = N_WORKLOAD_TASKS + (g_cfg.attack_enable ? 1u : 0u);
        for (int i = 0; i < 100 && tasks_done < expected; i++)
            vTaskDelay(pdMS_TO_TICKS(10));
        logging_flush();
        uint32_t end_info[3] = { tasks_done, trace_drops(), g_mon_stats.alarms };
        link_send(MSG_END, end_info, sizeof end_info);
        bsp_led(1);
    }
    vTaskSuspend(NULL);
}

static void spawn(const task_desc_t *d)
{
    xTaskCreate(periodic_task, d->name, d->stack_words, (void *)d, d->prio, &g_task[d->tid]);
    vTaskSetApplicationTaskTag(g_task[d->tid], (TaskHookFunction_t)(void *)&g_acct[d->tid]);
}

/* --------------------------------------------------------- boot / config */

typedef struct {
    uint8_t have_cfg;
    uint8_t start;
} boot_ctx_t;

/*
 * Measure the probe effect of the instrumentation itself, with interrupts
 * enabled as during the run: min is the intrinsic cost, max includes
 * interference. Reported so the paper can bound the measurement overhead.
 */
static void measure_calibration(void)
{
    enum { N = 2000 };
    calib_msg_t c = { .dwt_read_min = UINT32_MAX, .trace_push_min = UINT32_MAX,
                      .acct_hooks_min = UINT32_MAX, .samples = N };
    exec_acct_t dummy = { 0 };
    trace_rec_t r = { 0 };

    for (int i = 0; i < N; i++) {
        uint32_t t0 = cyc_now(), t1 = cyc_now(), d = t1 - t0;
        if (d < c.dwt_read_min) c.dwt_read_min = d;
        if (d > c.dwt_read_max) c.dwt_read_max = d;

        t0 = cyc_now();
        trace_push(&r);
        d = cyc_now() - t0;
        if (d < c.trace_push_min) c.trace_push_min = d;
        if (d > c.trace_push_max) c.trace_push_max = d;
        if ((i & 511) == 511) trace_reset();

        t0 = cyc_now();
        acct_switch_out(&dummy);
        acct_switch_in(&dummy);
        d = cyc_now() - t0;
        if (d < c.acct_hooks_min) c.acct_hooks_min = d;
        if (d > c.acct_hooks_max) c.acct_hooks_max = d;
    }
    trace_reset();
    link_send(MSG_CALIB, &c, sizeof c);
}

static void send_info(void)
{
    char s[120];
    int n = snprintf(s, sizeof s, "build=%s cc=gcc-%s flags=%s board=NUCLEO-F411RE", BUILD_ID, __VERSION__, BUILD_FLAGS);
    link_send(MSG_INFO, s, (size_t)n);
}

static void boot_on_frame(uint8_t type, const uint8_t *p, size_t len, void *ctx)
{
    boot_ctx_t *b = ctx;
    uint8_t ack[2] = { type, 0 };

    if (type == MSG_CONFIG && len == sizeof(run_config_t)) {
        memcpy(&g_cfg, p, sizeof g_cfg);
        b->have_cfg = 1;
        ack[1] = 1;
    } else if (type == MSG_START && b->have_cfg) {
        b->start = 1;
        ack[1] = 1;
    } else if (type == MSG_SENSOR) {
        return;   /* host may already stream sensor data */
    }
    link_send(MSG_ACK, ack, sizeof ack);
}

/*
 * Highest-priority boot task: announce itself, wait for CONFIG + START,
 * create the workload and fix the common epoch, then delete itself. One
 * board reset per run keeps runs independent.
 */
static void boot_task(void *arg)
{
    boot_ctx_t b = { 0 };
    uint8_t chunk[64];
    size_t n;
    const hello_msg_t hello = {
        .magic = 0x45524153u, .fw_version = FW_VERSION, .proto_version = PROTO_VERSION,
        .cpu_hz = CPU_HZ, .n_tasks = TID_COUNT, .record_size = sizeof(trace_rec_t),
        .config_size = sizeof(run_config_t),
    };

    vTaskSetApplicationTaskTag(xTaskGetIdleTaskHandle(), (TaskHookFunction_t)(void *)&g_acct[TID_IDLE]);

    TickType_t last_hello = 0;
    while (!b.start) {
        if (xTaskGetTickCount() - last_hello >= pdMS_TO_TICKS(500)) {
            last_hello = xTaskGetTickCount();
            link_send(MSG_HELLO, &hello, sizeof hello);
            send_info();
        }
        while ((n = bsp_uart_read(chunk, sizeof chunk)) > 0)
            link_rx_feed(&g_link_rx, chunk, n, boot_on_frame, &b);
        vTaskDelay(1);
    }
    g_link_rx.frames_ok = g_link_rx.frames_bad = 0;
    g_link_rx.bad_cobs = g_link_rx.bad_crc = g_link_rx.overlong_frames = g_link_rx.runt = 0;

    measure_calibration();
    workload_init();
    monitor_init();

    for (unsigned i = 0; i < N_WORKLOAD_TASKS; i++)
        spawn(&workload[i]);
    if (g_cfg.attack_enable) {
        attack_desc.prio = g_cfg.attack_prio;
        attack_desc.period_ms = g_cfg.attack_period_ms;
        attack_desc.job = attack_job;
        spawn(&attack_desc);
    }

    uint32_t now, now_cyc;
    timing_tick_origin(&now, &now_cyc);
    g_epoch_tick = now + pdMS_TO_TICKS(20);
    g_epoch_cyc = now_cyc + pdMS_TO_TICKS(20) * CYC_PER_TICK;
    g_end_tick = g_epoch_tick + pdMS_TO_TICKS(g_cfg.duration_ms);
    vTaskDelete(NULL);
}

void tasks_create_boot(void)
{
    xTaskCreate(boot_task, "Boot", 512, NULL, PRIO_BOOT, NULL);
}

void vApplicationStackOverflowHook(TaskHandle_t t, char *name)
{
    (void)t; (void)name;
    configASSERT(0);
}

void vApplicationMallocFailedHook(void)
{
    configASSERT(0);
}
