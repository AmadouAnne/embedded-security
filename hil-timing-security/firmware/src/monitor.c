#include "monitor.h"
#include "runtime.h"
#include "trace.h"
#include "bsp.h"
#include <math.h>

typedef struct {
    float    mu, var;
    uint32_t n;
    uint8_t  consec;
} mon_state_t;

static mon_state_t st[TID_COUNT];
volatile mon_stats_t g_mon_stats;

static volatile uint8_t  mit_active;
static volatile uint32_t mit_until;      /* tick at which the cool-down ends */
static volatile uint8_t  rx_masked;
static UBaseType_t saved_attack_prio;

void monitor_init(void)
{
    for (int i = 0; i < TID_COUNT; i++)
        st[i] = (mon_state_t){ 0 };
}

uint8_t mitigation_active(void)
{
    return mit_active;
}

static void mitigation_start(void)
{
    uint32_t now = xTaskGetTickCount();

    mit_until = now + pdMS_TO_TICKS(g_cfg.cooldown_ms);
    if (mit_active)
        return;   /* already engaged: just extend the cool-down */
    mit_active = 1;
    g_mon_stats.mitigations++;

    if ((g_cfg.mitigation_mask & MIT_DEMOTE) && g_task[TID_ATTACK]) {
        saved_attack_prio = uxTaskPriorityGet(g_task[TID_ATTACK]);
        vTaskPrioritySet(g_task[TID_ATTACK], PRIO_DEMOTED);
    }
    if (g_cfg.mitigation_mask & MIT_RX_THROTTLE) {
        rx_masked = 1;
        bsp_uart_rx_enable(0);
    }
}

/* Task-context part of the recovery (priority changes are not ISR-safe). */
static void mitigation_poll(void)
{
    if (!mit_active || (int32_t)(xTaskGetTickCount() - mit_until) < 0)
        return;
    if ((g_cfg.mitigation_mask & MIT_DEMOTE) && g_task[TID_ATTACK])
        vTaskPrioritySet(g_task[TID_ATTACK], saved_attack_prio);
    mit_active = 0;
}

void mitigation_tick(uint32_t tick)
{
    if (rx_masked && (int32_t)(tick - mit_until) >= 0) {
        rx_masked = 0;
        bsp_uart_rx_enable(1);
    }
}

uint8_t monitor_update(uint8_t tid, uint32_t response, uint32_t deadline)
{
    if (g_cfg.monitor_mode == MON_OFF || !(g_cfg.monitor_task_mask & (1u << tid)))
        return 0;

    mon_state_t *s = &st[tid];
    float r = (float)response;
    uint8_t flags = 0;
    int alarm = 0;

    if (s->n >= g_cfg.warmup_jobs) {
        float sigma = sqrtf(s->var);
        /* Lower bound on sigma relative to mu: nominal response times are so
           deterministic that a pure k-sigma rule would alarm on a few cycles. */
        if (sigma < g_cfg.sigma_floor * s->mu)
            sigma = g_cfg.sigma_floor * s->mu;
        alarm = r > s->mu + g_cfg.k_sigma * sigma || r > g_cfg.guard_ratio * (float)deadline;
    }

    /* Learn during warm-up; afterwards either freeze the baseline or keep
       adapting on non-alarm samples only, so an attack cannot drag it up. */
    if (s->n < g_cfg.warmup_jobs || (!g_cfg.monitor_frozen && !alarm)) {
        if (s->n == 0) {
            s->mu = r;
            s->var = 0.0f;
        } else {
            float a = g_cfg.ewma_alpha, d = r - s->mu;
            s->mu += a * d;
            s->var = (1.0f - a) * (s->var + a * d * d);
        }
    }
    s->n++;

    if (alarm) {
        flags |= TF_ALARM;
        g_mon_stats.alarms++;
        if (s->consec < 255) s->consec++;
        if (g_cfg.monitor_mode == MON_MITIGATE && s->consec >= g_cfg.alarm_consec)
            mitigation_start();
    } else {
        s->consec = 0;
    }

    if (g_cfg.monitor_mode == MON_MITIGATE)
        mitigation_poll();
    if (mit_active)
        flags |= TF_MITIGATING;
    return flags;
}
