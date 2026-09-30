"""The host replay must raise exactly the alarms of firmware/src/monitor.c."""
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "analysis"))
import monitor_replay as mr  # noqa: E402

# Minimal stand-ins for the FreeRTOS/BSP symbols monitor.c uses; the real
# monitor.c, link.h (run_config_t) and trace.h (flags) are compiled unchanged.
STUB_RUNTIME = r"""
#ifndef RUNTIME_H
#define RUNTIME_H
#include <stdint.h>
#include "link.h"
#include "app_config.h"
typedef void *TaskHandle_t;
typedef unsigned long UBaseType_t;
#define pdMS_TO_TICKS(ms) (ms)
extern run_config_t g_cfg;
extern TaskHandle_t g_task[TID_COUNT];
static inline uint32_t xTaskGetTickCount(void) { return 0; }
static inline void vTaskPrioritySet(TaskHandle_t t, UBaseType_t p) { (void)t; (void)p; }
static inline UBaseType_t uxTaskPriorityGet(TaskHandle_t t) { (void)t; return 0; }
#endif
"""
HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include "runtime.h"
#include "monitor.h"
#include "trace.h"
run_config_t g_cfg;
TaskHandle_t g_task[TID_COUNT];
void bsp_uart_rx_enable(int on) { (void)on; }
int main(int argc, char **argv) {
    g_cfg.monitor_mode = MON_DETECT;          /* detection only: no mitigation side effects */
    g_cfg.monitor_task_mask = 1;
    g_cfg.ewma_alpha = strtof(argv[1], 0);
    g_cfg.k_sigma = strtof(argv[2], 0);
    g_cfg.guard_ratio = strtof(argv[3], 0);
    g_cfg.sigma_floor = strtof(argv[4], 0);
    g_cfg.warmup_jobs = (uint16_t)atoi(argv[5]);
    g_cfg.monitor_frozen = (uint8_t)atoi(argv[6]);
    uint32_t deadline = (uint32_t)atol(argv[7]), r;
    monitor_init();
    while (scanf("%u", &r) == 1)
        putchar(monitor_update(0, r, deadline) & TF_ALARM ? '1' : '0');
    return 0;
}
"""


@pytest.fixture(scope="module")
def monitor_c(tmp_path_factory):
    d = tmp_path_factory.mktemp("mon")
    (d / "runtime.h").write_text(STUB_RUNTIME)
    (d / "h.c").write_text(HARNESS)
    exe = d / "mon"
    subprocess.run(["gcc", "-O2", "-ffp-contract=off", "-I", d, "-I", ROOT / "firmware/include",
                    d / "h.c", ROOT / "firmware/src/monitor.c", "-lm", "-o", exe], check=True)
    return exe


def c_alarms(exe, R, D, p):
    args = [str(exe), repr(p.ewma_alpha), repr(p.k_sigma), repr(p.guard_ratio), repr(p.sigma_floor),
            str(p.warmup_jobs), str(int(p.frozen)), str(D)]
    out = subprocess.run(args, input=" ".join(map(str, R)), capture_output=True, text=True, check=True).stdout
    return np.array([c == "1" for c in out])


def series(seed, n=6000):
    """Nominal jitter with bimodality, bursts and a late ramp: exercises
    warm-up, floor, k-sigma, guard and near-threshold values."""
    rng = np.random.default_rng(seed)
    r = 49_000 + rng.integers(0, 900, n) + (rng.random(n) < 0.3) * 8_000
    r[3000:3050] += 60_000
    r[5000:] += np.linspace(0, 400_000, n - 5000).astype(int)
    return r.astype(np.uint32)


@pytest.mark.parametrize("p", [
    mr.MonitorParams(),
    mr.MonitorParams(k_sigma=3.0, sigma_floor=0.005, warmup_jobs=100),
    mr.MonitorParams(k_sigma=6.0, sigma_floor=0.05, frozen=False),
    mr.MonitorParams(ewma_alpha=0.01, k_sigma=2.5, guard_ratio=0.6, sigma_floor=0.0),
])
def test_replay_bit_exact(monitor_c, p):
    D = 500_000
    for seed in range(3):
        R = series(seed)
        py, _ = mr.replay(R, D, p)
        c = c_alarms(monitor_c, R, D, p)
        assert np.array_equal(py, c), f"first mismatch at job {np.argmax(py != c)}"
        assert 0 < py.sum() < len(R)          # the series really exercises both outcomes


def test_trigger_needs_consecutive_alarms():
    p = mr.MonitorParams(warmup_jobs=10, alarm_consec=3)
    R = np.array([100] * 20 + [1000, 100, 1000, 1000, 1000], dtype=np.uint32)
    alarm, trig = mr.replay(R, 10_000, p)
    assert alarm[20] and not trig[20] and trig[24] and not trig[23]


@pytest.mark.parametrize("p", [
    mr.MonitorParams(),
    mr.MonitorParams(k_sigma=2.0, sigma_floor=0.0, warmup_jobs=100, alarm_consec=2),
    mr.MonitorParams(ewma_alpha=0.1, k_sigma=5.0, sigma_floor=0.05, warmup_jobs=500),
])
def test_fast_replay_equals_reference(p):
    for seed in range(4):
        R = series(seed)
        a_ref, t_ref = mr.replay(R, 500_000, p)
        a_fast, t_fast = mr.replay_frozen_fast(R, 500_000, p)
        assert np.array_equal(a_ref, a_fast) and np.array_equal(t_ref, t_fast)
