"""Response-time analysis (RTA) for the fixed-priority workload, fed with measured
execution times, and its comparison with the measured worst-case responses.

Classic preemptive fixed-priority RTA (Joseph & Pandya; Audsley et al. 1993):

    R_i = C_i + sum_{j in hp(i)} ceil(R_i / T_j) * C_j

iterated to a fixed point; unschedulable if R_i > D_i = T_i. C_i is the maximum
observed execution time (MOET) of the scenario, so the bound is only as safe as
MOET is (it is not a WCET). The Logging job blocks on the trace DMA
(self-suspension), which plain RTA does not model; its row is reported but
flagged.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from sare import PERIOD_MS

# FreeRTOS priorities (firmware/include/app_config.h); higher = more urgent.
PRIO = {"sensor": 14, "control": 12, "nav": 10, "health": 8, "security": 6, "logging": 4}
ATTACK_PERIOD_MS = 10
SELF_SUSPENDING = {"logging"}


def rta(tasks: dict[str, tuple[float, float, int]], jitter: float = 0.0) -> dict[str, float]:
    """tasks: name -> (C, T, prio), same time unit. Returns name -> R (inf if > T).

    jitter J (same for every task) is a release jitter: the time between the
    nominal release and the job becoming ready (tick ISR, scheduler, context
    switch). With J: w = C + sum ceil((w + J) / T_j) C_j and R = J + w
    (Audsley et al. 1993)."""
    out = {}
    for name, (c, t, p) in tasks.items():
        hp = [(cj, tj) for n, (cj, tj, pj) in tasks.items() if n != name and pj > p]
        w = c
        while True:
            nxt = c + sum(math.ceil((w + jitter) / tj) * cj for cj, tj in hp)
            if nxt + jitter > t:
                w = math.inf
                break
            if nxt == w:
                break
            w = nxt
        out[name] = w + jitter
    return out


def attack_config(scenario: str) -> tuple[int, int] | None:
    """(priority, load in per-mille) of the attacker encoded in an E2/X1 scenario name."""
    import re
    m = re.search(r"E2_p(\d+)_l(\d+)$", scenario)
    return (int(m.group(1)), int(m.group(2))) if m else None


def compare(tm: pd.DataFrame, scenarios) -> pd.DataFrame:
    """Per scenario x task: RTA bound from measured MOETs vs measured R_max, without
    and with the kernel release latency (the top-priority task's measured worst
    start latency, i.e. tick ISR + scheduler + context switch)."""
    rows = []
    for sc in scenarios:
        s = tm[tm["scenario"] == sc].set_index("task")
        tasks = {t: (float(s.loc[t, "MOET_us"]), PERIOD_MS[t] * 1e3, p) for t, p in PRIO.items() if t in s.index}
        att = attack_config(sc)
        if att and "attack" in s.index:
            tasks["attack"] = (float(s.loc["attack", "MOET_us"]), ATTACK_PERIOD_MS * 1e3, att[0])
        bounds = rta(tasks)
        j = float(s.loc["sensor", "S_max_us"]) if "sensor" in s.index else 0.0
        bounds_j = rta(tasks, jitter=j)
        for t in PRIO:
            if t not in s.index:
                continue
            r_meas, r_rta = float(s.loc[t, "R_max_us"]), bounds[t]
            rows.append({"scenario": sc, "task": t, "C_moet_us": tasks[t][0], "R_rta_us": r_rta,
                         "R_meas_us": r_meas, "meas_over_rta": r_meas / r_rta if np.isfinite(r_rta) else np.nan,
                         "D_us": tasks[t][1], "rta_schedulable": bool(np.isfinite(r_rta)),
                         "bound_holds": bool(r_meas <= r_rta), "J_kernel_us": j, "R_rta_j_us": bounds_j[t],
                         "bound_j_holds": bool(r_meas <= bounds_j[t]), "self_suspending": t in SELF_SUSPENDING})
    return pd.DataFrame(rows)
