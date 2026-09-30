"""Bit-exact host replay of the on-target timing monitor (firmware/src/monitor.c).

Every operation is done in float32, in the same order as the C code, and the
firmware is built with -ffp-contract=off, so for a given response-time series
the replay raises exactly the same alarms as the board. This allows the
monitor parameters to be calibrated offline on recorded C0 runs
(docs/analysis_plan.md, Sec. 6). tests/test_monitor_replay.py checks the
equivalence against monitor.c compiled for the host.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

f32 = np.float32


@dataclass(frozen=True)
class MonitorParams:
    ewma_alpha: float = 0.05
    k_sigma: float = 4.0
    guard_ratio: float = 0.8
    sigma_floor: float = 0.01
    warmup_jobs: int = 200
    frozen: bool = True
    alarm_consec: int = 3


def replay(response_cyc, deadline_cyc: int, p: MonitorParams) -> tuple[np.ndarray, np.ndarray]:
    """Replay the monitor on one task's response times (cycles, job order).

    Returns (alarm, trigger): boolean arrays per job; `trigger` marks jobs
    where the consecutive-alarm count reaches alarm_consec, i.e. where the
    firmware would start a mitigation in MON_MITIGATE mode.
    """
    a, k, g, fl = f32(p.ewma_alpha), f32(p.k_sigma), f32(p.guard_ratio), f32(p.sigma_floor)
    one = f32(1.0)
    dl = f32(deadline_cyc)
    mu = var = f32(0.0)
    n = consec = 0
    R = np.asarray(response_cyc, dtype=np.uint32)
    alarm = np.zeros(len(R), dtype=bool)
    trig = np.zeros(len(R), dtype=bool)
    for i, rc in enumerate(R):
        r = f32(rc)
        al = False
        if n >= p.warmup_jobs:
            sigma = np.sqrt(var, dtype=np.float32)
            floor = fl * mu
            if sigma < floor:
                sigma = floor
            al = bool(r > mu + k * sigma) or bool(r > g * dl)
        if n < p.warmup_jobs or (not p.frozen and not al):
            if n == 0:
                mu, var = r, f32(0.0)
            else:
                d = r - mu
                mu = mu + a * d
                var = (one - a) * (var + a * d * d)
        n += 1
        if al:
            alarm[i] = True
            consec = min(consec + 1, 255)
            if consec >= p.alarm_consec:
                trig[i] = True
        else:
            consec = 0
    return alarm, trig


def replay_frozen_fast(response_cyc, deadline_cyc: int, p: MonitorParams) -> tuple[np.ndarray, np.ndarray]:
    """Same result as replay() for frozen=True, vectorised after warm-up.

    With a frozen baseline, mu and var stop changing after warm_up jobs, so
    the threshold mu + k*sigma is a constant: the warm-up is replayed
    sequentially in float32 (exactly as the C code), and the comparisons for
    all later jobs are then done at once with the same float32 operations.
    Equality with replay() is checked in tests/test_monitor_replay.py.
    """
    if not p.frozen:
        return replay(response_cyc, deadline_cyc, p)
    R = np.asarray(response_cyc, dtype=np.uint32)
    w = min(p.warmup_jobs, len(R))
    a, one = f32(p.ewma_alpha), f32(1.0)
    mu = var = f32(0.0)
    for i in range(w):
        r = f32(R[i])
        if i == 0:
            mu, var = r, f32(0.0)
        else:
            d = r - mu
            mu = mu + a * d
            var = (one - a) * (var + a * d * d)
    alarm = np.zeros(len(R), dtype=bool)
    if len(R) > w:
        sigma = np.sqrt(var, dtype=np.float32)
        floor = f32(p.sigma_floor) * mu
        if sigma < floor:
            sigma = floor
        thr = mu + f32(p.k_sigma) * sigma
        guard = f32(p.guard_ratio) * f32(deadline_cyc)
        r = R[w:].astype(np.float32)
        alarm[w:] = (r > thr) | (r > guard)
    # consecutive-alarm count reaching alarm_consec (count saturates at 255)
    trig = np.zeros(len(R), dtype=bool)
    if alarm.any():
        run = np.zeros(len(R), dtype=np.int64)
        idx = np.flatnonzero(alarm)
        starts = np.r_[True, np.diff(idx) != 1]
        grp = np.cumsum(starts)
        first = idx[starts][grp - 1]
        run[idx] = idx - first + 1
        trig = run >= p.alarm_consec
    return alarm, trig


def threshold_over_d(response_cyc, deadline_cyc: int, p: MonitorParams) -> float:
    """Effective alarm threshold min(mu + k*sigma, guard*D) / D after warm-up
    (frozen baseline): the sensitivity figure used to rank parameter sets."""
    R = np.asarray(response_cyc, dtype=np.float64)[: p.warmup_jobs]
    a = p.ewma_alpha
    mu, var = R[0], 0.0
    for r in R[1:]:
        d = r - mu
        mu += a * d
        var = (1 - a) * (var + a * d * d)
    sigma = max(np.sqrt(var), p.sigma_floor * mu)
    return float(min(mu + p.k_sigma * sigma, p.guard_ratio * deadline_cyc) / deadline_cyc)
