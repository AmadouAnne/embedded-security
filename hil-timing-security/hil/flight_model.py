"""Environment model run on the HIL host: a smooth, bounded flight profile
producing IMU + barometer samples at 200 Hz, plus the E4 data-perturbation
injector. Deterministic for a given seed so runs are reproducible."""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

G = 9.81


@dataclass
class Perturbation:
    kind: str = "none"        # none | spike | nan | stuck_max
    rate: float = 0.0         # fraction of frames affected
    magnitude: float = 1e3    # multiplier for spikes


class FlightModel:
    def __init__(self, seed: int = 0) -> None:
        self.rng = random.Random(seed)
        self.t = 0.0

    def step(self, dt: float) -> list[float]:
        """Return [ax, ay, az, gx, gy, gz, alt] for a gentle climbing turn."""
        self.t += dt
        t, n = self.t, self.rng.gauss
        roll_rate = 0.15 * math.sin(0.20 * t)
        pitch_rate = 0.05 * math.sin(0.07 * t + 1.0)
        yaw_rate = 0.08 * math.cos(0.10 * t)
        return [
            0.3 * math.sin(0.2 * t) + n(0, 0.05),
            0.2 * math.cos(0.13 * t) + n(0, 0.05),
            -G + 0.1 * math.sin(0.5 * t) + n(0, 0.05),
            roll_rate + n(0, 0.002),
            pitch_rate + n(0, 0.002),
            yaw_rate + n(0, 0.002),
            1500.0 + 2.0 * t + n(0, 0.3),
        ]


def perturb(sample: list[float], p: Perturbation, rng: random.Random) -> list[float]:
    if p.kind == "none" or rng.random() >= p.rate:
        return sample
    s = list(sample)
    if p.kind == "spike":
        for i in range(3, 6):                      # gyro channels drive the slow path
            s[i] *= p.magnitude
    elif p.kind == "nan":
        s[rng.randrange(3, 6)] = float("nan")
    elif p.kind == "stuck_max":
        s[3:6] = [3.4e38] * 3
    else:
        raise ValueError(f"unknown perturbation {p.kind}")
    return s
