import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rta  # noqa: E402


def test_textbook_example():
    # Liu & Layland style set: C/T = 1/4 (high), 2/6 (low)  ->  R_low = 2 + ceil(3/4)*1 = 3
    assert rta.rta({"a": (1, 4, 2), "b": (2, 6, 1)}) == {"a": 1, "b": 3}


def test_unschedulable_is_inf():
    assert math.isinf(rta.rta({"a": (3, 4, 2), "b": (2, 6, 1)})["b"])


def test_jitter_adds_to_response():
    r0 = rta.rta({"a": (1, 4, 2), "b": (2, 6, 1)})
    r1 = rta.rta({"a": (1, 4, 2), "b": (2, 6, 1)}, jitter=0.5)
    assert r1["a"] == r0["a"] + 0.5 and r1["b"] >= r0["b"] + 0.5


def test_attack_config_parsing():
    assert rta.attack_config("X1_E2_p13_l450") == (13, 450)
    assert rta.attack_config("E1_ref") is None
