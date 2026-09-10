"""ML-KEM NTT-domain arithmetic and Hamming-weight helper.

Only what the simulated leakage model and the CPA distinguisher need:
the modulus, coefficient-wise modular multiplication, and a vectorized
popcount. Same role as side-channel/aes_sbox.py plays for P6.
"""
import numpy as np

Q = 3329  # ML-KEM modulus -- same for all parameter sets (512/768/1024)


def pointwise_mul_mod_q(a, b):
    """Coefficient-wise product mod Q, vectorized.

    This is the operation ML-KEM's decryption performs once per NTT
    coefficient: multiplying a known (attacker-chosen ciphertext) NTT
    coefficient by the corresponding secret-key NTT coefficient, before
    the inverse NTT and message decoding. See ../docs/methodology.md.
    """
    return (np.asarray(a, dtype=np.int64) * np.asarray(b, dtype=np.int64)) % Q


def hamming_weight(x):
    """Vectorized popcount (values must fit in 32 bits -- Q-1 needs 12)."""
    x = np.asarray(x, dtype=np.uint32)
    x = x - ((x >> 1) & np.uint32(0x55555555))
    x = (x & np.uint32(0x33333333)) + ((x >> 2) & np.uint32(0x33333333))
    x = (x + (x >> 4)) & np.uint32(0x0F0F0F0F)
    return ((x * np.uint32(0x01010101)) >> 24).astype(np.int64)
