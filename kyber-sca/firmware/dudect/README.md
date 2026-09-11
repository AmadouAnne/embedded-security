# (moved) dudect timing harness

The firmware harness originally sketched for this directory ended up living
inside the PQM4 fork submodule instead, at
[`../pqm4/common/dudect.c`](../pqm4/common/dudect.c) and
[`../pqm4/common/keypair_control.c`](../pqm4/common/keypair_control.c) (built
via [`../pqm4/mk/dudect.mk`](../pqm4/mk/dudect.mk)) -- not here.

Reason: PQM4's per-scheme build rules (`mupq/mk/schemes.mk`) compile a KEM
test harness straight from `mupq/crypto_kem/<name>.c`, but `mupq` here is an
*unforked* submodule (plain upstream `mupq/mupq`, unlike `pqm4` itself which
this project already forked for board support -- see
[`../../README.md`](../../README.md)). Adding a harness there would mean
forking `mupq` too just for one file. Putting the harness directly in the
already-forked `pqm4` fork's own `common/` dir, with a small hand-written
Makefile rule mirroring `mupq/mk/schemes.mk`'s pattern, avoids that for a
single extra source file -- see `mk/dudect.mk`'s header comment for the
exact mechanism.

See [`../../timing/README.md`](../../timing/README.md) for the host-side
half of this and the current results.
