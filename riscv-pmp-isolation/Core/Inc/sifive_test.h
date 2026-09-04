#ifndef SIFIVE_TEST_H
#define SIFIVE_TEST_H

/* Cleanly powers off QEMU via its "sifive_test" finisher device, instead
 * of spinning in wfi forever -- lets the demo terminate on its own so it
 * can be run non-interactively (no need to Ctrl+A X). */
void sifive_poweroff(void) __attribute__((noreturn));

#endif /* SIFIVE_TEST_H */
