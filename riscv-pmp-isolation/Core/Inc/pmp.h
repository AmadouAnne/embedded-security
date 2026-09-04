#ifndef PMP_H
#define PMP_H

/* Configures two PMP-enforced regions for the U-mode "untrusted" task:
 *   1. Its own code (.text.untrusted)      -- Read+Execute
 *   2. Its own scratch data + stack (.data.scratch) -- Read+Write
 * Every other address is denied to U-mode by PMP's fail-closed default
 * (no matching entry => access denied for U/S-mode; M-mode is exempt
 * unless an entry's lock bit is set, which none of these are). */
void pmp_configure(void);

#endif /* PMP_H */
