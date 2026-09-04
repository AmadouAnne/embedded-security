#ifndef TRAP_H
#define TRAP_H

/* Installs trap_handler as mtvec (direct mode). Call once, before
 * dropping to U-mode. */
void trap_init(void);

#endif /* TRAP_H */
