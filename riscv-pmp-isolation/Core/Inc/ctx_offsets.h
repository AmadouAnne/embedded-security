#ifndef CTX_OFFSETS_H
#define CTX_OFFSETS_H

/* Byte offsets into task_context_t (scheduler.h), for rv64 (8-byte GPRs).
 * Plain #defines only -- this header is included both from C (scheduler.h,
 * which _Static_asserts these against offsetof()) and from context_switch.S
 * (compiled with -x assembler-with-cpp), so it must stay assembler-safe. */
#define CTX_OFF_X1    0    /* ra */
#define CTX_OFF_X2    8    /* sp */
#define CTX_OFF_X3    16   /* gp */
#define CTX_OFF_X4    24   /* tp */
#define CTX_OFF_X5    32   /* t0 */
#define CTX_OFF_X6    40   /* t1 */
#define CTX_OFF_X7    48   /* t2 */
#define CTX_OFF_X8    56   /* s0/fp */
#define CTX_OFF_X9    64   /* s1 */
#define CTX_OFF_X10   72   /* a0 */
#define CTX_OFF_X11   80   /* a1 */
#define CTX_OFF_X12   88   /* a2 */
#define CTX_OFF_X13   96   /* a3 */
#define CTX_OFF_X14   104  /* a4 */
#define CTX_OFF_X15   112  /* a5 */
#define CTX_OFF_X16   120  /* a6 */
#define CTX_OFF_X17   128  /* a7 */
#define CTX_OFF_X18   136  /* s2 */
#define CTX_OFF_X19   144  /* s3 */
#define CTX_OFF_X20   152  /* s4 */
#define CTX_OFF_X21   160  /* s5 */
#define CTX_OFF_X22   168  /* s6 */
#define CTX_OFF_X23   176  /* s7 */
#define CTX_OFF_X24   184  /* s8 */
#define CTX_OFF_X25   192  /* s9 */
#define CTX_OFF_X26   200  /* s10 */
#define CTX_OFF_X27   208  /* s11 */
#define CTX_OFF_X28   216  /* t3 */
#define CTX_OFF_X29   224  /* t4 */
#define CTX_OFF_X30   232  /* t5 */
#define CTX_OFF_X31   240  /* t6 */
#define CTX_OFF_MEPC     248
#define CTX_OFF_MSTATUS  256
#define CTX_SIZE         264

#endif /* CTX_OFFSETS_H */
