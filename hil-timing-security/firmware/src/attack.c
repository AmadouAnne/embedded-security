/*
 * E2: untrusted partition executing a CPU-exhaustion payload. Each job
 * consumes attack_load_permille of its period in *execution* cycles (so the
 * demand is exact even when the task is preempted). Its priority is a run
 * parameter: a hog below every workload task cannot delay them under
 * fixed-priority preemptive scheduling, which is itself a result to report.
 */
#include "runtime.h"
#include "timing.h"
#include "trace.h"

void attack_payload(uint32_t k)
{
    uint32_t budget = (uint32_t)((uint64_t)MS_TO_CYC(g_cfg.attack_period_ms) * g_cfg.attack_load_permille / 1000u);
    uint32_t e0 = acct_exec_now(&g_acct[TID_ATTACK]);
    volatile float x = 1.0001f;

    while (acct_exec_now(&g_acct[TID_ATTACK]) - e0 < budget)
        for (int i = 0; i < 16; i++)
            x = x * 1.0000001f + 1e-7f;
    (void)k;
}
