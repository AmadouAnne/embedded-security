#include "bsp.h"
#include "timing.h"
#include "tasks.h"
#include "FreeRTOS.h"
#include "task.h"

int main(void)
{
    bsp_init();
    timing_init();
    tasks_create_boot();
    vTaskStartScheduler();
    for (;;) {}
}
