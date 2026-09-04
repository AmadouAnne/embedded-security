#include "stm32f4xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"
#include "semphr.h"
#include "tasks.h"
#include "security.h"
#include "fault_handlers.h"

QueueHandle_t     xSensorQueue;
SemaphoreHandle_t xUARTMutex;
UART_HandleTypeDef huart2;
ADC_HandleTypeDef  hadc1;

/* Stack (bottom-of-stack = lowest address, index 0) for the unprivileged
 * "Untrusted" task, created via xTaskCreateRestricted(). Statically
 * allocated because xTaskCreateRestricted() requires the caller to supply
 * puxStackBuffer -- this also gives Security_RegisterTask() a fixed address
 * to place a real stack canary at (dynamically-allocated tasks don't expose
 * their stack base in this FreeRTOS version, so LED/UART/Sensor instead
 * rely on the native configCHECK_FOR_STACK_OVERFLOW=2 watermark check). */
/* 128 words (512 bytes) was enough for the task's own busy-loop body, but
 * that never actually exercised its real worst-case stack usage: once the
 * task could actually run (see the priority fix above) and called
 * vTaskDelay(), the full unprivileged -> SVC -> privileged -> kernel call
 * chain overflowed it -- confirmed on real hardware via
 * vApplicationStackOverflowHook() firing for "Untrusted" (a silent
 * NVIC_SystemReset(), no fault message, which is why it looked different
 * from every other bug in this file's history). Must stay a power of two
 * for the MPU region size/alignment requirement. */
#define UNTRUSTED_STACK_WORDS 512
static StackType_t untrusted_stack[UNTRUSTED_STACK_WORDS] __attribute__((aligned(UNTRUSTED_STACK_WORDS * sizeof(StackType_t))));

/* Private RAM region granted to the Untrusted task -- the only memory
 * (besides its own stack) it can legally touch. Must be aligned to its own
 * size for the Cortex-M4 MPU's base-address field to take effect correctly. */
#define UNTRUSTED_SCRATCH_BYTES 32
static uint8_t untrusted_scratch[UNTRUSTED_SCRATCH_BYTES] __attribute__((aligned(UNTRUSTED_SCRATCH_BYTES)));

static void MX_GPIO_Init(void);
static void SystemClock_Config(void);
static void MX_USART2_UART_Init(void);
static void MX_ADC1_Init(void);

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName){
    (void)xTask; (void)pcTaskName;
    NVIC_SystemReset();
}

void vApplicationMallocFailedHook(void){ NVIC_SystemReset(); }

/* FreeRTOS owns SysTick_Handler entirely (see the xPortSysTickHandler alias
 * in FreeRTOSConfig.h), so nothing ever calls the STM32 HAL's own
 * HAL_IncTick() -- without this, HAL_GetTick() (uwTick) is frozen forever
 * and every HAL_GetTick()-based timeout (HAL_UART_Receive,
 * HAL_ADC_PollForConversion, ...) blocks indefinitely instead of expiring. */
void vApplicationTickHook(void){ HAL_IncTick(); }

int main(void){
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART2_UART_Init();
    MX_ADC1_Init();

    Security_MPU_Init();
    Security_StackGuard_Init();
    Security_IWDG_Init();
    FaultHandlers_Init();

    /* Length must be 1: vTask_Sensor uses xQueueOverwrite() (single-slot
     * "latest value" mailbox, read non-blockingly by vTask_UART) -- FreeRTOS
     * asserts xQueueOverwrite() is only ever used on a length-1 queue
     * (queue.c: configASSERT(!(xCopyPosition==queueOVERWRITE && uxLength!=1))).
     * With length 8 that assertion failed on every real run, permanently
     * halting the system with interrupts disabled (configASSERT() here is
     * taskDISABLE_INTERRUPTS();for(;;);) -- which froze HAL_GetTick() too
     * and was only ever visible from outside as a silent IWDG reset loop. */
    xSensorQueue = xQueueCreate(1, sizeof(float));
    xUARTMutex   = xSemaphoreCreateMutex();

    /* These are ordinary system tasks (HAL/UART/ADC access, RTOS primitives) --
     * portPRIVILEGE_BIT is required or FreeRTOS-MPU silently creates them
     * unprivileged (xRunPrivileged is derived from this exact bit in
     * uxPriority, see prvInitialiseNewTask()/pxPortInitialiseStack() in
     * tasks.c/port.c). Only "Untrusted" below is meant to be sandboxed. */
    /* LED is the watchdog-kick/canary-check task (see vTask_LED in tasks.c)
     * -- it must never be starved. UART/Sensor spend most of their time in
     * blocking-style HAL polls (HAL_UART_Receive/HAL_ADC_PollForConversion)
     * that busy-wait on HAL_GetTick() rather than yielding via a real RTOS
     * block, so at equal or lower priority LED never got scheduled and the
     * IWDG (~1.6s, never kicked) reset the board in a silent loop. Giving
     * LED strictly higher priority guarantees it always preempts them. */
    xTaskCreate(vTask_LED,    "LED",    configMINIMAL_STACK_SIZE*2, NULL, 3 | portPRIVILEGE_BIT, NULL);
    xTaskCreate(vTask_UART,   "UART",   configMINIMAL_STACK_SIZE*4, NULL, 2 | portPRIVILEGE_BIT, NULL);
    xTaskCreate(vTask_Sensor, "Sensor", configMINIMAL_STACK_SIZE*2, NULL, 2 | portPRIVILEGE_BIT, NULL);

    /* Unprivileged task, isolated by the Cortex-M4 MPU: it may only touch
     * its own stack (untrusted_stack) and untrusted_scratch. On the UART
     * "VIOLATE" command it deliberately writes to g_secure_secret, which is
     * outside both regions -- the MPU traps that access and MemManage_Handler
     * (fault_handlers.c) reports it and resets, instead of it silently
     * corrupting another task's state. */
    static const TaskParameters_t xUntrustedTaskParameters = {
        .pvTaskCode   = vTask_Untrusted,
        .pcName       = "Untrusted",
        .usStackDepth = UNTRUSTED_STACK_WORDS,
        .pvParameters = untrusted_scratch,
        /* KNOWN OPEN ISSUE (real hardware, not yet resolved -- see README):
         * at priority 1 this task never gets scheduled at all (same
         * busy-polling starvation as LED, see the comment above the
         * xTaskCreate() calls). Raising it to priority 2 lets it run, but
         * it then hits a deeper, still-undiagnosed bug the moment it calls
         * vTaskDelay() through FreeRTOS-MPU's SVC-based syscall gateway:
         * vApplicationStackOverflowHook() fires for "Untrusted" no matter
         * how large UNTRUSTED_STACK_WORDS is made (tried 128/256/512 words
         * -- all fail identically), and the TCB's pxTopOfStack at the point
         * of failure points nowhere near untrusted_stack[], which rules out
         * "just needs more stack" and points at something more fundamental
         * in how this restricted task's context is tracked across the SVC
         * privilege-raise/lower round trip. Left at priority 1 (starved but
         * stable) until that's properly root-caused -- this means the
         * VIOLATE demo cannot be completed on real hardware yet. */
        .uxPriority   = 1, /* no portPRIVILEGE_BIT -> unprivileged */
        .puxStackBuffer = untrusted_stack,
        .xRegions = {
            { untrusted_scratch, UNTRUSTED_SCRATCH_BYTES, portMPU_REGION_READ_WRITE },
            /* g_violate_signal (tasks.h/tasks.c): the task reads and clears
             * this flag every loop iteration -- without a granted region for
             * it, that read alone is an MPU violation (confirmed on real
             * hardware: it faulted on the very first iteration, before
             * "VIOLATE" was ever sent, once the task could finally run at
             * all -- see the priority fix above). */
            { g_violate_signal, sizeof(g_violate_signal), portMPU_REGION_READ_WRITE },
            { 0, 0, 0 },
        },
    };
    xTaskCreateRestricted(&xUntrustedTaskParameters, NULL);

    /* Must run AFTER xTaskCreateRestricted(): FreeRTOS-MPU's task creation
     * fills the whole stack buffer with its 0xA5 debug pattern (used for
     * uxTaskGetStackHighWaterMark()) as part of prvInitialiseNewTask() --
     * planting the canary before that call just gets it overwritten by the
     * fill, so Security_CheckCanaries() sees a permanent false-positive
     * "overflow" and resets the board in a loop before anything ever runs. */
    Security_RegisterTask("Untrusted", &untrusted_stack[0]);

    vTaskStartScheduler();
    while(1){}
}

static void SystemClock_Config(void){
    RCC_OscInitTypeDef osc={0};
    RCC_ClkInitTypeDef clk={0};
    osc.OscillatorType=RCC_OSCILLATORTYPE_HSI;
    osc.HSIState=RCC_HSI_ON;
    osc.HSICalibrationValue=RCC_HSICALIBRATION_DEFAULT;
    osc.PLL.PLLState=RCC_PLL_ON;
    osc.PLL.PLLSource=RCC_PLLSOURCE_HSI;
    osc.PLL.PLLM=16; osc.PLL.PLLN=200;
    osc.PLL.PLLP=RCC_PLLP_DIV2; osc.PLL.PLLQ=4;
    HAL_RCC_OscConfig(&osc);
    clk.ClockType=RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK|RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    clk.SYSCLKSource=RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider=RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider=RCC_HCLK_DIV2;
    clk.APB2CLKDivider=RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk,FLASH_LATENCY_3);
}

static void MX_GPIO_Init(void){
    GPIO_InitTypeDef g={0};
    __HAL_RCC_GPIOA_CLK_ENABLE();
    g.Pin=GPIO_PIN_5; g.Mode=GPIO_MODE_OUTPUT_PP;
    g.Pull=GPIO_NOPULL; g.Speed=GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOA,&g);

    /* PA2/PA3 = USART2 TX/RX (Nucleo ST-Link VCP) -- must be muxed to AF7
     * before HAL_UART_Init() touches the peripheral, otherwise USART2 is
     * initialized while its pins are still plain GPIO and nothing is ever
     * physically transmitted. */
    g.Pin=GPIO_PIN_2|GPIO_PIN_3;
    g.Mode=GPIO_MODE_AF_PP;
    g.Pull=GPIO_NOPULL;
    g.Speed=GPIO_SPEED_FREQ_VERY_HIGH;
    g.Alternate=GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA,&g);
}

static void MX_USART2_UART_Init(void){
    __HAL_RCC_USART2_CLK_ENABLE();
    huart2.Instance=USART2;
    huart2.Init.BaudRate=115200;
    huart2.Init.WordLength=UART_WORDLENGTH_8B;
    huart2.Init.StopBits=UART_STOPBITS_1;
    huart2.Init.Parity=UART_PARITY_NONE;
    huart2.Init.Mode=UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl=UART_HWCONTROL_NONE;
    huart2.Init.OverSampling=UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart2);
}

static void MX_ADC1_Init(void){
    __HAL_RCC_ADC1_CLK_ENABLE();
    ADC_ChannelConfTypeDef s={0};
    hadc1.Instance=ADC1;
    hadc1.Init.ClockPrescaler=ADC_CLOCK_SYNC_PCLK_DIV4;
    hadc1.Init.Resolution=ADC_RESOLUTION_12B;
    hadc1.Init.ScanConvMode=DISABLE;
    hadc1.Init.ContinuousConvMode=DISABLE;
    hadc1.Init.ExternalTrigConvEdge=ADC_EXTERNALTRIGCONVEDGE_NONE;
    hadc1.Init.DataAlign=ADC_DATAALIGN_RIGHT;
    hadc1.Init.NbrOfConversion=1;
    HAL_ADC_Init(&hadc1);
    s.Channel=ADC_CHANNEL_TEMPSENSOR;
    s.Rank=1; s.SamplingTime=ADC_SAMPLETIME_480CYCLES;
    HAL_ADC_ConfigChannel(&hadc1,&s);
}
