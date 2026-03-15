#include "stm32f4xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"
#include "semphr.h"
#include "tasks.h"
#include "security.h"

QueueHandle_t     xSensorQueue;
SemaphoreHandle_t xUARTMutex;
TimerHandle_t     xWatchdogTimer;
UART_HandleTypeDef huart2;
ADC_HandleTypeDef  hadc1;

static void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_ADC1_Init(void);

static void vWatchdogCallback(TimerHandle_t xTimer){
    (void)xTimer;
    NVIC_SystemReset();
}

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName){
    (void)xTask; (void)pcTaskName;
    NVIC_SystemReset();
}

void vApplicationMallocFailedHook(void){ NVIC_SystemReset(); }

int main(void){
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART2_UART_Init();
    MX_ADC1_Init();
    Security_MPU_Init();
    Security_StackGuard_Init();
    xSensorQueue  = xQueueCreate(8, sizeof(float));
    xUARTMutex    = xSemaphoreCreateMutex();
    xWatchdogTimer = xTimerCreate("WDG",pdMS_TO_TICKS(5000),pdFALSE,NULL,vWatchdogCallback);
    xTimerStart(xWatchdogTimer, 0);
    xTaskCreate(vTask_LED,    "LED",    configMINIMAL_STACK_SIZE*2, NULL, 1, NULL);
    xTaskCreate(vTask_UART,   "UART",   configMINIMAL_STACK_SIZE*4, NULL, 2, NULL);
    xTaskCreate(vTask_Sensor, "Sensor", configMINIMAL_STACK_SIZE*2, NULL, 2, NULL);
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
}

static void MX_USART2_UART_Init(void){
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
