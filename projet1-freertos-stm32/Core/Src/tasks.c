#include "stm32f4xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"
#include "tasks.h"
#include "security.h"
#include <stdio.h>
#include <string.h>

extern QueueHandle_t      xSensorQueue;
extern SemaphoreHandle_t  xUARTMutex;
extern TimerHandle_t      xWatchdogTimer;
extern UART_HandleTypeDef huart2;
extern ADC_HandleTypeDef  hadc1;

static void UART_Print(const char *msg){
    if(xSemaphoreTake(xUARTMutex,pdMS_TO_TICKS(100))==pdTRUE){
        HAL_UART_Transmit(&huart2,(uint8_t*)msg,strlen(msg),100);
        xSemaphoreGive(xUARTMutex);
    }
}

void vTask_LED(void *pvParameters){
    (void)pvParameters;
    char msg[64];
    for(;;){
        HAL_GPIO_TogglePin(GPIOA,GPIO_PIN_5);
        xTimerReset(xWatchdogTimer,0);
        snprintf(msg,sizeof(msg),"[LED] tick=%lu
",(unsigned long)xTaskGetTickCount());
        UART_Print(msg);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void vTask_UART(void *pvParameters){
    (void)pvParameters;
    char msg[256];
    float temperature=0.0f;
    for(;;){
        xQueueReceive(xSensorQueue,&temperature,0);
        snprintf(msg,sizeof(msg),"=== Report @%lu ms === Tasks:%u Heap:%u Temp:%.1fC
",
            (unsigned long)xTaskGetTickCount(),
            (unsigned)uxTaskGetNumberOfTasks(),
            (unsigned)xPortGetFreeHeapSize(),
            temperature);
        UART_Print(msg);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void vTask_Sensor(void *pvParameters){
    (void)pvParameters;
    for(;;){
        HAL_ADC_Start(&hadc1);
        if(HAL_ADC_PollForConversion(&hadc1,10)==HAL_OK){
            uint32_t raw=HAL_ADC_GetValue(&hadc1);
            float vsense=(raw*3.3f)/4096.0f;
            float temp=((vsense-0.76f)/0.0025f)+25.0f;
            xQueueOverwrite(xSensorQueue,&temp);
        }
        HAL_ADC_Stop(&hadc1);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
