#include "stm32f4xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"
#include "tasks.h"
#include "security.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern QueueHandle_t      xSensorQueue;
extern SemaphoreHandle_t  xUARTMutex;
extern UART_HandleTypeDef huart2;
extern ADC_HandleTypeDef  hadc1;

/* vTask_Untrusted (unprivileged) reads and clears this flag every loop
 * iteration -- it must live inside one of the task's own granted MPU
 * regions, or the mere act of checking it faults. A bare
 * "volatile uint8_t g_violate_requested" doesn't satisfy that (the Cortex-M4
 * MPU's minimum region size is 32 bytes, aligned to its own size, and nearby
 * globals would otherwise share that block), so it gets the same dedicated,
 * isolated, aligned-buffer treatment as untrusted_scratch in main.c.
 * Confirmed on real hardware: this was a real, previously-unobserved bug --
 * it only ever surfaced once the Untrusted task's earlier priority-inversion
 * starvation (see main.c) was fixed and it could finally run at all. */
uint8_t g_violate_signal[32] __attribute__((aligned(32)));
volatile uint32_t g_secure_secret     = 0xC0FFEE;

/* Demo pre-shared key for the UART challenge-response protocol.
 * This is intentionally a fixed constant for the hardware validation demo
 * -- a real deployment would provision this per-device (e.g. from a
 * protected flash sector or a secure element), never hardcode it in
 * source. */
static const uint8_t PSK[] = { 0x4b, 0x6f, 0x75, 0x63, 0x6c, 0x65, 0x61,
                                0x6e, 0x2d, 0x50, 0x31, 0x2d, 0x64, 0x65,
                                0x6d, 0x6f };

static void UART_Print(const char *msg){
    if(xSemaphoreTake(xUARTMutex,pdMS_TO_TICKS(100))==pdTRUE){
        HAL_UART_Transmit(&huart2,(uint8_t*)msg,strlen(msg),100);
        xSemaphoreGive(xUARTMutex);
    }
}

static int hexval(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_max, size_t *out_len){
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2*i]), lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

static void hex_encode(const uint8_t *in, size_t len, char *out){
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = digits[in[i] >> 4];
        out[2*i+1] = digits[in[i] & 0x0F];
    }
    out[2*len] = '\0';
}

/* Parses one line received over UART and reacts to it:
 *   AUTH <hex nonce>   -> replies "RESP <hex hmac-sha256(psk, nonce)>"
 *   VIOLATE             -> asks vTask_Untrusted to perform its illegal write
 * Anything else is ignored (this is a demo protocol, not a hardened parser). */
static void handle_line(char *line)
{
    /* strip trailing CR/LF */
    size_t len = strlen(line);
    while (len && (line[len-1]=='\r' || line[len-1]=='\n')) line[--len] = '\0';

    if (strncmp(line, "AUTH ", 5) == 0) {
        uint8_t nonce[64];
        size_t  nonce_len;
        if (hex_decode(line + 5, nonce, sizeof(nonce), &nonce_len) == 0) {
            uint8_t mac[HMAC_SHA256_DIGEST_SIZE];
            char    mac_hex[2*HMAC_SHA256_DIGEST_SIZE + 1];
            hmac_sha256(PSK, sizeof(PSK), nonce, nonce_len, mac);
            hex_encode(mac, sizeof(mac), mac_hex);

            char resp[128];
            snprintf(resp, sizeof(resp), "RESP %s\r\n", mac_hex);
            UART_Print(resp);
        } else {
            UART_Print("ERR bad nonce (expected hex)\r\n");
        }
    } else if (strncmp(line, "VIOLATE", 7) == 0) {
        UART_Print("[UART] arming deliberate MPU violation on Untrusted task...\r\n");
        g_violate_requested = 1;
    } else if (len > 0) {
        UART_Print("ERR unknown command (try: AUTH <hex>, VIOLATE)\r\n");
    }
}

void vTask_LED(void *pvParameters){
    (void)pvParameters;
    char msg[64];
    for(;;){
        HAL_GPIO_TogglePin(GPIOA,GPIO_PIN_5);
        Security_CheckCanaries();
        Security_Heartbeat(SECURITY_TASK_LED);
        Security_KickIfHealthy();
        snprintf(msg,sizeof(msg),"[LED] tick=%lu\r\n",(unsigned long)xTaskGetTickCount());
        UART_Print(msg);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void vTask_UART(void *pvParameters){
    (void)pvParameters;
    char     msg[256];
    char     line[96];
    size_t   line_pos = 0;
    uint8_t  rx_byte;
    float    temperature=0.0f;
    TickType_t last_report = xTaskGetTickCount();

    for(;;){
        /* Non-blocking-ish poll: short timeout keeps this task responsive
         * to both incoming commands and its own periodic report. */
        if (HAL_UART_Receive(&huart2, &rx_byte, 1, pdMS_TO_TICKS(50)) == HAL_OK) {
            if (rx_byte == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                handle_line(line);
                line_pos = 0;
            } else if (rx_byte != '\r') {
                line[line_pos++] = (char)rx_byte;
            }
        }

        xQueueReceive(xSensorQueue,&temperature,0);
        Security_Heartbeat(SECURITY_TASK_UART);

        if (xTaskGetTickCount() - last_report >= pdMS_TO_TICKS(1000)) {
            snprintf(msg,sizeof(msg),"=== Report @%lu ms === Tasks:%u Heap:%u Temp:%.1fC\r\n",
                (unsigned long)xTaskGetTickCount(),
                (unsigned)uxTaskGetNumberOfTasks(),
                (unsigned)xPortGetFreeHeapSize(),
                temperature);
            UART_Print(msg);
            last_report = xTaskGetTickCount();
        }
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
        Security_Heartbeat(SECURITY_TASK_SENSOR);
        /* Must stay well under the IWDG's ~1.6s window (security.c) -- at
         * the previous 2000ms period, this task's own heartbeat bit could
         * never be set inside the same window as LED's and UART's, so
         * Security_KickIfHealthy() could never see SECURITY_TASK_ALL and
         * the watchdog reset the board on a fixed, unavoidable cadence
         * regardless of whether anything was actually hung. */
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void vTask_Untrusted(void *pvParameters){
    (void)pvParameters;
    /* This buffer lives inside the MPU region this task was granted in
     * main.c (xUntrustedTaskParameters) -- normal writes here always
     * succeed regardless of privilege level. */
    volatile uint8_t *scratch = (volatile uint8_t *)pvParameters;

    for(;;){
        for (int i = 0; i < 16; i++) {
            scratch[i] = (uint8_t)(scratch[i] + 1); /* harmless, in-bounds */
        }

        if (g_violate_requested) {
            g_violate_requested = 0;
            /* g_secure_secret is NOT part of this task's granted regions:
             * on real hardware this write is trapped by the MPU and lands
             * in MemManage_Handler() (fault_handlers.c) instead of
             * silently corrupting another task's memory. */
            g_secure_secret = 0xBADBADBA;
        }

        vTaskDelay(pdMS_TO_TICKS(300));
    }
}
