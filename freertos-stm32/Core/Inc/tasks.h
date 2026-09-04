#ifndef TASKS_H
#define TASKS_H

void vTask_LED(void *pvParameters);
void vTask_UART(void *pvParameters);
void vTask_Sensor(void *pvParameters);

/* Unprivileged task created via xTaskCreateRestricted() (see main.c) with
 * its own private MPU-mapped RAM region. Normally only touches that
 * region; on the "VIOLATE" UART command it deliberately writes outside of
 * it to demonstrate the MPU trapping the access (see fault_handlers.c). */
void vTask_Untrusted(void *pvParameters);

/* Set by vTask_UART when it parses a "VIOLATE" command; read (and cleared)
 * by vTask_Untrusted on its next iteration. Byte [0] of a dedicated,
 * 32-byte-aligned buffer (not a bare uint8_t) so it can be granted to the
 * unprivileged Untrusted task as its own MPU region in main.c -- see the
 * comment above its definition in tasks.c. */
extern uint8_t g_violate_signal[32];
#define g_violate_requested (g_violate_signal[0])

/* Deliberately outside of any task's MPU region -- the demo target for the
 * illegal write performed by vTask_Untrusted. */
extern volatile uint32_t g_secure_secret;

#endif
