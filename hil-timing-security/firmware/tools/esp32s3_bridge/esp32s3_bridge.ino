/*
 * ESP32-S3 transparent UART <-> USB bridge for the SARE HIL link.
 *
 * Replaces the ST-LINK virtual COM port (which lost bytes, see paper Sec. III)
 * between the STM32 (USART1, 921600 8N1) and the host PC. The bytes are
 * forwarded unchanged in both directions; the PC side is the S3's native USB
 * Serial/JTAG CDC (no baud rate). Large buffers absorb host scheduling pauses.
 *
 * Wiring: GPIO43 "TX" -> STM32 D2 / PA10 (RX)
 *         GPIO44 "RX" <- STM32 D8 / PA9  (TX)
 *         GND         -- STM32 GND
 * Build:  arduino-cli compile -b esp32:esp32:esp32s3:CDCOnBoot=cdc,USBMode=default
 */
#define LINK_BAUD 921600
#define PIN_TX    43    /* board pin "TX" */
#define PIN_RX    44    /* board pin "RX" */

static uint8_t buf[4096];

void setup() {
  Serial.setRxBufferSize(16384);        // USB -> STM32 (sensor stream, E3 flooding)
  Serial.enableReboot(false);           // DTR/RTS must never restart the bridge
  Serial.begin();
  Serial1.setRxBufferSize(32768);       // absorbs >300 ms of full-rate traffic
  Serial1.begin(LINK_BAUD, SERIAL_8N1, PIN_RX, PIN_TX);
}

void loop() {
  size_t n = Serial1.available();
  if (n) {
    n = Serial1.readBytes(buf, n < sizeof buf ? n : sizeof buf);
    Serial.write(buf, n);
  }
  n = Serial.available();
  if (n) {
    n = Serial.readBytes(buf, n < sizeof buf ? n : sizeof buf);
    Serial1.write(buf, n);
  }
}
