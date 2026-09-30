#include "link.h"
#include "bsp.h"
#include <string.h>

uint16_t crc16_ccitt(uint16_t crc, const uint8_t *p, size_t n)
{
    while (n--) {
        crc ^= (uint16_t)(*p++) << 8;
        for (int i = 0; i < 8; i++)
            crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
    }
    return crc;
}

/* In-place COBS decode; returns decoded length or -1 on malformed input. */
static int cobs_decode(uint8_t *buf, size_t len)
{
    size_t r = 0, w = 0;

    while (r < len) {
        uint8_t code = buf[r++];
        if (code == 0 || r + code - 1u > len)
            return -1;
        for (uint8_t i = 1; i < code; i++)
            buf[w++] = buf[r++];
        if (code != 0xFF && r < len)
            buf[w++] = 0;
    }
    return (int)w;
}

static void note_bad(link_rx_t *rx)
{
    rx->frames_bad++;
    rx->last_bad_cyc = link_timestamp();
    rx->last_bad_len = (uint32_t)rx->len;
}

static void rx_frame_done(link_rx_t *rx, link_handler_t h, void *ctx)
{
    int n;

    if (rx->len == 0)
        return;
    if (rx->overlong) {
        note_bad(rx);
        rx->overlong_frames++;
        return;
    }
    if ((n = cobs_decode(rx->buf, rx->len)) < 0) {
        note_bad(rx);
        rx->bad_cobs++;
        return;
    }
    if (n < 3) {
        note_bad(rx);
        rx->runt++;
        return;
    }
    uint16_t crc = (uint16_t)(rx->buf[n - 2] | (rx->buf[n - 1] << 8));
    if (crc16_ccitt(0xFFFF, rx->buf, (size_t)n - 2u) != crc) {
        note_bad(rx);
        rx->bad_crc++;
        return;
    }
    rx->frames_ok++;
    h(rx->buf[0], rx->buf + 1, (size_t)n - 3u, ctx);
}

void link_rx_feed(link_rx_t *rx, const uint8_t *data, size_t n, link_handler_t h, void *ctx)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];
        if (b == 0) {
            rx_frame_done(rx, h, ctx);
            rx->len = 0;
            rx->overlong = 0;
        } else if (rx->len < sizeof rx->buf) {
            rx->buf[rx->len++] = b;
        } else {
            rx->overlong = 1;
        }
    }
}

size_t link_encode(uint8_t *dst, size_t cap, uint8_t type, const void *payload, size_t len)
{
    /* Worst case: 1 code byte per 254 data bytes, plus header, crc, delimiter. */
    size_t raw = 1u + len + 2u;
    if (cap < raw + raw / 254u + 2u)
        return 0;

    uint16_t crc = crc16_ccitt(0xFFFF, &type, 1);
    crc = crc16_ccitt(crc, payload, len);
    uint8_t tail[2] = { (uint8_t)crc, (uint8_t)(crc >> 8) };

    size_t w = 1, code_pos = 0;
    uint8_t code = 1;
    for (size_t i = 0; i < raw; i++) {
        uint8_t b = (i == 0) ? type : (i <= len) ? ((const uint8_t *)payload)[i - 1] : tail[i - 1 - len];
        if (b == 0) {
            dst[code_pos] = code;
            code_pos = w++;
            code = 1;
        } else {
            dst[w++] = b;
            if (++code == 0xFF) {
                dst[code_pos] = code;
                code_pos = w++;
                code = 1;
            }
        }
    }
    dst[code_pos] = code;
    dst[w++] = 0;
    return w;
}

void link_send(uint8_t type, const void *payload, size_t len)
{
    static uint8_t buf[160];
    size_t n = link_encode(buf, sizeof buf, type, payload, len);
    bsp_uart_send(buf, n);
}
