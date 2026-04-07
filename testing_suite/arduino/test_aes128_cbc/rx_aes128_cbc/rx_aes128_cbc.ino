/*
 * RX — AES-128 CBC (manual CBC over AESLib single-block primitives)
 * Protocol: RECV,AES128CBC,<size>,DEC_US:<t>,OK:<1|0>,ITER:<n>
 *
 * Received packet layout (32 bytes):
 *   [0..15]  IV
 *   [16..31] Ciphertext block
 *
 * CBC decrypt (one block):
 *   plaintext = AES_ECB_Dec(ciphertext) XOR IV
 */

#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

#define MSG_SIZE 16
#define PKT_SIZE 32   // IV (16) + ciphertext (16)

uint8_t key[16] = {
    0x00,0x01,0x10,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
};

static uint32_t recv_count = 0;

const uint8_t expected[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("RX_READY,AES128CBC");
}

void loop() {
    uint8_t pkt[PKT_SIZE + 4];   // small headroom for RH framing
    uint8_t pktlen = sizeof(pkt);

    if (driver.recv(pkt, &pktlen)) {
        if (pktlen < PKT_SIZE) {
            Serial.println("ERR,SHORT_PKT");
            return;
        }

        uint8_t *iv = pkt;        // first 16 bytes
        uint8_t *ct = pkt + 16;   // next  16 bytes

        // 1. Copy ciphertext into working buffer
        uint8_t buf[MSG_SIZE];
        memcpy(buf, ct, MSG_SIZE);

        // 2. CBC decrypt:
        //    plaintext = AES_ECB_Dec(ciphertext) XOR IV
        unsigned long t_start = micros();
        aes128_dec_single(key, buf);
        for (uint8_t i = 0; i < MSG_SIZE; i++)
            buf[i] ^= iv[i];
        unsigned long dec_us = micros() - t_start;

        int ok = (memcmp(buf, expected, MSG_SIZE) == 0) ? 1 : 0;

        Serial.print("RECV,AES128CBC,");
        Serial.print(pktlen);
        Serial.print(",DEC_US:");
        Serial.print(dec_us);
        Serial.print(",OK:");
        Serial.print(ok);
        Serial.print(",ITER:");
        Serial.println(recv_count++);
    }
}