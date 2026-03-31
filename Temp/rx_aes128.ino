/*
 * RX — AES-128 ECB Single Block
 * Protocol: RECV,AES128,<size>,DEC_US:<t>,OK:<1|0>,ITER:<n>
 */

#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

#define MSG_SIZE 16

uint8_t key[16] = { 0x00,0x01,0x10,0x03,0x04,0x05,0x06,0x07,
                    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };

static uint32_t recv_count = 0;

const uint8_t expected[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("RX_READY,AES128");
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);

    if (driver.recv(buf, &buflen)) {
        unsigned long t_start = micros();
        aes128_dec_single(key, buf);   // in-place decryption
        unsigned long dec_us = micros() - t_start;

        int ok = (buflen >= MSG_SIZE && memcmp(buf, expected, MSG_SIZE) == 0) ? 1 : 0;

        Serial.print("RECV,AES128,");
        Serial.print(buflen);
        Serial.print(",DEC_US:");
        Serial.print(dec_us);
        Serial.print(",OK:");
        Serial.print(ok);
        Serial.print(",ITER:");
        Serial.println(recv_count++);
    }
}
