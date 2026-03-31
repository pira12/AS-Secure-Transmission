/*
 * RX — XOR Cipher
 * Protocol: RECV,XOR,<size>,DEC_US:<t>,OK:<1|0>,ITER:<n>
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define MSG_SIZE 16
#define XOR_KEY  0xAB

static uint32_t recv_count = 0;

const uint8_t expected[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

void xor_decrypt(uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; i++)
        data[i] ^= XOR_KEY;  // XOR is its own inverse
}

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("RX_READY,XOR");
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);

    if (driver.recv(buf, &buflen)) {
        unsigned long t_start = micros();
        xor_decrypt(buf, MSG_SIZE);
        unsigned long dec_us = micros() - t_start;

        int ok = (buflen >= MSG_SIZE && memcmp(buf, expected, MSG_SIZE) == 0) ? 1 : 0;

        Serial.print("RECV,XOR,");
        Serial.print(buflen);
        Serial.print(",DEC_US:");
        Serial.print(dec_us);
        Serial.print(",OK:");
        Serial.print(ok);
        Serial.print(",ITER:");
        Serial.println(recv_count++);
    }
}
