/*
 * TX — XOR Cipher (Broken Crypto Baseline)
 * Static single-byte key XOR — trivially reversible.
 * Protocol: TEST,XOR,<size>,ENC_US:<t>,ITER:<n>
 *
 * PURPOSE: Show that XOR with a static key leaks structure.
 * If you send the same message twice, ciphertext is identical.
 * Key recovery: C1 XOR C2 = P1 XOR P2 (known-plaintext is trivial).
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16
#define XOR_KEY          0xAB  // static, single-byte — deliberately weak

static uint32_t iter = 0;

const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

void xor_encrypt(uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; i++)
        data[i] ^= XOR_KEY;
}

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("TX_READY,XOR");
}

void loop() {
    uint8_t buf[MSG_SIZE];
    memcpy(buf, plaintext, MSG_SIZE);

    unsigned long t_start = micros();
    xor_encrypt(buf, MSG_SIZE);
    unsigned long enc_us = micros() - t_start;

    driver.send(buf, MSG_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,XOR,");
    Serial.print(MSG_SIZE);
    Serial.print(",ENC_US:");
    Serial.print(enc_us);
    Serial.print(",ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}
