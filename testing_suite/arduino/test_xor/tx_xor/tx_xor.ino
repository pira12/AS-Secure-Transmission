/*
 * TX — XOR cipher (static repeating key — deliberately weak baseline)
 * Protocol: TEST,XOR,<size>,ENC_US:<t>,ITER:<n>
 *
 * Demonstrates broken crypto: identical plaintext always produces
 * identical ciphertext. Key recovery needs only one known-plaintext pair.
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16

// 16-byte repeating key — must match RX
const uint8_t key[MSG_SIZE] = {
    0xAB,0xCD,0xEF,0x12, 0x34,0x56,0x78,0x9A,
    0xBC,0xDE,0xF0,0x11, 0x22,0x33,0x44,0x55
};

static uint32_t iter = 0;

const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

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
    for (uint8_t i = 0; i < MSG_SIZE; i++)
        buf[i] ^= key[i];
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
