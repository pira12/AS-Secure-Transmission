/*
 * TX — AES-128 ECB (AESLib by DavyLandman)
 * Protocol: TEST,AES128,<size>,ENC_US:<t>,ITER:<n>
 *
 * NOTE: ECB mode — identical plaintext blocks produce identical ciphertext.
 * Included to show the ECB penguin problem vs CBC mode.
 *
 * Library: Arduino Library Manager → search "AESLib"
 */

#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16

uint8_t key[16] = {
    0x00,0x01,0x10,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
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
    Serial.println("TX_READY,AES128");
}

void loop() {
    uint8_t buf[MSG_SIZE];
    memcpy(buf, plaintext, MSG_SIZE);

    unsigned long t_start = micros();
    aes128_enc_single(key, buf);
    unsigned long enc_us = micros() - t_start;

    driver.send(buf, MSG_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,AES128,");
    Serial.print(MSG_SIZE);
    Serial.print(",ENC_US:");
    Serial.print(enc_us);
    Serial.print(",ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}
