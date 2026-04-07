/*
 * TX — AES-128 CBC (manual CBC over AESLib single-block primitives)
 * Protocol: TEST,AES128CBC,<size>,ENC_US:<t>,ITER:<n>
 *
 * CBC mode: each plaintext block is XOR'd with the previous ciphertext block
 * (or IV for the first block) before encryption. The IV is prepended to the
 * transmission so the receiver can decrypt without shared state.
 *
 * Transmitted packet layout (32 bytes):
 *   [0..15]  IV  (random-ish, seeded from iter + analog noise)
 *   [16..31] Ciphertext block
 */

#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16
#define PKT_SIZE         32   // IV (16) + ciphertext (16)

uint8_t key[16] = {
    0x00,0x01,0x10,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
};

static uint32_t iter = 0;

const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

// Generate a low-quality but functional IV from analog noise + iteration
// counter. Good enough for bench testing; replace with a TRNG for production.
void makeIV(uint8_t *iv, uint32_t iteration) {
    for (uint8_t i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(analogRead(A0) ^ (iteration >> (i % 4) * 8) ^ (i * 0x5A));
    }
}

void setup() {
    Serial.begin(9600);
    while (!Serial);
    randomSeed(analogRead(A0));
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("TX_READY,AES128CBC");
}

void loop() {
    uint8_t pkt[PKT_SIZE];
    uint8_t *iv  = pkt;          // first 16 bytes = IV
    uint8_t *ct  = pkt + 16;     // next  16 bytes = ciphertext

    // 1. Generate IV
    makeIV(iv, iter);

    // 2. CBC encrypt (one 16-byte block):
    //    ct = AES_ECB_Enc(plaintext XOR iv)
    uint8_t buf[MSG_SIZE];
    for (uint8_t i = 0; i < MSG_SIZE; i++)
        buf[i] = plaintext[i] ^ iv[i];

    unsigned long t_start = micros();
    aes128_enc_single(key, buf);
    unsigned long enc_us = micros() - t_start;

    memcpy(ct, buf, MSG_SIZE);

    driver.send(pkt, PKT_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,AES128CBC,");
    Serial.print(PKT_SIZE);
    Serial.print(",ENC_US:");
    Serial.print(enc_us);
    Serial.print(",ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}