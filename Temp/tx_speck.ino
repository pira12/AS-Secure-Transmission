/*
 * TX — SPECK-64/128 (64-bit block, 128-bit key)
 * Reference implementation — pure C, no library needed.
 * SPECK is NSA-designed for constrained hardware; tiny footprint.
 *
 * Protocol: TEST,SPECK,<size>,ENC_US:<t>,ITER:<n>
 *
 * Block size: 8 bytes (64-bit). We send exactly 8 bytes per packet.
 * Key: 128 bits = 4 x uint32_t words.
 *
 * SPECK64/128 reference: https://eprint.iacr.org/2013/404.pdf
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         8   // SPECK-64 block size

// SPECK 64/128 constants
#define SPECK_ROUNDS 27
#define ROR(x,r) ((x >> r) | (x << (32 - r)))
#define ROL(x,r) ((x << r) | (x >> (32 - r)))

// Key: 128 bits = 4 x 32-bit words
// Using same logical key material as AES sketch for fairness
const uint32_t raw_key[4] = { 0x03020100, 0x07060504,
                               0x0B0A0908, 0x0F0E0D0C };

uint32_t round_keys[SPECK_ROUNDS];

static uint32_t iter = 0;

// Plaintext: first 8 bytes of the same message
const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o'
};

// Key schedule
void speck_key_schedule(const uint32_t k[4]) {
    uint32_t A = k[0], B = k[1], C = k[2], D = k[3];
    round_keys[0] = A;
    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        // Rotate B through the schedule
        B = (ROR(B, 8) + A) ^ i;
        A = ROL(A, 3) ^ B;
        round_keys[i + 1] = A;
        // Cycle key words: shift C,D through
        if (i % 3 == 0)      { uint32_t t = B; B = C; C = t; }
        else if (i % 3 == 1) { uint32_t t = B; B = D; D = t; }
    }
}

// Encrypt one 64-bit block
void speck64_encrypt(uint32_t *x, uint32_t *y) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x = (ROR(*x, 8) + *y) ^ round_keys[i];
        *y = ROL(*y, 3) ^ *x;
    }
}

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    speck_key_schedule(raw_key);
    Serial.println("TX_READY,SPECK");
}

void loop() {
    uint8_t buf[MSG_SIZE];
    memcpy(buf, plaintext, MSG_SIZE);

    // Treat buffer as two 32-bit words (little-endian)
    uint32_t x, y;
    memcpy(&x, buf,     4);
    memcpy(&y, buf + 4, 4);

    unsigned long t_start = micros();
    speck64_encrypt(&x, &y);
    unsigned long enc_us = micros() - t_start;

    memcpy(buf,     &x, 4);
    memcpy(buf + 4, &y, 4);

    driver.send(buf, MSG_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,SPECK,");
    Serial.print(MSG_SIZE);
    Serial.print(",ENC_US:");
    Serial.print(enc_us);
    Serial.print(",ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}
