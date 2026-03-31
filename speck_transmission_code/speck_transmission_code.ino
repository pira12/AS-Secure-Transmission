#include <RH_ASK.h>
#include <SPI.h>

// SPECK-64/128 transmitter
// SPECK is an NSA-designed lightweight block cipher for constrained hardware.
// Block size: 64 bits (8 bytes). Key size: 128 bits (4 x uint32_t).
// No external library required — pure C implementation.
// Reference: https://eprint.iacr.org/2013/404.pdf

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

#define SPECK_ROUNDS 27
#define ROR(x,r) ((x >> r) | (x << (32 - r)))
#define ROL(x,r) ((x << r) | (x >> (32 - r)))

// 128-bit key (4 x 32-bit words) — must match receiver
const uint32_t raw_key[4] = {0x03020100, 0x07060504,
                              0x0B0A0908, 0x0F0E0D0C};

uint32_t round_keys[SPECK_ROUNDS];

// Expand 128-bit key into SPECK_ROUNDS round keys
void speck_key_schedule(const uint32_t k[4]) {
    uint32_t A = k[0], B = k[1], C = k[2], D = k[3];
    round_keys[0] = A;
    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        B = (ROR(B, 8) + A) ^ i;
        A = ROL(A, 3) ^ B;
        round_keys[i + 1] = A;
        if      (i % 3 == 0) { uint32_t t = B; B = C; C = t; }
        else if (i % 3 == 1) { uint32_t t = B; B = D; D = t; }
    }
}

// Encrypt one 64-bit block (two 32-bit words)
void speck64_encrypt(uint32_t *x, uint32_t *y) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x = (ROR(*x, 8) + *y) ^ round_keys[i];
        *y = ROL(*y, 3) ^ *x;
    }
}

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
    speck_key_schedule(raw_key);
}

void loop() {
    // SPECK-64 block = 8 bytes
    const char* msg = "HELLOSPK";
    uint8_t buf[8];
    memcpy(buf, msg, 8);

    // Treat the 8-byte block as two 32-bit words (little-endian)
    uint32_t x, y;
    memcpy(&x, buf,     4);
    memcpy(&y, buf + 4, 4);

    unsigned long t_start = micros();
    speck64_encrypt(&x, &y);
    unsigned long t_enc = micros() - t_start;

    memcpy(buf,     &x, 4);
    memcpy(buf + 4, &y, 4);

    driver.send(buf, 8);
    driver.waitPacketSent();

    Serial.print("Sent (plaintext): ");
    Serial.println(msg);
    Serial.print("Ciphertext (hex): ");
    for (uint8_t i = 0; i < 8; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
    Serial.print("Encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}
