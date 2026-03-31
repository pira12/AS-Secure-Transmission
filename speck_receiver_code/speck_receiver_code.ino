#include <RH_ASK.h>
#include <SPI.h>

// SPECK-64/128 receiver

RH_ASK driver(2000, 11, 12);

#define SPECK_ROUNDS 27
#define ROR(x,r) ((x >> r) | (x << (32 - r)))
#define ROL(x,r) ((x << r) | (x >> (32 - r)))

// Must match transmitter key exactly
const uint32_t raw_key[4] = {0x03020100, 0x07060504,
                              0x0B0A0908, 0x0F0E0D0C};

uint32_t round_keys[SPECK_ROUNDS];

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

// Decrypt one 64-bit block — inverse of speck64_encrypt
void speck64_decrypt(uint32_t *x, uint32_t *y) {
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        *y = ROR(*x ^ *y, 3);
        *x = ROL((*x ^ round_keys[i]) - *y, 8);
    }
}

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK — listening...");
    speck_key_schedule(raw_key);
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);

    if (driver.recv(buf, &buflen)) {
        if (buflen < 8) {
            Serial.println("Packet too short, skipping");
            return;
        }

        uint32_t x, y;
        memcpy(&x, buf,     4);
        memcpy(&y, buf + 4, 4);

        unsigned long t_start = micros();
        speck64_decrypt(&x, &y);
        unsigned long t_dec = micros() - t_start;

        memcpy(buf,     &x, 4);
        memcpy(buf + 4, &y, 4);
        buf[8] = '\0';

        Serial.print("Received: ");
        Serial.println((char*)buf);
        Serial.print("Decrypt time (us): ");
        Serial.println(t_dec);
    }
}
