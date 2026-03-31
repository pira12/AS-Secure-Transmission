#include <RH_ASK.h>
#include <SPI.h>

// XOR stream cipher receiver

RH_ASK driver(2000, 11, 12);

// Must match transmitter key exactly
const uint8_t key[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                       0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t KEY_LEN = sizeof(key);

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK — listening...");
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);

    if (driver.recv(buf, &buflen)) {
        // XOR is its own inverse — decrypt == encrypt
        unsigned long t_start = micros();
        for (uint8_t i = 0; i < buflen; i++)
            buf[i] ^= key[i % KEY_LEN];
        unsigned long t_dec = micros() - t_start;

        buf[buflen] = '\0';
        Serial.print("Received: ");
        Serial.println((char*)buf);
        Serial.print("Decrypt time (us): ");
        Serial.println(t_dec);
    }
}
