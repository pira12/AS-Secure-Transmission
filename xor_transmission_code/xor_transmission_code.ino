#include <RH_ASK.h>
#include <SPI.h>

// XOR stream cipher transmitter
// Uses a repeating 16-byte key — trivially breakable (same key = same ciphertext),
// included as a weak-crypto baseline for comparison with AES and ChaCha20.

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

// 16-byte repeating XOR key — must match receiver exactly
const uint8_t key[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                       0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t KEY_LEN = sizeof(key);

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
}

void loop() {
    const char* msg = "Hello SNE XOR!";
    uint8_t len = strlen(msg);
    uint8_t buf[64];
    memcpy(buf, msg, len);

    // XOR encrypt with repeating key
    unsigned long t_start = micros();
    for (uint8_t i = 0; i < len; i++)
        buf[i] ^= key[i % KEY_LEN];
    unsigned long t_enc = micros() - t_start;

    driver.send(buf, len);
    driver.waitPacketSent();

    Serial.print("Sent (plaintext): ");
    Serial.println(msg);
    Serial.print("Ciphertext (hex): ");
    for (uint8_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
    Serial.print("Encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}
