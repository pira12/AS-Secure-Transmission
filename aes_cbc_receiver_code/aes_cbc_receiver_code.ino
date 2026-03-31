#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

uint8_t key[] = {42,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t iv[]  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // must match TX exactly

const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

void pkcs7_unpad(uint8_t* buf, uint8_t* len) {
    uint8_t pad_byte = buf[*len - 1];
    if (pad_byte < 1 || pad_byte > 16) return;
    *len -= pad_byte;
    buf[*len] = '\0';
}

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK — listening...");
}

void loop() {
    uint8_t packet[64];
    uint8_t packet_len = sizeof(packet);  // reset every loop

    if (driver.recv(packet, &packet_len)) {
        Serial.print("Raw packet received, length: ");
        Serial.println(packet_len);  // debug: print ALL received packets

        if (packet_len < 16) {
            Serial.println("Too short, skipping");
            return;
        }

        // Ciphertext is the whole packet now — no IV prefix to strip
        uint8_t cipher_len = packet_len;
        uint8_t ciphertext[64];
        memcpy(ciphertext, packet, cipher_len);

        uint8_t decrypted[64];

        // Use a copy so static iv is never modified
        uint8_t iv_copy[16];
        memcpy(iv_copy, iv, 16);

        unsigned long t_start = micros();
        for (uint8_t i = 0; i < cipher_len; i += 16) {
            uint8_t prev_block[16];
            memcpy(prev_block, (i == 0) ? iv_copy : &ciphertext[i - 16], 16);
            memcpy(&decrypted[i], &ciphertext[i], 16);
            aes128_dec_single(key, &decrypted[i]);
            for (uint8_t j = 0; j < 16; j++)
                decrypted[i + j] ^= prev_block[j];
        }
        unsigned long t_dec = micros() - t_start;

        // Check magic bytes — if wrong key or wrong team, magic won't match
        if (memcmp(decrypted, MAGIC, 4) != 0) {
            Serial.println("Magic mismatch — not our packet, ignoring");
            return;
        }

        pkcs7_unpad(decrypted, &cipher_len);

        Serial.print("Decrypted: ");
        Serial.println((char*)(decrypted + 4));  // skip magic bytes
        Serial.print("Decrypt time (us): ");
        Serial.println(t_dec);
    }
}