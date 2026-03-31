#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

uint8_t key[] = {42,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t iv[]  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // static, same on both sides

const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

uint8_t pkcs7_pad(uint8_t* buf, const char* msg, uint8_t msglen) {
    uint8_t padded_len = ((msglen / 16) + 1) * 16;
    memcpy(buf, msg, msglen);
    uint8_t pad_byte = padded_len - msglen;
    for (uint8_t i = msglen; i < padded_len; i++)
        buf[i] = pad_byte;
    return padded_len;
}

void print_block(uint8_t* block, uint8_t block_num, bool as_text) {
    Serial.print("  Block ");
    Serial.print(block_num);
    Serial.print(": ");
    if (as_text) {
        // Print as text, replacing non-printable chars with '.'
        for (uint8_t i = 0; i < 16; i++) {
            char c = (char)block[i];
            Serial.print(c >= 32 && c < 127 ? c : '.');
        }
    } else {
        // Print as hex
        for (uint8_t i = 0; i < 16; i++) {
            if (block[i] < 0x10) Serial.print("0");
            Serial.print(block[i], HEX);
            Serial.print(" ");
        }
    }
    Serial.println();
}

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
}

void loop() {
    const char* msg = "HELLO SNE THIS IS A LONGER MESSAGE!";
    uint8_t plaintext[64];
    memcpy(plaintext, MAGIC, 4);
    memcpy(plaintext + 4, msg, strlen(msg));
    uint8_t plain_len = 4 + strlen(msg);

    uint8_t padded[64];
    uint8_t padded_len = pkcs7_pad(padded, (char*)plaintext, plain_len);

    // Print the plaintext blocks before encryption
    Serial.println("--- Plaintext blocks ---");
    Serial.print("Total length after padding: ");
    Serial.print(padded_len);
    Serial.println(" bytes");
    for (uint8_t i = 0; i < padded_len; i += 16)
        print_block(&padded[i], i / 16, true);

    // Use a copy so the static iv is never modified
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    // CBC encrypt
    unsigned long t_start = micros();
    for (uint8_t i = 0; i < padded_len; i += 16) {
        for (uint8_t j = 0; j < 16; j++)
            padded[i + j] ^= iv_copy[j];
        aes128_enc_single(key, &padded[i]);
        memcpy(iv_copy, &padded[i], 16);
    }
    unsigned long t_enc = micros() - t_start;

    // Print the ciphertext blocks after encryption
    Serial.println("--- Ciphertext blocks (hex) ---");
    for (uint8_t i = 0; i < padded_len; i += 16)
        print_block(&padded[i], i / 16, false);

    // Warn if message exceeds one RadioHead packet
    if (padded_len > 60) {
        Serial.println("WARNING: payload exceeds 60 bytes, truncating!");
        padded_len = 60;
    }

    for (uint8_t i = 0; i < 3; i++) {
        driver.send(padded, padded_len);
        driver.waitPacketSent();
        delay(100);
    }

    Serial.print("Sent (3x) | Encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}