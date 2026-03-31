#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

uint8_t key[] = {42,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t iv[]  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // static, same on both sides

const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

// Max ciphertext per packet: 60 bytes total - 2 bytes header = 58 bytes
// Round down to block boundary: 48 bytes (3 blocks) per packet
#define MAX_CIPHER_PER_PACKET 48

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
    const char* msg = "HELLO SNE THIS IS AN EVEN SUPER LONG LONGER LONGER MESSAGE!";

    // Build plaintext: magic + message
    uint8_t plaintext[128];
    memcpy(plaintext, MAGIC, 4);
    memcpy(plaintext + 4, msg, strlen(msg));
    uint8_t plain_len = 4 + strlen(msg);

    // Pad to block boundary
    uint8_t padded[128];
    uint8_t padded_len = pkcs7_pad(padded, (char*)plaintext, plain_len);

    Serial.println("--- Plaintext blocks ---");
    for (uint8_t i = 0; i < padded_len; i += 16) {
        Serial.print("  Block "); Serial.print(i/16); Serial.print(": ");
        for (uint8_t j = 0; j < 16; j++) {
            char c = (char)padded[i+j];
            Serial.print(c >= 32 && c < 127 ? c : '.');
        }
        Serial.println();
    }

    // CBC encrypt entire padded plaintext at once
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

    // Split ciphertext into packets
    uint8_t total_packets = (padded_len + MAX_CIPHER_PER_PACKET - 1) / MAX_CIPHER_PER_PACKET;

    Serial.print("Total ciphertext bytes: "); Serial.println(padded_len);
    Serial.print("Splitting into "); Serial.print(total_packets); Serial.println(" packets");

    for (uint8_t pkt = 0; pkt < total_packets; pkt++) {
        uint8_t offset = pkt * MAX_CIPHER_PER_PACKET;
        uint8_t chunk_len = min((uint8_t)MAX_CIPHER_PER_PACKET, (uint8_t)(padded_len - offset));

        // Packet format: [pkt_index (1)] [total_packets (1)] [ciphertext chunk]
        uint8_t packet[60];
        packet[0] = pkt;
        packet[1] = total_packets;
        memcpy(packet + 2, padded + offset, chunk_len);
        uint8_t packet_len = 2 + chunk_len;

        Serial.print("  Sending packet "); Serial.print(pkt + 1);
        Serial.print("/"); Serial.print(total_packets);
        Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes ciphertext)");

        for (uint8_t r = 0; r < 3; r++) {
            driver.send(packet, packet_len);
            driver.waitPacketSent();
            delay(100);
        }
        delay(500); // gap between packets so RX can process
    }

    Serial.print("Done. Encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}