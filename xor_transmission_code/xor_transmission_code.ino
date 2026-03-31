#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

// Unencrypted header magic — used by RX to filter foreign packets
const uint8_t HEADER_MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

// Encrypted payload magic — embedded in plaintext, verified after decryption
const uint8_t PAYLOAD_MAGIC[] = {0xCA, 0xFE, 0xBA, 0xBE};

const uint8_t key[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                       0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t KEY_LEN = sizeof(key);

#define MAX_CHUNK_PER_PACKET 54

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
}

void loop() {
    const char* msg = "HELLO SNE THIS IS AN EVEN SUPER LONG LONGER LONGER MESSAGE NOW WITH MORE THAN 80 bytes! SO FOR THIS TEST WE ARE USING MORE THAN 2 PACKETS.";

    // Build plaintext: payload magic + message
    uint8_t plaintext[192];
    memcpy(plaintext, PAYLOAD_MAGIC, 4);
    memcpy(plaintext + 4, msg, strlen(msg));
    uint8_t plain_len = 4 + strlen(msg);

    // XOR encrypt in place
    uint8_t encrypted[192];
    unsigned long t_start = micros();
    for (uint8_t i = 0; i < plain_len; i++)
        encrypted[i] = plaintext[i] ^ key[i % KEY_LEN];
    unsigned long t_enc = micros() - t_start;

    // Print plaintext blocks
    Serial.println("--- Plaintext blocks ---");
    for (uint8_t i = 0; i < plain_len; i += 16) {
        uint8_t block_len = min((uint8_t)16, (uint8_t)(plain_len - i));
        Serial.print("  Block ["); Serial.print(i / 16); Serial.print("]: ");
        for (uint8_t j = 0; j < block_len; j++) {
            char c = (char)plaintext[i + j];
            Serial.print(c >= 32 && c < 127 ? c : '.');
        }
        Serial.println();
    }

    // Print encrypted blocks
    Serial.println("--- Encrypted blocks (hex) ---");
    for (uint8_t i = 0; i < plain_len; i += 16) {
        uint8_t block_len = min((uint8_t)16, (uint8_t)(plain_len - i));
        Serial.print("  Block ["); Serial.print(i / 16); Serial.print("]: ");
        for (uint8_t j = 0; j < block_len; j++) {
            if (encrypted[i + j] < 0x10) Serial.print("0");
            Serial.print(encrypted[i + j], HEX);
            Serial.print(" ");
        }
        Serial.println();
    }

    // Split into packets
    uint8_t total_packets = (plain_len + MAX_CHUNK_PER_PACKET - 1) / MAX_CHUNK_PER_PACKET;

    Serial.print("Total bytes: "); Serial.println(plain_len);
    Serial.print("Splitting into "); Serial.print(total_packets); Serial.println(" packets");

    for (uint8_t pkt = 0; pkt < total_packets; pkt++) {
        uint8_t offset = pkt * MAX_CHUNK_PER_PACKET;
        uint8_t chunk_len = min((uint8_t)MAX_CHUNK_PER_PACKET, (uint8_t)(plain_len - offset));

        // Packet format: [HEADER_MAGIC (4)] [pkt_index (1)] [total_packets (1)] [encrypted chunk]
        uint8_t packet[60];
        memcpy(packet, HEADER_MAGIC, 4);
        packet[4] = pkt;
        packet[5] = total_packets;
        memcpy(packet + 6, encrypted + offset, chunk_len);
        uint8_t packet_len = 6 + chunk_len;

        Serial.print("  Sending packet "); Serial.print(pkt + 1);
        Serial.print("/"); Serial.print(total_packets);
        Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes)");

        for (uint8_t r = 0; r < 3; r++) {
            driver.send(packet, packet_len);
            driver.waitPacketSent();
            delay(100);
        }
        delay(500);
    }

    Serial.print("Done. XOR encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}