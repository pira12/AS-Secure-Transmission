#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

uint8_t key[] = {42,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t iv[]  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // must match TX exactly

const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

#define MAX_CIPHER_PER_PACKET 48
#define MAX_TOTAL_CIPHER 128

// Reassembly buffer — holds ciphertext chunks as they arrive
uint8_t reassembly_buf[MAX_TOTAL_CIPHER];
bool    received_packets[8];   // tracks which packet indices arrived
uint8_t expected_total = 0;
uint8_t packets_received = 0;

void reset_reassembly() {
    memset(reassembly_buf, 0, sizeof(reassembly_buf));
    memset(received_packets, 0, sizeof(received_packets));
    expected_total = 0;
    packets_received = 0;
}

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
    reset_reassembly();
}

void loop() {
    uint8_t packet[64];
    uint8_t packet_len = sizeof(packet);  // reset every loop

    if (driver.recv(packet, &packet_len)) {

        // Need at least header (2 bytes) + 1 block (16 bytes)
        if (packet_len < 18) {
            Serial.println("Too short, skipping");
            return;
        }

        uint8_t pkt_index    = packet[0];
        uint8_t total_pkts   = packet[1];
        uint8_t* chunk       = packet + 2;
        uint8_t  chunk_len   = packet_len - 2;

        Serial.print("Got packet "); Serial.print(pkt_index + 1);
        Serial.print("/"); Serial.print(total_pkts);
        Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes)");

        // Sanity checks
        if (pkt_index >= 8 || total_pkts == 0 || total_pkts > 8) {
            Serial.println("Invalid header, skipping");
            return;
        }

        // If this is a new message (different total or fresh start), reset
        if (expected_total != 0 && total_pkts != expected_total) {
            Serial.println("New message detected, resetting reassembly");
            reset_reassembly();
        }

        expected_total = total_pkts;

        // Store chunk if not already received (deduplication handles 3x retransmit)
        if (!received_packets[pkt_index]) {
            memcpy(reassembly_buf + (pkt_index * MAX_CIPHER_PER_PACKET), chunk, chunk_len);
            received_packets[pkt_index] = true;
            packets_received++;
        } else {
            Serial.println("Duplicate packet, ignoring");
            return;
        }

        // Check if we have all packets
        if (packets_received == expected_total) {
            Serial.println("All packets received — decrypting...");

            uint8_t total_cipher = (expected_total - 1) * MAX_CIPHER_PER_PACKET + chunk_len;

            uint8_t iv_copy[16];
            memcpy(iv_copy, iv, 16);

            uint8_t decrypted[MAX_TOTAL_CIPHER];

            unsigned long t_start = micros();
            for (uint8_t i = 0; i < total_cipher; i += 16) {
                uint8_t prev_block[16];
                memcpy(prev_block, (i == 0) ? iv_copy : &reassembly_buf[i - 16], 16);
                memcpy(&decrypted[i], &reassembly_buf[i], 16);
                aes128_dec_single(key, &decrypted[i]);
                for (uint8_t j = 0; j < 16; j++)
                    decrypted[i + j] ^= prev_block[j];
            }
            unsigned long t_dec = micros() - t_start;

            // Check magic
            if (memcmp(decrypted, MAGIC, 4) != 0) {
                Serial.println("Magic mismatch — wrong key or corrupted");
                reset_reassembly();
                return;
            }

            pkcs7_unpad(decrypted, &total_cipher);
            Serial.print("Decrypted: ");
            Serial.println((char*)(decrypted + 4));
            Serial.print("Decrypt time (us): ");
            Serial.println(t_dec);

            reset_reassembly();
        } else {
            Serial.print("Waiting for ");
            Serial.print(expected_total - packets_received);
            Serial.println(" more packets...");
        }
    }
}