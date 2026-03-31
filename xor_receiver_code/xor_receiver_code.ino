#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

const uint8_t HEADER_MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};
const uint8_t PAYLOAD_MAGIC[] = {0xCA, 0xFE, 0xBA, 0xBE};

const uint8_t key[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                       0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t KEY_LEN = sizeof(key);

#define MAX_CHUNK_PER_PACKET 54
#define MAX_TOTAL_PLAIN 192

uint8_t  reassembly_buf[MAX_TOTAL_PLAIN];
bool     received_packets[8];
uint8_t  expected_total = 0;
uint8_t  packets_received = 0;

void reset_reassembly() {
    memset(reassembly_buf, 0, sizeof(reassembly_buf));
    memset(received_packets, 0, sizeof(received_packets));
    expected_total = 0;
    packets_received = 0;
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
    uint8_t packet_len = sizeof(packet);

    if (driver.recv(packet, &packet_len)) {

        // Filter foreign packets using unencrypted header magic
        if (packet_len < 22 || memcmp(packet, HEADER_MAGIC, 4) != 0) {
            Serial.println("Not our packet, ignoring");
            return;
        }

        uint8_t pkt_index  = packet[4];
        uint8_t total_pkts = packet[5];
        uint8_t* chunk     = packet + 6;
        uint8_t  chunk_len = packet_len - 6;

        Serial.print("Got packet "); Serial.print(pkt_index + 1);
        Serial.print("/"); Serial.print(total_pkts);
        Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes)");

        if (pkt_index >= 8 || total_pkts == 0 || total_pkts > 8) {
            Serial.println("Invalid header, skipping");
            return;
        }

        if (expected_total != 0 && total_pkts != expected_total) {
            Serial.println("New message detected, resetting reassembly");
            reset_reassembly();
        }

        expected_total = total_pkts;

        if (!received_packets[pkt_index]) {
            memcpy(reassembly_buf + (pkt_index * MAX_CHUNK_PER_PACKET), chunk, chunk_len);
            received_packets[pkt_index] = true;
            packets_received++;
        } else {
            Serial.println("Duplicate packet, ignoring");
            return;
        }

        if (packets_received == expected_total) {
            Serial.println("All packets received — decrypting...");

            uint8_t total_len = (expected_total - 1) * MAX_CHUNK_PER_PACKET + chunk_len;

            // XOR decrypt in place — XOR is symmetric so same operation as encrypt
            unsigned long t_start = micros();
            for (uint8_t i = 0; i < total_len; i++)
                reassembly_buf[i] ^= key[i % KEY_LEN];
            unsigned long t_dec = micros() - t_start;

            // Verify payload magic
            if (memcmp(reassembly_buf, PAYLOAD_MAGIC, 4) != 0) {
                Serial.println("Magic mismatch — wrong key or corrupted");
                reset_reassembly();
                return;
            }

            reassembly_buf[total_len] = '\0';
            Serial.print("Decrypted: ");
            Serial.println((char*)(reassembly_buf + 4));
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