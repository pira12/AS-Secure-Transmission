#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define SPECK_ROUNDS 27
#define ROR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROL32(x, r) ((x << r) | (x >> (32 - r)))

const uint32_t raw_key[4] = {0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C};
uint32_t round_keys[SPECK_ROUNDS];
static uint32_t speck_l[SPECK_ROUNDS + 2];

// ── Large buffers as globals to avoid stack overflow ──────────────────────────
static uint8_t reassembly_buf[192];
static uint8_t decrypted[192];

uint8_t chunk_lengths[8];
bool    received_packets[8];
uint8_t expected_total   = 0;
uint8_t packets_received = 0;

void speck_key_schedule(const uint32_t k[4]) {
    speck_l[0] = k[1]; speck_l[1] = k[2]; speck_l[2] = k[3];
    round_keys[0] = k[0];
    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        speck_l[i + 3]    = (ROR32(speck_l[i], 8) + round_keys[i]) ^ i;
        round_keys[i + 1] = ROL32(round_keys[i], 3) ^ speck_l[i + 3];
    }
}

void speck64_decrypt_bytes(uint8_t block[8]) {
    uint32_t x, y;
    x = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
        ((uint32_t)block[2] <<  8) |  (uint32_t)block[3];
    y = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
        ((uint32_t)block[6] <<  8) |  (uint32_t)block[7];
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        y = ROR32(y ^ x, 3);
        x = ROL32((x ^ round_keys[i]) - y, 8);
    }
    block[0] = (x >> 24) & 0xFF; block[1] = (x >> 16) & 0xFF;
    block[2] = (x >>  8) & 0xFF; block[3] =  x        & 0xFF;
    block[4] = (y >> 24) & 0xFF; block[5] = (y >> 16) & 0xFF;
    block[6] = (y >>  8) & 0xFF; block[7] =  y        & 0xFF;
}

const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};
const uint8_t iv[8]   = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

#define BLOCK_SIZE            8
#define MAX_CIPHER_PER_PACKET 56

int freeMemory() {
    extern int __heap_start, *__brkval;
    int v;
    return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}

void reset_reassembly() {
    memset(reassembly_buf,   0, sizeof(reassembly_buf));
    memset(received_packets, 0, sizeof(received_packets));
    memset(chunk_lengths,    0, sizeof(chunk_lengths));
    expected_total   = 0;
    packets_received = 0;
}

void pkcs7_unpad(uint8_t *buf, uint8_t *len) {
    if (*len == 0) return;
    uint8_t pad_byte = buf[*len - 1];
    if (pad_byte < 1 || pad_byte > BLOCK_SIZE) return;
    *len -= pad_byte;
    buf[*len] = '\0';
}

void printBlock(const char* label, uint8_t* b) {
    Serial.print(label);
    for (int i = 0; i < 8; i++) {
        if (b[i] < 0x10) Serial.print("0");
        Serial.print(b[i], HEX); Serial.print(" ");
    }
    Serial.println();
}

void setup() {
    Serial.begin(9600);
    delay(500);
    speck_key_schedule(raw_key);

    Serial.print("Free RAM: "); Serial.println(freeMemory());
    Serial.println("--- Round keys (first 4) ---");
    for (int i = 0; i < 4; i++) {
        Serial.print("  rk["); Serial.print(i); Serial.print("]: 0x");
        Serial.println(round_keys[i], HEX);
    }

    Serial.println("=== Loopback test ===");
    uint8_t ct[8]          = {0x6A, 0xA3, 0xF7, 0x42, 0x7A, 0xF1, 0xD6, 0xB1};
    uint8_t expected_pt[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x48, 0x45, 0x4C, 0x4C};
    printBlock("Ciphertext:    ", ct);
    speck64_decrypt_bytes(ct);
    printBlock("After decrypt: ", ct);
    for (int i = 0; i < 8; i++) ct[i] ^= iv[i];
    printBlock("After IV XOR:  ", ct);
    printBlock("Expected:      ", expected_pt);
    Serial.println(memcmp(ct, expected_pt, 8) == 0 ? "Loopback: PASS" : "Loopback: FAIL");

    if (!driver.init()) Serial.println("RF init failed");
    else                Serial.println("RF init OK — listening...");
    reset_reassembly();
}

void loop() {
    uint8_t packet[64];
    uint8_t packet_len = sizeof(packet);

    if (!driver.recv(packet, &packet_len)) return;

    if (packet_len < 2 + BLOCK_SIZE) { Serial.println("Too short, skipping"); return; }

    uint8_t  pkt_index  = packet[0];
    uint8_t  total_pkts = packet[1];
    uint8_t *chunk      = packet + 2;
    uint8_t  chunk_len  = packet_len - 2;

    if (total_pkts == 0 || total_pkts > 8 || pkt_index >= total_pkts) {
        Serial.println("Invalid header, skipping"); return;
    }

    if (expected_total != 0 && total_pkts != expected_total) {
        Serial.println("New message detected, resetting reassembly");
        reset_reassembly();
    }

    expected_total = total_pkts;

    if (received_packets[pkt_index]) { Serial.println("Duplicate packet, ignoring"); return; }

    Serial.print("Got packet "); Serial.print(pkt_index + 1);
    Serial.print("/"); Serial.print(total_pkts);
    Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes)");

    memcpy(reassembly_buf + (pkt_index * MAX_CIPHER_PER_PACKET), chunk, chunk_len);
    chunk_lengths[pkt_index] = chunk_len;
    received_packets[pkt_index] = true;
    packets_received++;

    if (packets_received < expected_total) {
        Serial.print("Waiting for "); Serial.print(expected_total - packets_received);
        Serial.println(" more packet(s)..."); return;
    }

    Serial.println("All packets received — decrypting...");

    uint8_t total_cipher = 0;
    for (uint8_t i = 0; i < expected_total; i++) total_cipher += chunk_lengths[i];

    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (uint8_t i = 0; i < total_cipher; i += BLOCK_SIZE) {
        uint8_t ct_block[BLOCK_SIZE];
        memcpy(ct_block, &reassembly_buf[i], BLOCK_SIZE);
        memcpy(&decrypted[i], &reassembly_buf[i], BLOCK_SIZE);
        speck64_decrypt_bytes(&decrypted[i]);
        for (uint8_t j = 0; j < BLOCK_SIZE; j++) decrypted[i + j] ^= prev[j];
        memcpy(prev, ct_block, BLOCK_SIZE);
    }

    printBlock("Decrypted block 0: ", decrypted);

    if (memcmp(decrypted, MAGIC, 4) != 0) {
        Serial.println("Magic mismatch — wrong key or corrupted data");
        reset_reassembly(); return;
    }

    pkcs7_unpad(decrypted, &total_cipher);
    Serial.print("Decrypted: ");
    Serial.println((char *)(decrypted + 4));
    reset_reassembly();
}