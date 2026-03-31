#include <RH_ASK.h>
#include <SPI.h>

// SPECK-64/128 receiver with CBC mode, PKCS7 unpadding, magic verification,
// and multi-packet reassembly with duplicate-packet detection.
//
// Reference: https://eprint.iacr.org/2013/404.pdf

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

// ── SPECK-64/128 parameters ──────────────────────────────────────────────────
#define SPECK_ROUNDS 27
#define ROR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROL32(x, r) ((x << r) | (x >> (32 - r)))

// Must match transmitter key exactly
const uint32_t raw_key[4] = {0x03020100, 0x07060504,
                              0x0B0A0908, 0x0F0E0D0C};

uint32_t round_keys[SPECK_ROUNDS];

// Correct SPECK-64/128 key schedule (ref. Algorithm 3 in the SPECK paper).
void speck_key_schedule(const uint32_t k[4]) {
    uint32_t l[SPECK_ROUNDS + 2];
    l[0] = k[1];
    l[1] = k[2];
    l[2] = k[3];

    round_keys[0] = k[0];
    uint32_t A = k[0];

    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        l[i + 3] = (ROR32(l[i], 8) + A) ^ i;
        A = ROL32(A, 3) ^ l[i + 3];
        round_keys[i + 1] = A;
    }
}

// Decrypt one 64-bit block — exact inverse of speck64_encrypt.
// Inverse operations (applied in reverse round order):
//   y = ROR(y ^ x, 3)          ← undo ROL(y,3) ^ x
//   x = ROL((x ^ rk) - y, 8)  ← undo (ROR(x,8) + y) ^ rk
void speck64_decrypt(uint32_t *x, uint32_t *y) {
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        *y = ROR32(*y ^ *x, 3);
        *x = ROL32((*x ^ round_keys[i]) - *y, 8);
    }
}

// ── Protocol constants ────────────────────────────────────────────────────────
const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

// CBC IV — must match transmitter exactly
const uint8_t iv[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

#define BLOCK_SIZE            8
#define MAX_CIPHER_PER_PACKET 56   // 7 × 8-byte blocks
#define MAX_TOTAL_CIPHER      192

// ── Reassembly state ──────────────────────────────────────────────────────────
uint8_t reassembly_buf[MAX_TOTAL_CIPHER];
bool    received_packets[8];   // which packet indices have arrived
uint8_t expected_total   = 0;
uint8_t packets_received = 0;

void reset_reassembly() {
    memset(reassembly_buf,   0, sizeof(reassembly_buf));
    memset(received_packets, 0, sizeof(received_packets));
    expected_total   = 0;
    packets_received = 0;
}

// ── PKCS7 unpadding ───────────────────────────────────────────────────────────
// Removes PKCS7 padding in-place and updates *len.
void pkcs7_unpad(uint8_t *buf, uint8_t *len) {
    if (*len == 0) return;
    uint8_t pad_byte = buf[*len - 1];
    if (pad_byte < 1 || pad_byte > BLOCK_SIZE) return; // invalid padding, leave as-is
    *len -= pad_byte;
    buf[*len] = '\0'; // null-terminate so we can print as a C string
}

// ── Arduino entry points ──────────────────────────────────────────────────────
void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK — listening...");
    speck_key_schedule(raw_key);
    reset_reassembly();
}

void loop() {
    uint8_t packet[64];
    uint8_t packet_len = sizeof(packet);

    if (!driver.recv(packet, &packet_len))
        return;

    // Need at least the 2-byte header plus one full SPECK block
    if (packet_len < 2 + BLOCK_SIZE) {
        Serial.println("Too short, skipping");
        return;
    }

    uint8_t  pkt_index  = packet[0];
    uint8_t  total_pkts = packet[1];
    uint8_t *chunk      = packet + 2;
    uint8_t  chunk_len  = packet_len - 2;

    Serial.print("Got packet "); Serial.print(pkt_index + 1);
    Serial.print("/"); Serial.print(total_pkts);
    Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes)");

    // Sanity-check the header fields
    if (pkt_index >= 8 || total_pkts == 0 || total_pkts > 8) {
        Serial.println("Invalid header, skipping");
        return;
    }

    // If this looks like the start of a brand-new message, reset reassembly
    if (expected_total != 0 && total_pkts != expected_total) {
        Serial.println("New message detected, resetting reassembly");
        reset_reassembly();
    }

    expected_total = total_pkts;

    // Deduplicate — the transmitter sends each packet 3× for reliability
    if (received_packets[pkt_index]) {
        Serial.println("Duplicate packet, ignoring");
        return;
    }

    // Store this chunk at its correct position in the reassembly buffer
    memcpy(reassembly_buf + (pkt_index * MAX_CIPHER_PER_PACKET), chunk, chunk_len);
    received_packets[pkt_index] = true;
    packets_received++;

    // Check whether all packets for this message have arrived
    if (packets_received < expected_total) {
        Serial.print("Waiting for ");
        Serial.print(expected_total - packets_received);
        Serial.println(" more packet(s)...");
        return;
    }

    // ── All packets received — decrypt ────────────────────────────────────────
    Serial.println("All packets received — decrypting...");

    // The last chunk may be shorter than MAX_CIPHER_PER_PACKET
    uint8_t last_chunk_len = chunk_len; // chunk_len still refers to the last packet
    uint8_t total_cipher   = (expected_total - 1) * MAX_CIPHER_PER_PACKET + last_chunk_len;

    uint8_t decrypted[MAX_TOTAL_CIPHER];
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE); // start CBC chain with the shared IV

    unsigned long t_start = micros();
    for (uint8_t i = 0; i < total_cipher; i += BLOCK_SIZE) {
        // Save ciphertext block before we overwrite it
        uint8_t ct_block[BLOCK_SIZE];
        memcpy(ct_block, &reassembly_buf[i], BLOCK_SIZE);

        // Decrypt in-place using two 32-bit words (little-endian)
        uint32_t x, y;
        memcpy(&x, &reassembly_buf[i],     4);
        memcpy(&y, &reassembly_buf[i + 4], 4);
        speck64_decrypt(&x, &y);
        memcpy(&decrypted[i],     &x, 4);
        memcpy(&decrypted[i + 4], &y, 4);

        // XOR with previous ciphertext block (CBC)
        for (uint8_t j = 0; j < BLOCK_SIZE; j++)
            decrypted[i + j] ^= prev[j];

        // Advance the CBC chain
        memcpy(prev, ct_block, BLOCK_SIZE);
    }
    unsigned long t_dec = micros() - t_start;

    // ── Verify magic ──────────────────────────────────────────────────────────
    if (memcmp(decrypted, MAGIC, 4) != 0) {
        Serial.println("Magic mismatch — wrong key or corrupted data");
        reset_reassembly();
        return;
    }

    // ── Strip PKCS7 padding and print ─────────────────────────────────────────
    pkcs7_unpad(decrypted, &total_cipher);

    Serial.print("Decrypted: ");
    Serial.println((char *)(decrypted + 4)); // skip the 4-byte magic prefix
    Serial.print("Decrypt time (us): ");
    Serial.println(t_dec);

    reset_reassembly();
}
