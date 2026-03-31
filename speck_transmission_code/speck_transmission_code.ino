#include <RH_ASK.h>
#include <SPI.h>

// SPECK-64/128 transmitter with CBC mode, PKCS7 padding, magic header,
// and multi-packet support.
//
// SPECK is an NSA-designed lightweight block cipher for constrained hardware.
// Block size: 64 bits (8 bytes). Key size: 128 bits (4 x uint32_t).
// No external library required — pure C implementation.
// Reference: https://eprint.iacr.org/2013/404.pdf

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

// ── SPECK-64/128 parameters ──────────────────────────────────────────────────
#define SPECK_ROUNDS 27
#define ROR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROL32(x, r) ((x << r) | (x >> (32 - r)))

// 128-bit key (4 x 32-bit words, little-endian) — must match receiver
const uint32_t raw_key[4] = {0x03020100, 0x07060504,
                              0x0B0A0908, 0x0F0E0D0C};

uint32_t round_keys[SPECK_ROUNDS];

// Correct SPECK-64/128 key schedule (ref. Algorithm 3 in the SPECK paper).
// The 128-bit key is split into k[0] (the first key word) and l[0..2]
// (the remaining three words). Each round i produces round_keys[i+1] by
// advancing a single sequential index into l[], not a modulo-3 swap.
void speck_key_schedule(const uint32_t k[4]) {
    // l[] holds the "auxiliary" key words that are updated each round.
    // Initialised from k[1..3]; we need enough headroom for SPECK_ROUNDS-1
    // updates, so size the array accordingly.
    uint32_t l[SPECK_ROUNDS + 2];
    l[0] = k[1];
    l[1] = k[2];
    l[2] = k[3];

    round_keys[0] = k[0];
    uint32_t A = k[0]; // running key word

    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        // l[i+3] = (ROR(l[i], 8) + A) ^ i
        l[i + 3] = (ROR32(l[i], 8) + A) ^ i;
        // A = ROL(A, 3) ^ l[i+3]
        A = ROL32(A, 3) ^ l[i + 3];
        round_keys[i + 1] = A;
    }
}

// Encrypt one 64-bit block (two 32-bit words, in-place).
void speck64_encrypt(uint32_t *x, uint32_t *y) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x = (ROR32(*x, 8) + *y) ^ round_keys[i];
        *y = ROL32(*y, 3) ^ *x;
    }
}

// ── Protocol constants ────────────────────────────────────────────────────────
// Magic bytes prepended to every plaintext so the receiver can verify the key.
const uint8_t MAGIC[] = {0xDE, 0xAD, 0xBE, 0xEF};

// CBC IV — must match the receiver exactly.
// With a static IV the same plaintext always produces the same ciphertext;
// acceptable for a lab demo, but use a random IV in production.
const uint8_t iv[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

// Each RF packet carries a 2-byte header (packet index + total count) plus
// ciphertext.  RH_ASK max payload is 60 bytes, so leave room for the header.
// Round down to a SPECK block boundary: 56 bytes = 7 blocks per packet.
#define BLOCK_SIZE            8
#define MAX_CIPHER_PER_PACKET 56   // 7 × 8-byte blocks
#define MAX_TOTAL_CIPHER      192  // enough for ~180-byte messages

// ── PKCS7 helpers ─────────────────────────────────────────────────────────────
// Pad `src` (length `len`) into `dst` using PKCS7 and return padded length.
uint8_t pkcs7_pad(uint8_t *dst, const uint8_t *src, uint8_t len) {
    uint8_t padded_len = ((len / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    uint8_t pad_byte   = padded_len - len;
    memcpy(dst, src, len);
    for (uint8_t i = len; i < padded_len; i++)
        dst[i] = pad_byte;
    return padded_len;
}

// ── Arduino entry points ──────────────────────────────────────────────────────
void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
    speck_key_schedule(raw_key);
}

void loop() {
    const char *msg = "HELLO SNE THIS IS A LONG MESSAGE THAT NEEDS MULTIPLE PACKETS TO TRANSMIT SECURELY OVER RF!";

    // 1. Build plaintext: MAGIC (4 bytes) + message
    uint8_t plaintext[MAX_TOTAL_CIPHER];
    uint8_t plain_len = 4 + strlen(msg);
    memcpy(plaintext, MAGIC, 4);
    memcpy(plaintext + 4, msg, strlen(msg));

    // 2. PKCS7-pad to a SPECK block boundary
    uint8_t padded[MAX_TOTAL_CIPHER];
    uint8_t padded_len = pkcs7_pad(padded, plaintext, plain_len);

    Serial.println("--- Plaintext blocks ---");
    for (uint8_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        Serial.print("  Block "); Serial.print(i / BLOCK_SIZE); Serial.print(": ");
        for (uint8_t j = 0; j < BLOCK_SIZE; j++) {
            char c = (char)padded[i + j];
            Serial.print(c >= 32 && c < 127 ? c : '.');
        }
        Serial.println();
    }

    // 3. CBC encrypt (XOR with previous ciphertext block, then encrypt)
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    unsigned long t_start = micros();
    for (uint8_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        // XOR plaintext block with IV / previous ciphertext block
        for (uint8_t j = 0; j < BLOCK_SIZE; j++)
            padded[i + j] ^= prev[j];

        // Encrypt the block in-place using two 32-bit words (little-endian)
        uint32_t x, y;
        memcpy(&x, &padded[i],     4);
        memcpy(&y, &padded[i + 4], 4);
        speck64_encrypt(&x, &y);
        memcpy(&padded[i],     &x, 4);
        memcpy(&padded[i + 4], &y, 4);

        // Save ciphertext block as next IV
        memcpy(prev, &padded[i], BLOCK_SIZE);
    }
    unsigned long t_enc = micros() - t_start;

    // 4. Split ciphertext into packets and send (3× retransmit each)
    uint8_t total_packets = (padded_len + MAX_CIPHER_PER_PACKET - 1) / MAX_CIPHER_PER_PACKET;

    Serial.print("Total ciphertext bytes: "); Serial.println(padded_len);
    Serial.print("Splitting into "); Serial.print(total_packets); Serial.println(" packet(s)");

    for (uint8_t pkt = 0; pkt < total_packets; pkt++) {
        uint8_t offset    = pkt * MAX_CIPHER_PER_PACKET;
        uint8_t chunk_len = min((uint8_t)MAX_CIPHER_PER_PACKET,
                                (uint8_t)(padded_len - offset));

        // Packet layout: [pkt_index (1B)] [total_packets (1B)] [ciphertext chunk]
        uint8_t packet[60];
        packet[0] = pkt;
        packet[1] = total_packets;
        memcpy(packet + 2, padded + offset, chunk_len);
        uint8_t packet_len = 2 + chunk_len;

        Serial.print("  Sending packet "); Serial.print(pkt + 1);
        Serial.print("/"); Serial.print(total_packets);
        Serial.print(" ("); Serial.print(chunk_len); Serial.println(" bytes ciphertext)");

        // Transmit 3 times so the receiver can discard duplicates rather than
        // miss a packet due to RF noise.
        for (uint8_t r = 0; r < 3; r++) {
            driver.send(packet, packet_len);
            driver.waitPacketSent();
            delay(100);
        }
        delay(500); // gap between different packets so RX can process each one
    }

    Serial.print("Done. Encrypt time (us): "); Serial.println(t_enc);
    delay(6000); // duty-cycle gap — give others airtime
}
