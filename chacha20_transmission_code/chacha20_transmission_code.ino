#include <RH_ASK.h>
#include <SPI.h>

// ChaCha20 stream cipher transmitter
// ChaCha20 is a stream cipher — no padding, no block alignment needed.
// Any message length up to the RF packet limit works directly.
// Nonce is static here for the demo; production use must increment per message.
// Reference: RFC 7539. No external library — pure C implementation.

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

// 256-bit key (32 bytes) — must match receiver
const uint8_t cc20_key[32] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
};

// 96-bit nonce (12 bytes) — static for demo, must match receiver
const uint8_t cc20_nonce[12] = {
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};

// --- ChaCha20 core (RFC 7539) ---
#define CC_ROTL(v,n) (((v) << (n)) | ((v) >> (32-(n))))
#define QR(a,b,c,d) \
    a += b; d ^= a; d = CC_ROTL(d,16); \
    c += d; b ^= c; b = CC_ROTL(b,12); \
    a += b; d ^= a; d = CC_ROTL(d, 8); \
    c += d; b ^= c; b = CC_ROTL(b, 7);

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

// Generate one 64-byte ChaCha20 keystream block
void chacha20_block(const uint8_t *key, uint32_t counter,
                    const uint8_t *nonce, uint8_t *out) {
    uint32_t s[16], init[16];

    // "expand 32-byte k" constant
    s[0]  = 0x61707865; s[1]  = 0x3320646E;
    s[2]  = 0x79622D32; s[3]  = 0x6B206574;
    // Key
    for (int i = 0; i < 8; i++)
        s[4 + i] = load32_le(key + i * 4);
    // Counter + nonce
    s[12] = counter;
    s[13] = load32_le(nonce);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);

    memcpy(init, s, 64);

    // 20 rounds (10 double-rounds)
    for (int i = 0; i < 10; i++) {
        QR(s[0], s[4], s[ 8], s[12]);
        QR(s[1], s[5], s[ 9], s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[ 8], s[13]);
        QR(s[3], s[4], s[ 9], s[14]);
    }

    for (int i = 0; i < 16; i++)
        store32_le(out + i * 4, s[i] + init[i]);
}

// XOR plaintext with ChaCha20 keystream (encrypt or decrypt — same operation)
void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce,
                      uint8_t *data, uint8_t len) {
    uint8_t keystream[64];
    chacha20_block(key, 1, nonce, keystream); // counter starts at 1 per RFC 7539
    for (uint8_t i = 0; i < len; i++)
        data[i] ^= keystream[i];
}

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
    else
        Serial.println("RF init OK");
}

void loop() {
    const char* msg = "Hello SNE ChaCha20!";
    uint8_t len = strlen(msg);
    uint8_t buf[64];
    memcpy(buf, msg, len);

    unsigned long t_start = micros();
    chacha20_encrypt(cc20_key, cc20_nonce, buf, len);
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
