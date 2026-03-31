/*
 * TX — ChaCha20 stream cipher
 * Protocol: TEST,CHACHA20,<size>,ENC_US:<t>,ITER:<n>
 *
 * Stream cipher — no padding or block alignment needed.
 * No external library — pure C (RFC 7539).
 * Nonce is static for the benchmark; production use must increment per message.
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16

// 256-bit key — must match RX
const uint8_t cc20_key[32] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
};

// 96-bit nonce — must match RX
const uint8_t cc20_nonce[12] = {
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};

const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

static uint32_t iter = 0;

// --- ChaCha20 core (RFC 7539) ---
#define CC_ROTL(v,n) (((v) << (n)) | ((v) >> (32-(n))))
#define QR(a,b,c,d) \
    a += b; d ^= a; d = CC_ROTL(d,16); \
    c += d; b ^= c; b = CC_ROTL(b,12); \
    a += b; d ^= a; d = CC_ROTL(d, 8); \
    c += d; b ^= c; b = CC_ROTL(b, 7);

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24;
}

void chacha20_block(const uint8_t *key, uint32_t counter,
                    const uint8_t *nonce, uint8_t *out) {
    uint32_t s[16], init[16];
    s[0]=0x61707865; s[1]=0x3320646E; s[2]=0x79622D32; s[3]=0x6B206574;
    for (int i=0;i<8;i++) s[4+i]=load32_le(key+i*4);
    s[12]=counter;
    s[13]=load32_le(nonce); s[14]=load32_le(nonce+4); s[15]=load32_le(nonce+8);
    memcpy(init,s,64);
    for (int i=0;i<10;i++){
        QR(s[0],s[4],s[ 8],s[12]); QR(s[1],s[5],s[ 9],s[13]);
        QR(s[2],s[6],s[10],s[14]); QR(s[3],s[7],s[11],s[15]);
        QR(s[0],s[5],s[10],s[15]); QR(s[1],s[6],s[11],s[12]);
        QR(s[2],s[7],s[ 8],s[13]); QR(s[3],s[4],s[ 9],s[14]);
    }
    for (int i=0;i<16;i++) store32_le(out+i*4, s[i]+init[i]);
}

void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce,
                      uint8_t *data, uint8_t len) {
    uint8_t keystream[64];
    chacha20_block(key, 1, nonce, keystream);
    for (uint8_t i=0;i<len;i++) data[i]^=keystream[i];
}

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("TX_READY,CHACHA20");
}

void loop() {
    uint8_t buf[MSG_SIZE];
    memcpy(buf, plaintext, MSG_SIZE);

    unsigned long t_start = micros();
    chacha20_encrypt(cc20_key, cc20_nonce, buf, MSG_SIZE);
    unsigned long enc_us = micros() - t_start;

    driver.send(buf, MSG_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,CHACHA20,");
    Serial.print(MSG_SIZE);
    Serial.print(",ENC_US:");
    Serial.print(enc_us);
    Serial.print(",ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}
