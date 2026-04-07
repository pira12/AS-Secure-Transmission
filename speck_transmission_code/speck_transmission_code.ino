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
static uint8_t plaintext[192];
static uint8_t padded[192];

void speck_key_schedule(const uint32_t k[4]) {
    speck_l[0] = k[1]; speck_l[1] = k[2]; speck_l[2] = k[3];
    round_keys[0] = k[0];
    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        speck_l[i + 3]    = (ROR32(speck_l[i], 8) + round_keys[i]) ^ i;
        round_keys[i + 1] = ROL32(round_keys[i], 3) ^ speck_l[i + 3];
    }
}

void speck64_encrypt_bytes(uint8_t block[8]) {
    uint32_t x, y;
    // Big-endian load: block[0] is most significant byte of x
    x = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
        ((uint32_t)block[2] <<  8) |  (uint32_t)block[3];
    y = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
        ((uint32_t)block[6] <<  8) |  (uint32_t)block[7];
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        x = (ROR32(x, 8) + y) ^ round_keys[i];
        y = ROL32(y, 3) ^ x;
    }
    // Big-endian store
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

uint8_t pkcs7_pad(uint8_t *dst, const uint8_t *src, uint8_t len) {
    uint8_t padded_len = ((len / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    uint8_t pad_byte   = padded_len - len;
    memcpy(dst, src, len);
    for (uint8_t i = len; i < padded_len; i++) dst[i] = pad_byte;
    return padded_len;
}

void setup() {
    Serial.begin(9600);
    speck_key_schedule(raw_key);
    Serial.print("Free RAM: "); Serial.println(freeMemory());
    Serial.println("--- Round keys (first 4) ---");
    for (int i = 0; i < 4; i++) {
        Serial.print("  rk["); Serial.print(i); Serial.print("]: 0x");
        Serial.println(round_keys[i], HEX);
    }
    if (!driver.init()) Serial.println("RF init failed");
    else                Serial.println("RF init OK");
}

void loop() {
    const char *msg = "HELLO SNE THIS IS A LONG MESSAGE THAT NEEDS MULTIPLE PACKETS TO TRANSMIT SECURELY OVER RF!";

    uint8_t plain_len = 4 + strlen(msg);
    memcpy(plaintext, MAGIC, 4);
    memcpy(plaintext + 4, msg, strlen(msg));

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

    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    unsigned long t_start = micros();
    for (uint8_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        for (uint8_t j = 0; j < BLOCK_SIZE; j++)
            padded[i + j] ^= prev[j];
        speck64_encrypt_bytes(&padded[i]);
        memcpy(prev, &padded[i], BLOCK_SIZE);
    }
    unsigned long t_enc = micros() - t_start;

    Serial.println("--- Ciphertext blocks ---");
    for (uint8_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        Serial.print("  Block "); Serial.print(i / BLOCK_SIZE); Serial.print(": ");
        for (uint8_t j = 0; j < BLOCK_SIZE; j++) {
            if (padded[i + j] < 0x10) Serial.print("0");
            Serial.print(padded[i + j], HEX); Serial.print(" ");
        }
        Serial.println();
    }

    uint8_t total_packets = (padded_len + MAX_CIPHER_PER_PACKET - 1) / MAX_CIPHER_PER_PACKET;
    Serial.print("Total ciphertext bytes: "); Serial.println(padded_len);
    Serial.print("Splitting into "); Serial.print(total_packets); Serial.println(" packet(s)");

    for (uint8_t pkt = 0; pkt < total_packets; pkt++) {
        uint8_t offset    = pkt * MAX_CIPHER_PER_PACKET;
        uint8_t chunk_len = min((uint8_t)MAX_CIPHER_PER_PACKET, (uint8_t)(padded_len - offset));

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
        delay(500);
    }

    Serial.print("Done. Encrypt time (us): "); Serial.println(t_enc);
    delay(6000);
}