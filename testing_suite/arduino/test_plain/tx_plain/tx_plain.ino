/*
 * TX — Plaintext baseline
 * Protocol: TEST,PLAIN,<size>,ENC_US:0,ITER:<n>
 */

#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

#define TEST_INTERVAL_MS 500
#define MSG_SIZE         16

static uint32_t iter = 0;

const uint8_t plaintext[MSG_SIZE] = {
    'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
};

void setup() {
    Serial.begin(9600);
    while (!Serial);
    if (!driver.init())
        Serial.println("RF init failed");
    Serial.println("TX_READY,PLAIN");
}

void loop() {
    uint8_t buf[MSG_SIZE];
    memcpy(buf, plaintext, MSG_SIZE);

    driver.send(buf, MSG_SIZE);
    driver.waitPacketSent();

    Serial.print("TEST,PLAIN,");
    Serial.print(MSG_SIZE);
    Serial.print(",ENC_US:0,ITER:");
    Serial.println(iter++);

    delay(TEST_INTERVAL_MS);
}
