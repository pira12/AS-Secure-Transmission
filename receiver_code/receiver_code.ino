#include <RH_ASK.h>
#include <SPI.h>

RH_ASK driver(2000, 11, 12);

// Plaintext receiver code

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);
    if (driver.recv(buf, &buflen)) {
        buf[buflen] = '\0'; // null-terminate
        Serial.print("Received: ");
        Serial.println((char *)buf);
    }
}