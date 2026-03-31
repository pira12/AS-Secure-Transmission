#include <RH_ASK.h>
#include <SPI.h> // required by RadioHead even for ASK

// Plaintext transmitter code

RH_ASK driver(2000, 11, 12); // speed, RX pin, TX pin

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
}

void loop() {
    const char *msg = "A plain text message to transmit!!";
    driver.send((uint8_t *)msg, strlen(msg));
    driver.waitPacketSent();
    Serial.print("Sent: ");
    Serial.println(msg);
    delay(6000); // mandatory per assignment
}