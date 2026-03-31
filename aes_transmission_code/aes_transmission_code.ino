#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>  // DavyLandman — note: AES.h, not AESLib.h

RH_ASK driver(2000, 11, 12);

// Shared 128-bit key — 16 bytes exactly
uint8_t key[] = { 0,1,16,3,4,5,6,7,8,9,10,11,12,13,14,15 };

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
}

void loop() {
    // Must be exactly 16 bytes for one AES block
    char data[] = "THIS IS AN AES ENCRYPTED MESSAGE!";

    unsigned long t_start = micros();
    aes128_enc_single(key, data);  // encrypts in-place
    unsigned long t_enc = micros() - t_start;

    driver.send((uint8_t*)data, 16);
    driver.waitPacketSent();

    Serial.print("Sent encrypted block. Encrypt time (us): ");
    Serial.println(t_enc);
    delay(6000);
}