#include <RH_ASK.h>
#include <SPI.h>
#include <AESLib.h>

RH_ASK driver(2000, 11, 12);

uint8_t key[] = { 0,1,16,3,4,5,6,7,8,9,10,11,12,13,14,15 };

void setup() {
    Serial.begin(9600);
    if (!driver.init())
        Serial.println("RF init failed");
}

void loop() {
    uint8_t buf[64];
    uint8_t buflen = sizeof(buf);

    if (driver.recv(buf, &buflen)) {
        unsigned long t_start = micros();
        aes128_dec_single(key, buf);  // decrypts in-place
        unsigned long t_dec = micros() - t_start;

        buf[16] = '\0';
        Serial.print("Decrypted: ");
        Serial.println((char*)buf);
        Serial.print("Decrypt time (us): ");
        Serial.println(t_dec);
    }
}