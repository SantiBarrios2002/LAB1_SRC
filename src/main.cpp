#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>

// ESP32 DevKit Hardware SPI pins for PN532
#define PN532_SS   5   // Chip Select (CS)
#define PN532_SCK  18  // SPI Clock
#define PN532_MISO 19  // Master In Slave Out
#define PN532_MOSI 23  // Master Out Slave In

Adafruit_PN532 nfc(PN532_SS);

uint8_t keyA_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const char* identifyTagType(uint8_t *uid, uint8_t uidLength) {
  // Try Mifare Classic authentication
  if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, keyA_default)) {
    return "Mifare Classic";
  }

  // Try Mifare Ultralight / NTAG read
  uint8_t pageData[4];
  if (nfc.mifareultralight_ReadPage(4, pageData)) {
    return "Mifare Ultralight / NTAG2xx";
  }

  return "Unknown";
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  Serial.println("\nPN532 RFID Key Identifier");
  Serial.println("========================");

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("ERROR: PN532 not found. Check wiring!");
    while (1) delay(100);
  }

  Serial.print("PN5");
  Serial.print((versiondata >> 24) & 0xFF, HEX);
  Serial.print(" fw ");
  Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print(".");
  Serial.println((versiondata >> 8) & 0xFF, DEC);

  nfc.SAMConfig();
  nfc.setPassiveActivationRetries(0xFF);

  Serial.println("Ready. Scan a tag...\n");
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 1000)) {
    // Print UID
    Serial.print("UID: ");
    for (uint8_t i = 0; i < uidLength; i++) {
      if (uid[i] < 0x10) Serial.print("0");
      Serial.print(uid[i], HEX);
      if (i < uidLength - 1) Serial.print(":");
    }

    // Identify and print type
    const char* tagType = identifyTagType(uid, uidLength);
    Serial.print(" -> ");
    Serial.println(tagType);

    delay(1500);
  }
}
