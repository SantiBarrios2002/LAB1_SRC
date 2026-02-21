#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>

// ESP32 DevKit Hardware SPI pins for PN532
#define PN532_SS   5   // Chip Select (CS)
#define PN532_SCK  18  // SPI Clock
#define PN532_MISO 19  // Master In Slave Out
#define PN532_MOSI 23  // Master Out Slave In

Adafruit_PN532 nfc(PN532_SS);

// Access the library's internal packet buffer to read ATQA/SAK
extern byte pn532_packetbuffer[];

// Tag type enumeration
enum TagType {
  TAG_MIFARE_CLASSIC_1K,
  TAG_MIFARE_CLASSIC_4K,
  TAG_MIFARE_ULTRALIGHT,
  TAG_MIFARE_PLUS,
  TAG_MIFARE_DESFIRE,
  TAG_NTAG_213_215_216,
  TAG_ISO14443_4,
  TAG_UNKNOWN
};

struct TagInfo {
  TagType type;
  const char *name;
  uint16_t atqa;
  uint8_t sak;
  uint8_t uidLen;
};

// Identify tag from SAK, ATQA and UID length
// SAK is the primary identifier per ISO 14443-3
TagInfo identifyTag(uint16_t atqa, uint8_t sak, uint8_t uidLen) {
  TagInfo info;
  info.atqa = atqa;
  info.sak = sak;
  info.uidLen = uidLen;

  if (sak == 0x08) {
    info.type = TAG_MIFARE_CLASSIC_1K;
    info.name = "MIFARE Classic 1K";
  } else if (sak == 0x18) {
    info.type = TAG_MIFARE_CLASSIC_4K;
    info.name = "MIFARE Classic 4K";
  } else if (sak == 0x09) {
    info.type = TAG_MIFARE_CLASSIC_1K;
    info.name = "MIFARE Classic Mini";
  } else if (sak == 0x00 && uidLen == 7) {
    info.type = TAG_MIFARE_ULTRALIGHT;
    info.name = "MIFARE Ultralight / NTAG";
  } else if (sak == 0x00 && uidLen == 4) {
    info.type = TAG_MIFARE_ULTRALIGHT;
    info.name = "MIFARE Ultralight (4-byte UID)";
  } else if (sak == 0x10) {
    info.type = TAG_MIFARE_PLUS;
    info.name = "MIFARE Plus 2K (SL2)";
  } else if (sak == 0x11) {
    info.type = TAG_MIFARE_PLUS;
    info.name = "MIFARE Plus 4K (SL2)";
  } else if (sak == 0x20 && (atqa & 0x0F) == 0x03) {
    info.type = TAG_MIFARE_DESFIRE;
    info.name = "MIFARE DESFire";
  } else if (sak == 0x20) {
    info.type = TAG_ISO14443_4;
    info.name = "ISO 14443-4 (SAK 0x20)";
  } else {
    info.type = TAG_UNKNOWN;
    info.name = "Unknown";
  }

  return info;
}

void printHex(uint8_t val) {
  if (val < 0x10) Serial.print("0");
  Serial.print(val, HEX);
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  Serial.println("\nPN532 NFC Multi-Tool");
  Serial.println("====================");

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
    uint16_t atqa = (pn532_packetbuffer[9] << 8) | pn532_packetbuffer[10];
    uint8_t sak = pn532_packetbuffer[11];

    TagInfo tag = identifyTag(atqa, sak, uidLength);

    // Tag type
    Serial.print("Tag: ");
    Serial.println(tag.name);

    // UID
    Serial.print("  UID (");
    Serial.print(uidLength);
    Serial.print("): ");
    for (uint8_t i = 0; i < uidLength; i++) {
      printHex(uid[i]);
      if (i < uidLength - 1) Serial.print(":");
    }
    Serial.println();

    // Raw ATQA + SAK
    Serial.print("  ATQA: 0x");
    if (atqa < 0x1000) Serial.print("0");
    if (atqa < 0x100) Serial.print("0");
    if (atqa < 0x10) Serial.print("0");
    Serial.print(atqa, HEX);
    Serial.print("  SAK: 0x");
    printHex(sak);
    Serial.println();

    Serial.println();
    delay(1500);
  }
}
