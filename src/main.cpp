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

// Common MIFARE Classic keys found in the wild
const uint8_t KNOWN_KEYS[][6] = {
  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  // Factory default
  {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},  // MAD key A
  {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},  // MAD key B
  {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},  // NFC Forum / NDEF
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // Zeros
  {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0},  // Common transport
  {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},  // Common transport
  {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},  // Infineon
  {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},  // Gallagher
  {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},  // Samsung/Philips
};
const uint8_t NUM_KNOWN_KEYS = sizeof(KNOWN_KEYS) / sizeof(KNOWN_KEYS[0]);

// Test all known keys on every sector of a MIFARE Classic tag
void testClassicKeys(uint8_t *uid, uint8_t uidLen, TagType type) {
  uint8_t numSectors = (type == TAG_MIFARE_CLASSIC_4K) ? 40 : 16;

  Serial.println("  --- MIFARE Classic Key Audit ---");
  Serial.println("  Sect | Key A found              | Key B found");
  Serial.println("  -----+--------------------------+--------------------------");

  for (uint8_t sector = 0; sector < numSectors; sector++) {
    // First block of each sector (trailer block is used for auth)
    uint8_t firstBlock;
    if (sector < 32) {
      firstBlock = sector * 4;
    } else {
      firstBlock = 128 + (sector - 32) * 16;
    }

    Serial.print("  ");
    if (sector < 10) Serial.print(" ");
    Serial.print(sector);
    Serial.print("  | ");

    // Try Key A (type 0)
    bool foundA = false;
    for (uint8_t k = 0; k < NUM_KNOWN_KEYS; k++) {
      if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, firstBlock, 0, (uint8_t *)KNOWN_KEYS[k])) {
        foundA = true;
        for (uint8_t i = 0; i < 6; i++) {
          printHex(KNOWN_KEYS[k][i]);
          if (i < 5) Serial.print(":");
        }
        Serial.print(" (A)");
        break;
      }
    }
    if (!foundA) {
      Serial.print("-- none matched --    ");
    }

    Serial.print(" | ");

    // Try Key B (type 1)
    bool foundB = false;
    for (uint8_t k = 0; k < NUM_KNOWN_KEYS; k++) {
      if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, firstBlock, 1, (uint8_t *)KNOWN_KEYS[k])) {
        foundB = true;
        for (uint8_t i = 0; i < 6; i++) {
          printHex(KNOWN_KEYS[k][i]);
          if (i < 5) Serial.print(":");
        }
        Serial.print(" (B)");
        break;
      }
    }
    if (!foundB) {
      Serial.print("-- none matched --");
    }

    Serial.println();
  }

  Serial.print("  Keys tested per sector: ");
  Serial.print(NUM_KNOWN_KEYS);
  Serial.println(" known keys x 2 (A+B)");
}

// Dump MIFARE Classic 1K: 16 sectors, 4 blocks each (64 blocks total)
// Classic 4K: 32 sectors x 4 blocks + 8 sectors x 16 blocks (256 blocks total)
void dumpMifareClassic(uint8_t *uid, uint8_t uidLen, TagType type) {
  uint8_t totalBlocks = (type == TAG_MIFARE_CLASSIC_4K) ? 256 : 64;
  uint8_t data[16];

  Serial.println("  --- MIFARE Classic Memory Dump ---");
  Serial.println("  Blk | Data                                          | ASCII");
  Serial.println("  ----+--------------------------------------------------+------------------");

  for (uint8_t block = 0; block < totalBlocks; block++) {
    // Authenticate at the start of each sector
    // Classic 1K/Mini: 4 blocks per sector
    // Classic 4K: 4 blocks per sector for first 32, 16 blocks per sector after
    uint8_t sectorFirstBlock;
    if (block < 128) {
      sectorFirstBlock = block - (block % 4);
    } else {
      sectorFirstBlock = block - (block % 16);
    }

    if (block == sectorFirstBlock) {
      if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, 0, (uint8_t *)KNOWN_KEYS[0])) {
        // Print the sector as unreadable
        uint8_t blocksInSector = (block < 128) ? 4 : 16;
        for (uint8_t b = 0; b < blocksInSector && (block + b) < totalBlocks; b++) {
          Serial.print("  ");
          if ((block + b) < 10) Serial.print(" ");
          if ((block + b) < 100) Serial.print(" ");
          Serial.print(block + b);
          Serial.println(" | AUTH FAILED (key FF..FF)                         |");
        }
        block = sectorFirstBlock + ((block < 128) ? 3 : 15);
        continue;
      }
    }

    if (nfc.mifareclassic_ReadDataBlock(block, data)) {
      // Block number
      Serial.print("  ");
      if (block < 10) Serial.print(" ");
      if (block < 100) Serial.print(" ");
      Serial.print(block);
      Serial.print(" | ");

      // Hex
      for (uint8_t i = 0; i < 16; i++) {
        printHex(data[i]);
        Serial.print(" ");
      }
      Serial.print("| ");

      // ASCII
      for (uint8_t i = 0; i < 16; i++) {
        Serial.print((data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.');
      }
      Serial.println();
    } else {
      Serial.print("  ");
      if (block < 10) Serial.print(" ");
      if (block < 100) Serial.print(" ");
      Serial.print(block);
      Serial.println(" | READ ERROR                                        |");
    }
  }
}

// Dump MIFARE Ultralight / NTAG: 4 bytes per page
// Ultralight: 16 pages, Ultralight C: 48 pages, NTAG213: 45, NTAG215: 135, NTAG216: 231
// We read until we get a failure, which indicates end of memory
void dumpUltralight(void) {
  uint8_t data[4];

  Serial.println("  --- Ultralight / NTAG Memory Dump ---");
  Serial.println("  Page | Data        | ASCII");
  Serial.println("  -----+-------------+------");

  for (uint8_t page = 0; page < 231; page++) {
    if (!nfc.mifareultralight_ReadPage(page, data)) {
      break;
    }

    // Page number
    Serial.print("  ");
    if (page < 10) Serial.print(" ");
    if (page < 100) Serial.print(" ");
    Serial.print(page);
    Serial.print("  | ");

    // Hex
    for (uint8_t i = 0; i < 4; i++) {
      printHex(data[i]);
      Serial.print(" ");
    }
    Serial.print("| ");

    // ASCII
    for (uint8_t i = 0; i < 4; i++) {
      Serial.print((data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.');
    }
    Serial.println();
  }
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

    // Memory dump and key audit based on tag type
    if (tag.type == TAG_MIFARE_CLASSIC_1K || tag.type == TAG_MIFARE_CLASSIC_4K) {
      dumpMifareClassic(uid, uidLength, tag.type);
      Serial.println();
      testClassicKeys(uid, uidLength, tag.type);
    } else if (tag.type == TAG_MIFARE_ULTRALIGHT) {
      dumpUltralight();
    } else {
      Serial.println("  (Memory dump not supported for this tag type)");
    }

    Serial.println();
    delay(2000);
  }
}
