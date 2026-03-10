#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>
#include <mbedtls/des.h>

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

// Re-select the card after a failed auth (card goes to HALT state)
bool reselectCard(void) {
  uint8_t uid[7];
  uint8_t uidLen;
  return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 500);
}

// Try to authenticate a block with all known keys, re-selecting after each failure.
// Returns the key index that worked, or -1 if none matched.
// keyType: 0 = Key A, 1 = Key B
int8_t tryAuthBlock(uint8_t *uid, uint8_t uidLen, uint8_t block, uint8_t keyType) {
  for (uint8_t k = 0; k < NUM_KNOWN_KEYS; k++) {
    if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, keyType, (uint8_t *)KNOWN_KEYS[k])) {
      return k;
    }
    reselectCard();
  }
  return -1;
}

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
    int8_t keyA = tryAuthBlock(uid, uidLen, firstBlock, 0);
    if (keyA >= 0) {
      for (uint8_t i = 0; i < 6; i++) {
        printHex(KNOWN_KEYS[keyA][i]);
        if (i < 5) Serial.print(":");
      }
      Serial.print(" (A)");
    } else {
      Serial.print("-- none matched --    ");
    }

    Serial.print(" | ");

    // Try Key B (type 1)
    int8_t keyB = tryAuthBlock(uid, uidLen, firstBlock, 1);
    if (keyB >= 0) {
      for (uint8_t i = 0; i < 6; i++) {
        printHex(KNOWN_KEYS[keyB][i]);
        if (i < 5) Serial.print(":");
      }
      Serial.print(" (B)");
    } else {
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
      // Try all known keys with re-select between failures
      bool authenticated = (tryAuthBlock(uid, uidLen, block, 0) >= 0);
      if (!authenticated) {
        authenticated = (tryAuthBlock(uid, uidLen, block, 1) >= 0);
      }
      if (!authenticated) {
        uint8_t blocksInSector = (block < 128) ? 4 : 16;
        for (uint8_t b = 0; b < blocksInSector && (block + b) < totalBlocks; b++) {
          Serial.print("  ");
          if ((block + b) < 10) Serial.print(" ");
          if ((block + b) < 100) Serial.print(" ");
          Serial.print(block + b);
          Serial.println(" | AUTH FAILED (no known key)                       |");
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

// ============================================================
// NDEF Parser
// ============================================================

// URI prefix lookup table per NFC Forum URI RTD specification
const char *URI_PREFIXES[] = {
  "",                           // 0x00
  "http://www.",                // 0x01
  "https://www.",               // 0x02
  "http://",                    // 0x03
  "https://",                   // 0x04
  "tel:",                       // 0x05
  "mailto:",                    // 0x06
  "ftp://anonymous:anonymous@", // 0x07
  "ftp://ftp.",                 // 0x08
  "ftps://",                    // 0x09
  "sftp://",                    // 0x0A
  "smb://",                     // 0x0B
  "nfs://",                     // 0x0C
  "ftp://",                     // 0x0D
  "dav://",                     // 0x0E
  "news:",                      // 0x0F
  "telnet://",                  // 0x10
  "imap:",                      // 0x11
  "rtsp://",                    // 0x12
  "urn:",                       // 0x13
  "pop:",                       // 0x14
  "sip:",                       // 0x15
  "sips:",                      // 0x16
  "tftp:",                      // 0x17
  "btspp://",                   // 0x18
  "btl2cap://",                 // 0x19
  "btgoep://",                  // 0x1A
  "tcpobex://",                 // 0x1B
  "irdaobex://",                // 0x1C
  "file://",                    // 0x1D
  "urn:epc:id:",                // 0x1E
  "urn:epc:tag:",               // 0x1F
  "urn:epc:pat:",               // 0x20
  "urn:epc:raw:",               // 0x21
  "urn:epc:",                   // 0x22
  "urn:nfc:",                   // 0x23
};
const uint8_t NUM_URI_PREFIXES = sizeof(URI_PREFIXES) / sizeof(URI_PREFIXES[0]);

// Parse and print a single NDEF record from a buffer
// Returns number of bytes consumed, or 0 on error
uint16_t parseNdefRecord(uint8_t *buf, uint16_t bufLen, uint8_t recordNum) {
  if (bufLen < 3) return 0;

  uint8_t header = buf[0];
  bool mb = header & 0x80;  // Message Begin
  bool me = header & 0x40;  // Message End
  bool cf = header & 0x20;  // Chunk Flag
  bool sr = header & 0x10;  // Short Record
  bool il = header & 0x08;  // ID Length present
  uint8_t tnf = header & 0x07;  // Type Name Format

  uint8_t typeLen = buf[1];
  uint16_t offset = 2;

  // Payload length: 1 byte if SR, 4 bytes otherwise
  uint32_t payloadLen;
  if (sr) {
    payloadLen = buf[offset++];
  } else {
    if (offset + 4 > bufLen) return 0;
    payloadLen = ((uint32_t)buf[offset] << 24) | ((uint32_t)buf[offset+1] << 16) |
                 ((uint32_t)buf[offset+2] << 8) | buf[offset+3];
    offset += 4;
  }

  // ID length
  uint8_t idLen = 0;
  if (il) {
    idLen = buf[offset++];
  }

  // Type
  uint8_t *type = buf + offset;
  offset += typeLen;

  // ID (skip)
  offset += idLen;

  // Payload
  uint8_t *payload = buf + offset;
  if (offset + payloadLen > bufLen) {
    payloadLen = bufLen - offset;  // truncate
  }

  Serial.print("  Record #");
  Serial.println(recordNum);

  // TNF name
  Serial.print("    TNF: ");
  switch (tnf) {
    case 0x00: Serial.println("Empty"); break;
    case 0x01: Serial.println("NFC Forum well-known"); break;
    case 0x02: Serial.println("Media type (RFC 2046)"); break;
    case 0x03: Serial.println("Absolute URI"); break;
    case 0x04: Serial.println("NFC Forum external"); break;
    case 0x05: Serial.println("Unknown"); break;
    case 0x06: Serial.println("Unchanged"); break;
    default:   Serial.println("Reserved"); break;
  }

  // Print type
  if (typeLen > 0) {
    Serial.print("    Type: ");
    for (uint8_t i = 0; i < typeLen; i++) {
      Serial.print((char)type[i]);
    }
    Serial.println();
  }

  Serial.print("    Payload (");
  Serial.print(payloadLen);
  Serial.println(" bytes):");

  // Decode well-known types
  if (tnf == 0x01 && typeLen == 1 && type[0] == 'U' && payloadLen >= 1) {
    // URI record
    uint8_t prefixCode = payload[0];
    Serial.print("    URI: ");
    if (prefixCode < NUM_URI_PREFIXES) {
      Serial.print(URI_PREFIXES[prefixCode]);
    }
    for (uint32_t i = 1; i < payloadLen; i++) {
      Serial.print((char)payload[i]);
    }
    Serial.println();

  } else if (tnf == 0x01 && typeLen == 1 && type[0] == 'T' && payloadLen >= 3) {
    // Text record
    uint8_t statusByte = payload[0];
    uint8_t langLen = statusByte & 0x3F;
    bool isUtf16 = statusByte & 0x80;

    Serial.print("    Lang: ");
    for (uint8_t i = 1; i <= langLen && i < payloadLen; i++) {
      Serial.print((char)payload[i]);
    }
    Serial.println();

    Serial.print("    Text: ");
    if (!isUtf16) {
      for (uint32_t i = 1 + langLen; i < payloadLen; i++) {
        Serial.print((char)payload[i]);
      }
    } else {
      Serial.print("(UTF-16 encoded, ");
      Serial.print(payloadLen - 1 - langLen);
      Serial.print(" bytes)");
    }
    Serial.println();

  } else if (tnf == 0x02) {
    // Media type - print as string if ASCII
    Serial.print("    Data: ");
    for (uint32_t i = 0; i < payloadLen && i < 128; i++) {
      Serial.print((payload[i] >= 0x20 && payload[i] <= 0x7E) ? (char)payload[i] : '.');
    }
    if (payloadLen > 128) Serial.print("...");
    Serial.println();

  } else {
    // Generic hex dump of payload (max 64 bytes)
    Serial.print("    Hex: ");
    for (uint32_t i = 0; i < payloadLen && i < 64; i++) {
      printHex(payload[i]);
      Serial.print(" ");
    }
    if (payloadLen > 64) Serial.print("...");
    Serial.println();
  }

  offset += payloadLen;
  return offset;
}

// Parse NDEF from Ultralight/NTAG TLV data (pages 4+)
void parseNdefUltralight(void) {
  // Read user data pages into a buffer (max ~200 pages x 4 bytes)
  // NTAG213=36 user pages, NTAG215=126, NTAG216=222
  uint8_t buf[232 * 4];
  uint16_t bufLen = 0;

  for (uint16_t page = 4; page < 232; page++) {
    if (!nfc.mifareultralight_ReadPage(page, buf + bufLen)) {
      break;
    }
    bufLen += 4;
  }

  if (bufLen == 0) {
    Serial.println("  (Could not read NDEF data area)");
    return;
  }

  Serial.println("  --- NDEF Records ---");

  // Parse TLV blocks
  uint16_t pos = 0;
  bool foundNdef = false;
  while (pos < bufLen) {
    uint8_t tlvType = buf[pos++];

    if (tlvType == 0x00) {
      continue;  // NULL TLV, skip
    }
    if (tlvType == 0xFE) {
      break;  // Terminator TLV
    }

    // Read length (1 or 3 bytes)
    if (pos >= bufLen) break;
    uint16_t tlvLen;
    if (buf[pos] == 0xFF) {
      if (pos + 2 >= bufLen) break;
      tlvLen = (buf[pos + 1] << 8) | buf[pos + 2];
      pos += 3;
    } else {
      tlvLen = buf[pos++];
    }

    if (tlvType == 0x03) {
      // NDEF Message TLV
      foundNdef = true;
      uint16_t ndefEnd = pos + tlvLen;
      if (ndefEnd > bufLen) ndefEnd = bufLen;

      uint8_t recordNum = 1;
      uint16_t ndefPos = pos;
      while (ndefPos < ndefEnd) {
        uint16_t consumed = parseNdefRecord(buf + ndefPos, ndefEnd - ndefPos, recordNum);
        if (consumed == 0) break;
        ndefPos += consumed;
        recordNum++;
      }
      pos = ndefEnd;
    } else {
      // Skip other TLV types
      pos += tlvLen;
    }
  }

  if (!foundNdef) {
    Serial.println("  (No NDEF message found - tag may not be NDEF formatted)");
  }
}

// Parse NDEF from MIFARE Classic (using MAD - MIFARE Application Directory)
void parseNdefClassic(uint8_t *uid, uint8_t uidLen) {
  // MAD is in sector 0, blocks 1-2
  // First check if sector 0 uses MAD key A (A0:A1:A2:A3:A4:A5)
  uint8_t madKeyA[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
  uint8_t block1[16], block2[16];
  bool hasMad = false;

  // Try all known keys on sector 0 (block 0)
  if (tryAuthBlock(uid, uidLen, 0, 0) >= 0) {
    if (nfc.mifareclassic_ReadDataBlock(1, block1) &&
        nfc.mifareclassic_ReadDataBlock(2, block2)) {
      hasMad = true;
    }
  }

  Serial.println("  --- NDEF Records ---");

  if (!hasMad) {
    Serial.println("  (Could not read MAD - no NDEF on this Classic tag)");
    return;
  }

  // MAD entries: block1[0]=CRC, block1[1]=info, block1[2..15] = AID for sectors 1-7
  // block2[0..15] = AID for sectors 8-15
  // NDEF AID = 0x03E1

  // Collect sectors that contain NDEF data
  uint8_t ndefSectors[15];
  uint8_t numNdefSectors = 0;

  // MAD1 entries for sectors 1-15 (2 bytes each)
  // block1 bytes 2-15 = sectors 1-7 (7 entries = 14 bytes)
  for (uint8_t i = 0; i < 7; i++) {
    uint16_t aid = (block1[2 + i * 2] << 8) | block1[2 + i * 2 + 1];
    if (aid == 0x03E1) {
      ndefSectors[numNdefSectors++] = i + 1;
    }
  }
  // block2 bytes 0-15 = sectors 8-15 (8 entries = 16 bytes)
  for (uint8_t i = 0; i < 8; i++) {
    uint16_t aid = (block2[i * 2] << 8) | block2[i * 2 + 1];
    if (aid == 0x03E1) {
      ndefSectors[numNdefSectors++] = i + 8;
    }
  }

  if (numNdefSectors == 0) {
    Serial.println("  (MAD present but no NDEF application found)");
    return;
  }

  // Read NDEF data from identified sectors
  // NDEF key for data sectors is D3:F7:D3:F7:D3:F7
  uint8_t ndefKey[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
  uint8_t ndefBuf[15 * 3 * 16];  // max 15 sectors x 3 data blocks x 16 bytes
  uint16_t ndefLen = 0;

  for (uint8_t s = 0; s < numNdefSectors; s++) {
    uint8_t firstBlock = ndefSectors[s] * 4;
    // Try all known keys on this sector
    if (tryAuthBlock(uid, uidLen, firstBlock, 0) < 0) {
      continue;
    }
    // Read 3 data blocks (skip trailer)
    for (uint8_t b = 0; b < 3; b++) {
      if (nfc.mifareclassic_ReadDataBlock(firstBlock + b, ndefBuf + ndefLen)) {
        ndefLen += 16;
      }
    }
  }

  if (ndefLen == 0) {
    Serial.println("  (Could not read NDEF sectors)");
    return;
  }

  // Parse TLV in the NDEF data (same format as Ultralight)
  uint16_t pos = 0;
  bool foundNdef = false;
  while (pos < ndefLen) {
    uint8_t tlvType = ndefBuf[pos++];
    if (tlvType == 0x00) continue;
    if (tlvType == 0xFE) break;

    if (pos >= ndefLen) break;
    uint16_t tlvLen;
    if (ndefBuf[pos] == 0xFF) {
      if (pos + 2 >= ndefLen) break;
      tlvLen = (ndefBuf[pos + 1] << 8) | ndefBuf[pos + 2];
      pos += 3;
    } else {
      tlvLen = ndefBuf[pos++];
    }

    if (tlvType == 0x03) {
      foundNdef = true;
      uint16_t ndefEnd = pos + tlvLen;
      if (ndefEnd > ndefLen) ndefEnd = ndefLen;

      uint8_t recordNum = 1;
      uint16_t ndefPos = pos;
      while (ndefPos < ndefEnd) {
        uint16_t consumed = parseNdefRecord(ndefBuf + ndefPos, ndefEnd - ndefPos, recordNum);
        if (consumed == 0) break;
        ndefPos += consumed;
        recordNum++;
      }
      pos = ndefEnd;
    } else {
      pos += tlvLen;
    }
  }

  if (!foundNdef) {
    Serial.println("  (No NDEF message in data sectors)");
  }
}

// ============================================================
// Serial helpers
// ============================================================

// Read a line from Serial with timeout (ms). Returns length, 0 on timeout.
uint8_t readSerialLine(char *buf, uint8_t maxLen, uint32_t timeoutMs) {
  uint32_t start = millis();
  uint8_t idx = 0;
  while (millis() - start < timeoutMs) {
    if (Serial.available()) {
      char c = Serial.read();
      if (c == '\n' || c == '\r') {
        if (idx > 0) break;
        continue;
      }
      if (idx < maxLen - 1) {
        buf[idx++] = c;
      }
    }
  }
  buf[idx] = '\0';
  return idx;
}

// Read an integer from Serial with a prompt. Returns -1 on timeout/invalid.
int readSerialInt(const char *prompt, uint32_t timeoutMs) {
  Serial.print(prompt);
  char buf[16];
  if (readSerialLine(buf, sizeof(buf), timeoutMs) == 0) return -1;
  Serial.println(buf);
  return atoi(buf);
}

// Parse a hex byte string like "FF" into a byte. Returns -1 if invalid.
int parseHexByte(const char *s) {
  if (strlen(s) < 2) return -1;
  char hi = toupper(s[0]), lo = toupper(s[1]);
  int val = 0;
  if (hi >= '0' && hi <= '9') val = (hi - '0') << 4;
  else if (hi >= 'A' && hi <= 'F') val = (hi - 'A' + 10) << 4;
  else return -1;
  if (lo >= '0' && lo <= '9') val |= (lo - '0');
  else if (lo >= 'A' && lo <= 'F') val |= (lo - 'A' + 10);
  else return -1;
  return val;
}

// ============================================================
// Feature 1: Write data to a MIFARE Classic block (exercise 4)
// ============================================================

void cmdWriteClassicBlock(uint8_t *uid, uint8_t uidLen) {
  Serial.println("\n  == Write Data to MIFARE Classic Block ==");

  int block = readSerialInt("  Block number (0-63): ", 30000);
  if (block < 0 || block > 255) {
    Serial.println("  Cancelled.");
    return;
  }

  // Warn about trailer blocks
  uint8_t posInSector = (block < 128) ? (block % 4) : (block % 16);
  uint8_t blocksInSector = (block < 128) ? 4 : 16;
  if (posInSector == blocksInSector - 1) {
    Serial.println("  WARNING: This is a sector trailer! Writing here changes keys/access bits.");
    Serial.print("  Are you sure? (y/n): ");
    char confirm[4];
    readSerialLine(confirm, sizeof(confirm), 15000);
    Serial.println(confirm);
    if (confirm[0] != 'y' && confirm[0] != 'Y') {
      Serial.println("  Cancelled.");
      return;
    }
  }

  Serial.println("  Enter 16 bytes as hex (e.g. 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35):");
  Serial.print("  > ");
  char hexInput[80];
  if (readSerialLine(hexInput, sizeof(hexInput), 60000) == 0) {
    Serial.println("  Cancelled (timeout).");
    return;
  }
  Serial.println(hexInput);

  // Parse hex bytes
  uint8_t data[16];
  memset(data, 0, 16);
  uint8_t byteCount = 0;
  char *tok = strtok(hexInput, " ,:");
  while (tok && byteCount < 16) {
    int val = parseHexByte(tok);
    if (val < 0) {
      Serial.print("  Invalid hex byte: ");
      Serial.println(tok);
      return;
    }
    data[byteCount++] = (uint8_t)val;
    tok = strtok(NULL, " ,:");
  }
  if (byteCount < 16) {
    Serial.print("  Only ");
    Serial.print(byteCount);
    Serial.println(" bytes entered, padding rest with 0x00.");
  }

  // Authenticate
  Serial.println("  Authenticating...");
  if (tryAuthBlock(uid, uidLen, block, 0) < 0 &&
      tryAuthBlock(uid, uidLen, block, 1) < 0) {
    Serial.println("  AUTH FAILED - cannot write.");
    return;
  }

  // Write
  if (nfc.mifareclassic_WriteDataBlock(block, data)) {
    Serial.print("  Block ");
    Serial.print(block);
    Serial.println(" written OK.");

    // Read back to verify
    uint8_t readback[16];
    if (nfc.mifareclassic_ReadDataBlock(block, readback)) {
      Serial.print("  Verify: ");
      for (uint8_t i = 0; i < 16; i++) {
        printHex(readback[i]);
        Serial.print(" ");
      }
      Serial.println();
    }
  } else {
    Serial.println("  WRITE FAILED.");
  }
}

// ============================================================
// Feature 2: Change Key A on a sector (exercise 5)
// ============================================================

void cmdChangeKey(uint8_t *uid, uint8_t uidLen) {
  Serial.println("\n  == Change Key A for a Sector ==");

  int sector = readSerialInt("  Sector number (0-15): ", 30000);
  if (sector < 0 || sector > 15) {
    Serial.println("  Cancelled.");
    return;
  }

  uint8_t trailerBlock = sector * 4 + 3;

  // Authenticate trailer block
  Serial.println("  Authenticating sector trailer...");
  int8_t authKey = tryAuthBlock(uid, uidLen, trailerBlock, 0);
  if (authKey < 0) {
    authKey = tryAuthBlock(uid, uidLen, trailerBlock, 1);
    if (authKey < 0) {
      Serial.println("  AUTH FAILED - cannot access trailer.");
      return;
    }
  }

  // Read current trailer
  uint8_t trailer[16];
  if (!nfc.mifareclassic_ReadDataBlock(trailerBlock, trailer)) {
    Serial.println("  Failed to read sector trailer.");
    return;
  }

  Serial.print("  Current trailer: ");
  for (uint8_t i = 0; i < 16; i++) {
    printHex(trailer[i]);
    Serial.print(" ");
  }
  Serial.println();
  Serial.println("  [bytes 0-5: KeyA | 6-9: Access bits | 10-15: KeyB]");

  Serial.println("  Enter new Key A (6 hex bytes, e.g. 0F 0F 0F 0F 0F 0F):");
  Serial.print("  > ");
  char hexInput[40];
  if (readSerialLine(hexInput, sizeof(hexInput), 60000) == 0) {
    Serial.println("  Cancelled.");
    return;
  }
  Serial.println(hexInput);

  uint8_t newKey[6];
  uint8_t byteCount = 0;
  char *tok = strtok(hexInput, " ,:");
  while (tok && byteCount < 6) {
    int val = parseHexByte(tok);
    if (val < 0) {
      Serial.print("  Invalid hex: ");
      Serial.println(tok);
      return;
    }
    newKey[byteCount++] = (uint8_t)val;
    tok = strtok(NULL, " ,:");
  }
  if (byteCount != 6) {
    Serial.println("  Need exactly 6 bytes for Key A.");
    return;
  }

  // Replace Key A (bytes 0-5), keep access bits (6-9) and Key B (10-15) unchanged
  memcpy(trailer, newKey, 6);

  Serial.print("  New trailer to write: ");
  for (uint8_t i = 0; i < 16; i++) {
    printHex(trailer[i]);
    Serial.print(" ");
  }
  Serial.println();

  Serial.print("  Confirm write? (y/n): ");
  char confirm[4];
  readSerialLine(confirm, sizeof(confirm), 15000);
  Serial.println(confirm);
  if (confirm[0] != 'y' && confirm[0] != 'Y') {
    Serial.println("  Cancelled.");
    return;
  }

  // Re-auth since reading may have changed state
  reselectCard();
  if (tryAuthBlock(uid, uidLen, trailerBlock, 0) < 0 &&
      tryAuthBlock(uid, uidLen, trailerBlock, 1) < 0) {
    Serial.println("  Re-auth failed.");
    return;
  }

  if (nfc.mifareclassic_WriteDataBlock(trailerBlock, trailer)) {
    Serial.print("  Sector ");
    Serial.print(sector);
    Serial.println(" Key A changed OK.");
    Serial.println("  IMPORTANT: Remember the new key or the sector becomes inaccessible!");
  } else {
    Serial.println("  WRITE FAILED.");
  }
}

// ============================================================
// Feature 3: Change access conditions on a sector (exercise 8)
// ============================================================

// Encode access bits for a single block. C1, C2, C3 are each 0 or 1.
// Returns the 3 access bytes (bytes 6,7,8 of the sector trailer).
void encodeAccessBits(uint8_t c1[4], uint8_t c2[4], uint8_t c3[4], uint8_t accessBytes[3]) {
  // Byte 6: ~C2_3 ~C2_2 ~C2_1 ~C2_0 ~C1_3 ~C1_2 ~C1_1 ~C1_0
  accessBytes[0] = ((~c2[3] & 1) << 7) | ((~c2[2] & 1) << 6) | ((~c2[1] & 1) << 5) | ((~c2[0] & 1) << 4) |
                   ((~c1[3] & 1) << 3) | ((~c1[2] & 1) << 2) | ((~c1[1] & 1) << 1) | (~c1[0] & 1);
  // Byte 7: C1_3 C1_2 C1_1 C1_0 ~C3_3 ~C3_2 ~C3_1 ~C3_0
  accessBytes[1] = ((c1[3] & 1) << 7) | ((c1[2] & 1) << 6) | ((c1[1] & 1) << 5) | ((c1[0] & 1) << 4) |
                   ((~c3[3] & 1) << 3) | ((~c3[2] & 1) << 2) | ((~c3[1] & 1) << 1) | (~c3[0] & 1);
  // Byte 8: C3_3 C3_2 C3_1 C3_0 C2_3 C2_2 C2_1 C2_0
  accessBytes[2] = ((c3[3] & 1) << 7) | ((c3[2] & 1) << 6) | ((c3[1] & 1) << 5) | ((c3[0] & 1) << 4) |
                   ((c2[3] & 1) << 3) | ((c2[2] & 1) << 2) | ((c2[1] & 1) << 1) | (c2[0] & 1);
}

void cmdChangeAccessBits(uint8_t *uid, uint8_t uidLen) {
  Serial.println("\n  == Change Access Conditions ==");
  Serial.println("  Presets:");
  Serial.println("    1 = Default (transport: key A|B read/write all)");
  Serial.println("    2 = Read-only with key A|B (no write)");
  Serial.println("    3 = Never read/write data blocks (hidden data)");
  Serial.println("    4 = Write with key B only, read with A|B");
  Serial.println("    5 = Custom (enter raw access bytes)");

  int sector = readSerialInt("  Sector number (0-15): ", 30000);
  if (sector < 0 || sector > 15) {
    Serial.println("  Cancelled.");
    return;
  }

  int preset = readSerialInt("  Preset (1-5): ", 30000);
  if (preset < 1 || preset > 5) {
    Serial.println("  Cancelled.");
    return;
  }

  uint8_t trailerBlock = sector * 4 + 3;

  // Authenticate
  Serial.println("  Authenticating...");
  if (tryAuthBlock(uid, uidLen, trailerBlock, 0) < 0 &&
      tryAuthBlock(uid, uidLen, trailerBlock, 1) < 0) {
    Serial.println("  AUTH FAILED.");
    return;
  }

  // Read current trailer
  uint8_t trailer[16];
  if (!nfc.mifareclassic_ReadDataBlock(trailerBlock, trailer)) {
    Serial.println("  Failed to read trailer.");
    return;
  }

  uint8_t accessBytes[3];

  if (preset == 5) {
    // Custom: enter 3 raw bytes
    Serial.println("  Enter 3 access bytes hex (e.g. FF 07 80):");
    Serial.print("  > ");
    char hexInput[20];
    if (readSerialLine(hexInput, sizeof(hexInput), 60000) == 0) {
      Serial.println("  Cancelled.");
      return;
    }
    Serial.println(hexInput);
    uint8_t cnt = 0;
    char *tok = strtok(hexInput, " ,:");
    while (tok && cnt < 3) {
      int val = parseHexByte(tok);
      if (val < 0) { Serial.println("  Invalid hex."); return; }
      accessBytes[cnt++] = (uint8_t)val;
      tok = strtok(NULL, " ,:");
    }
    if (cnt != 3) { Serial.println("  Need 3 bytes."); return; }
  } else {
    // C1, C2, C3 for blocks 0,1,2,3 (block 3 = trailer)
    uint8_t c1[4], c2[4], c3[4];
    switch (preset) {
      case 1: // Default transport: C1=C2=C3=0 for data, trailer C1=0 C2=0 C3=1
        c1[0]=0; c2[0]=0; c3[0]=0;  // block 0: key A|B r/w
        c1[1]=0; c2[1]=0; c3[1]=0;  // block 1
        c1[2]=0; c2[2]=0; c3[2]=0;  // block 2
        c1[3]=0; c2[3]=0; c3[3]=1;  // trailer: key A write, key A read access, key A r/w key B
        break;
      case 2: // Read-only: C1=0 C2=1 C3=0 for data
        c1[0]=0; c2[0]=1; c3[0]=0;
        c1[1]=0; c2[1]=1; c3[1]=0;
        c1[2]=0; c2[2]=1; c3[2]=0;
        c1[3]=0; c2[3]=0; c3[3]=1;  // trailer: manageable with key A
        break;
      case 3: // Never read/write data: C1=1 C2=1 C3=1
        c1[0]=1; c2[0]=1; c3[0]=1;
        c1[1]=1; c2[1]=1; c3[1]=1;
        c1[2]=1; c2[2]=1; c3[2]=1;
        c1[3]=0; c2[3]=0; c3[3]=1;  // keep trailer accessible with key A
        break;
      case 4: // Write key B only: C1=1 C2=0 C3=0 data
        c1[0]=1; c2[0]=0; c3[0]=0;
        c1[1]=1; c2[1]=0; c3[1]=0;
        c1[2]=1; c2[2]=0; c3[2]=0;
        c1[3]=0; c2[3]=0; c3[3]=1;
        break;
      default:
        Serial.println("  Invalid preset.");
        return;
    }
    encodeAccessBits(c1, c2, c3, accessBytes);
  }

  // Update trailer bytes 6,7,8 with new access bits (keep byte 9 / user data)
  trailer[6] = accessBytes[0];
  trailer[7] = accessBytes[1];
  trailer[8] = accessBytes[2];

  Serial.print("  New trailer: ");
  for (uint8_t i = 0; i < 16; i++) {
    printHex(trailer[i]);
    Serial.print(" ");
  }
  Serial.println();
  Serial.print("  Access bytes: ");
  printHex(accessBytes[0]); Serial.print(" ");
  printHex(accessBytes[1]); Serial.print(" ");
  printHex(accessBytes[2]); Serial.println();

  Serial.print("  Confirm write? (y/n): ");
  char confirm[4];
  readSerialLine(confirm, sizeof(confirm), 15000);
  Serial.println(confirm);
  if (confirm[0] != 'y' && confirm[0] != 'Y') {
    Serial.println("  Cancelled.");
    return;
  }

  reselectCard();
  if (tryAuthBlock(uid, uidLen, trailerBlock, 0) < 0 &&
      tryAuthBlock(uid, uidLen, trailerBlock, 1) < 0) {
    Serial.println("  Re-auth failed.");
    return;
  }

  if (nfc.mifareclassic_WriteDataBlock(trailerBlock, trailer)) {
    Serial.print("  Sector ");
    Serial.print(sector);
    Serial.println(" access conditions updated OK.");
  } else {
    Serial.println("  WRITE FAILED.");
  }
}

// ============================================================
// Feature 4: Format Classic for NDEF + write URI (exercise 9)
// ============================================================

void cmdFormatNdefClassic(uint8_t *uid, uint8_t uidLen) {
  Serial.println("\n  == Format MIFARE Classic for NDEF + Write URI ==");
  Serial.println("  WARNING: This will overwrite sector 0 (MAD) and a data sector!");

  Serial.println("  NDEF URI prefixes:");
  Serial.println("    0 = (none)     1 = http://www.   2 = https://www.");
  Serial.println("    3 = http://    4 = https://      5 = tel:");
  Serial.println("    6 = mailto:");

  int prefix = readSerialInt("  URI prefix code (0-6): ", 30000);
  if (prefix < 0 || prefix > 0x23) {
    Serial.println("  Cancelled.");
    return;
  }

  Serial.println("  Enter URL/text (max 38 chars, without prefix):");
  Serial.print("  > ");
  char url[48];
  if (readSerialLine(url, sizeof(url), 60000) == 0) {
    Serial.println("  Cancelled.");
    return;
  }
  Serial.println(url);

  if (strlen(url) < 1 || strlen(url) > 38) {
    Serial.println("  URL must be 1-38 characters.");
    return;
  }

  Serial.print("  Will write: ");
  if (prefix < NUM_URI_PREFIXES) Serial.print(URI_PREFIXES[prefix]);
  Serial.println(url);

  Serial.print("  Confirm? (y/n): ");
  char confirm[4];
  readSerialLine(confirm, sizeof(confirm), 15000);
  Serial.println(confirm);
  if (confirm[0] != 'y' && confirm[0] != 'Y') {
    Serial.println("  Cancelled.");
    return;
  }

  // Step 1: Authenticate sector 0 with default key
  Serial.println("  Authenticating sector 0...");
  uint8_t defaultKey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 0, 0, defaultKey)) {
    Serial.println("  Cannot auth sector 0. Already formatted?");
    // Try MAD key
    uint8_t madKey[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    reselectCard();
    if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 0, 0, madKey)) {
      Serial.println("  Cannot auth sector 0 with MAD key either. Aborting.");
      return;
    }
    Serial.println("  (Authenticated with MAD key - card may already be formatted)");
  }

  // Step 2: Format sector 0 as MAD
  Serial.println("  Formatting sector 0 (MAD)...");
  if (!nfc.mifareclassic_FormatNDEF()) {
    Serial.println("  FormatNDEF failed.");
    return;
  }
  Serial.println("  MAD written to sector 0.");

  // Step 3: Authenticate sector 1 and write NDEF URI
  Serial.println("  Authenticating sector 1...");
  reselectCard();
  if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 4, 0, defaultKey)) {
    // Try NDEF key since FormatNDEF may have changed things
    uint8_t ndefKey[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
    reselectCard();
    if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 4, 0, ndefKey)) {
      Serial.println("  Cannot auth sector 1. Aborting.");
      return;
    }
  }

  Serial.println("  Writing NDEF URI to sector 1...");
  if (nfc.mifareclassic_WriteNDEFURI(1, (uint8_t)prefix, url)) {
    Serial.println("  NDEF URI written OK!");
    Serial.println("  Tap this card on an NFC phone to trigger the action.");
  } else {
    Serial.println("  WriteNDEFURI failed.");
  }
}

// ============================================================
// Feature 5: Ultralight C 3DES Authentication (agenda item)
// ============================================================

// Rotate a buffer left by 8 bits (1 byte)
static void rotateLeft8(uint8_t *buf, uint8_t len) {
  if (len < 2) return;
  uint8_t first = buf[0];
  memmove(buf, buf + 1, len - 1);
  buf[len - 1] = first;
}

// 2-key 3DES CBC encrypt (8 bytes at a time)
static void des3CbcEncrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint8_t len) {
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set2key_enc(&ctx, key);
  mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len, iv, data, data);
  mbedtls_des3_free(&ctx);
}

// 2-key 3DES CBC decrypt (8 bytes at a time)
static void des3CbcDecrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint8_t len) {
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set2key_dec(&ctx, key);
  mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, len, iv, data, data);
  mbedtls_des3_free(&ctx);
}

bool authenticateUltralightC(uint8_t *key16) {
  // Step 1: Send AUTHENTICATE command (0x1A, 0x00)
  uint8_t cmd1[2] = {0x1A, 0x00};
  uint8_t response[32];
  uint8_t respLen = sizeof(response);

  if (!nfc.inDataExchange(cmd1, 2, response, &respLen)) {
    Serial.println("  Auth step 1 failed (no response).");
    return false;
  }

  // Response should be: AF + 8 bytes (ek(RndB))
  if (respLen < 9 || response[0] != 0xAF) {
    Serial.println("  Auth step 1: unexpected response.");
    return false;
  }

  uint8_t ekRndB[8];
  memcpy(ekRndB, response + 1, 8);

  // Decrypt ek(RndB) to get RndB
  uint8_t iv[8];
  memset(iv, 0, 8);
  uint8_t rndB[8];
  memcpy(rndB, ekRndB, 8);
  des3CbcDecrypt(key16, iv, rndB, 8);

  // Generate RndA (random 8 bytes)
  uint8_t rndA[8];
  for (int i = 0; i < 8; i++) rndA[i] = (uint8_t)esp_random();

  // Compute RndB' = rotate RndB left by 8 bits
  uint8_t rndBprime[8];
  memcpy(rndBprime, rndB, 8);
  rotateLeft8(rndBprime, 8);

  // Concatenate RndA || RndB'
  uint8_t concat[16];
  memcpy(concat, rndA, 8);
  memcpy(concat + 8, rndBprime, 8);

  // Encrypt with IV = ek(RndB) (the original encrypted bytes)
  uint8_t iv2[8];
  memcpy(iv2, ekRndB, 8);
  des3CbcEncrypt(key16, iv2, concat, 16);

  // Step 3: Send AF + encrypted(RndA || RndB')
  uint8_t cmd2[17];
  cmd2[0] = 0xAF;
  memcpy(cmd2 + 1, concat, 16);
  respLen = sizeof(response);

  if (!nfc.inDataExchange(cmd2, 17, response, &respLen)) {
    Serial.println("  Auth step 3 failed (no response).");
    return false;
  }

  // Response should be: 00 + 8 bytes (ek(RndA'))
  if (respLen < 9 || response[0] != 0x00) {
    Serial.println("  Auth step 3: rejected (wrong key?).");
    return false;
  }

  // Verify: decrypt the response to get RndA', compare with rotate(RndA)
  uint8_t ekRndAprime[8];
  memcpy(ekRndAprime, response + 1, 8);
  uint8_t iv3[8];
  memcpy(iv3, concat + 8, 8);  // IV = last 8 bytes sent
  des3CbcDecrypt(key16, iv3, ekRndAprime, 8);

  uint8_t rndAprime[8];
  memcpy(rndAprime, rndA, 8);
  rotateLeft8(rndAprime, 8);

  if (memcmp(ekRndAprime, rndAprime, 8) != 0) {
    Serial.println("  Auth verification failed (RndA' mismatch).");
    return false;
  }

  return true;
}

void cmdAuthUltralightC(void) {
  Serial.println("\n  == Ultralight C 3DES Authentication ==");
  Serial.println("  Default key: 49 45 4D 4B 41 45 52 42 21 4E 41 43 55 4F 59 46");
  Serial.println("               (\"IEMKAERB!NACUOYF\" = \"BREAKMEIFYOUCAN!\" reversed)");

  Serial.println("  Use default key? (y/n): ");
  char choice[4];
  readSerialLine(choice, sizeof(choice), 15000);
  Serial.println(choice);

  uint8_t key[16];

  if (choice[0] == 'n' || choice[0] == 'N') {
    Serial.println("  Enter 16-byte key as hex:");
    Serial.print("  > ");
    char hexInput[64];
    if (readSerialLine(hexInput, sizeof(hexInput), 60000) == 0) {
      Serial.println("  Cancelled.");
      return;
    }
    Serial.println(hexInput);
    uint8_t cnt = 0;
    char *tok = strtok(hexInput, " ,:");
    while (tok && cnt < 16) {
      int val = parseHexByte(tok);
      if (val < 0) { Serial.println("  Invalid hex."); return; }
      key[cnt++] = (uint8_t)val;
      tok = strtok(NULL, " ,:");
    }
    if (cnt != 16) {
      Serial.println("  Need exactly 16 bytes.");
      return;
    }
  } else {
    // Default Ultralight C key (reverse of "BREAKMEIFYOUCAN!")
    uint8_t defaultKey[16] = {
      0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42,
      0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46
    };
    memcpy(key, defaultKey, 16);
  }

  Serial.print("  Key: ");
  for (int i = 0; i < 16; i++) {
    printHex(key[i]);
    Serial.print(" ");
  }
  Serial.println();

  Serial.println("  Authenticating...");
  if (authenticateUltralightC(key)) {
    Serial.println("  3DES Authentication SUCCESS!");
  } else {
    Serial.println("  3DES Authentication FAILED.");
  }
}

// ============================================================
// Interactive menu
// ============================================================

void printMenu(TagType type) {
  Serial.println("\n  --- Actions Menu ---");
  Serial.println("  0 = Scan next tag (exit menu)");
  if (type == TAG_MIFARE_CLASSIC_1K || type == TAG_MIFARE_CLASSIC_4K) {
    Serial.println("  1 = Write data to a block");
    Serial.println("  2 = Change Key A on a sector");
    Serial.println("  3 = Change access conditions on a sector");
    Serial.println("  4 = Format for NDEF + write URI");
  }
  if (type == TAG_MIFARE_ULTRALIGHT) {
    Serial.println("  5 = Authenticate Ultralight C (3DES)");
  }
  Serial.print("  Choice: ");
}

// Run the interactive menu. Returns when user chooses 0 or timeout.
void interactiveMenu(uint8_t *uid, uint8_t uidLen, TagInfo tag) {
  while (true) {
    printMenu(tag.type);
    char buf[4];
    if (readSerialLine(buf, sizeof(buf), 60000) == 0) {
      Serial.println("\n  (Timeout - returning to scan mode)");
      break;
    }
    Serial.println(buf);
    int choice = atoi(buf);

    if (choice == 0) break;

    if (tag.type == TAG_MIFARE_CLASSIC_1K || tag.type == TAG_MIFARE_CLASSIC_4K) {
      switch (choice) {
        case 1: cmdWriteClassicBlock(uid, uidLen); break;
        case 2: cmdChangeKey(uid, uidLen); break;
        case 3: cmdChangeAccessBits(uid, uidLen); break;
        case 4: cmdFormatNdefClassic(uid, uidLen); break;
        default: Serial.println("  Invalid choice."); break;
      }
    } else if (tag.type == TAG_MIFARE_ULTRALIGHT) {
      if (choice == 5) {
        cmdAuthUltralightC();
      } else {
        Serial.println("  Invalid choice.");
      }
    }

    // Re-select card for next operation
    reselectCard();
  }
}

// ============================================================
// Setup & Loop
// ============================================================

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

    // Memory dump, key audit, and NDEF parsing based on tag type
    if (tag.type == TAG_MIFARE_CLASSIC_1K || tag.type == TAG_MIFARE_CLASSIC_4K) {
      dumpMifareClassic(uid, uidLength, tag.type);
      Serial.println();
      testClassicKeys(uid, uidLength, tag.type);
      Serial.println();
      parseNdefClassic(uid, uidLength);
    } else if (tag.type == TAG_MIFARE_ULTRALIGHT) {
      dumpUltralight();
      Serial.println();
      parseNdefUltralight();
    } else {
      Serial.println("  (Memory dump not supported for this tag type)");
    }

    // Show interactive menu for write operations
    interactiveMenu(uid, uidLength, tag);

    Serial.println("\nReady. Scan a tag...\n");
    delay(1000);
  }
}
