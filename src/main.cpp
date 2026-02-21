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
      // Try all known keys (A and B) until one works
      bool authenticated = false;
      for (uint8_t k = 0; k < NUM_KNOWN_KEYS && !authenticated; k++) {
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, 0, (uint8_t *)KNOWN_KEYS[k])) {
          authenticated = true;
        } else if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, 1, (uint8_t *)KNOWN_KEYS[k])) {
          authenticated = true;
        }
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

  // Try MAD key first, then default key
  if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 1, 0, madKeyA) ||
      nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 1, 0, (uint8_t *)KNOWN_KEYS[0])) {
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
    // Try NDEF key, then default
    if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLen, firstBlock, 0, ndefKey) &&
        !nfc.mifareclassic_AuthenticateBlock(uid, uidLen, firstBlock, 0, (uint8_t *)KNOWN_KEYS[0])) {
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

    Serial.println();
    delay(2000);
  }
}
