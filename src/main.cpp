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

// ============================================================
// Tag types and identification
// ============================================================

enum TagType {
  TAG_MIFARE_CLASSIC_1K,
  TAG_MIFARE_CLASSIC_4K,
  TAG_MIFARE_ULTRALIGHT,
  TAG_MIFARE_PLUS,
  TAG_MIFARE_DESFIRE,
  TAG_ISO14443_4,
  TAG_UNKNOWN
};

struct TagInfo {
  TagType type;
  const char *name;
  uint16_t atqa;
  uint8_t sak;
  uint8_t uid[7];
  uint8_t uidLen;
};

// Currently scanned tag (persists between commands)
TagInfo currentTag;
bool hasTag = false;

// Clone buffer
uint8_t cloneBuf[1024];  // enough for Classic 1K (64 blocks x 16 bytes)
uint16_t cloneLen = 0;
TagType cloneType = TAG_UNKNOWN;
uint8_t cloneUid[7];
uint8_t cloneUidLen = 0;

TagInfo identifyTag(uint16_t atqa, uint8_t sak, uint8_t *uid, uint8_t uidLen) {
  TagInfo info;
  info.atqa = atqa;
  info.sak = sak;
  info.uidLen = uidLen;
  memcpy(info.uid, uid, uidLen);

  if (sak == 0x08 || sak == 0x09) {
    info.type = (sak == 0x09) ? TAG_MIFARE_CLASSIC_1K : TAG_MIFARE_CLASSIC_1K;
    info.name = (sak == 0x09) ? "MIFARE Classic Mini" : "MIFARE Classic 1K";
  } else if (sak == 0x18) {
    info.type = TAG_MIFARE_CLASSIC_4K;
    info.name = "MIFARE Classic 4K";
  } else if (sak == 0x00) {
    info.type = TAG_MIFARE_ULTRALIGHT;
    info.name = (uidLen == 7) ? "MIFARE Ultralight / NTAG" : "MIFARE Ultralight";
  } else if (sak == 0x10 || sak == 0x11) {
    info.type = TAG_MIFARE_PLUS;
    info.name = (sak == 0x10) ? "MIFARE Plus 2K" : "MIFARE Plus 4K";
  } else if (sak == 0x20 && (atqa & 0x0F) == 0x03) {
    info.type = TAG_MIFARE_DESFIRE;
    info.name = "MIFARE DESFire";
  } else if (sak == 0x20) {
    info.type = TAG_ISO14443_4;
    info.name = "ISO 14443-4";
  } else {
    info.type = TAG_UNKNOWN;
    info.name = "Unknown";
  }
  return info;
}

// ============================================================
// Helpers
// ============================================================

void printHex(uint8_t val) {
  if (val < 0x10) Serial.print("0");
  Serial.print(val, HEX);
}

void printUid(uint8_t *uid, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    printHex(uid[i]);
    if (i < len - 1) Serial.print(":");
  }
}

// Common MIFARE Classic keys
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

bool reselectCard(void) {
  uint8_t uid[7];
  uint8_t uidLen;
  return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 500);
}

int8_t tryAuthBlock(uint8_t *uid, uint8_t uidLen, uint8_t block, uint8_t keyType) {
  for (uint8_t k = 0; k < NUM_KNOWN_KEYS; k++) {
    if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, keyType, (uint8_t *)KNOWN_KEYS[k])) {
      return k;
    }
    reselectCard();
  }
  return -1;
}

// ============================================================
// Command: SCAN
// ============================================================

void cmdScan() {
  Serial.println("Place tag on reader...");
  uint8_t uid[7];
  uint8_t uidLen;

  // Wait up to 10 seconds
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 10000)) {
    Serial.println("No tag found.");
    return;
  }

  uint16_t atqa = (pn532_packetbuffer[9] << 8) | pn532_packetbuffer[10];
  uint8_t sak = pn532_packetbuffer[11];

  currentTag = identifyTag(atqa, sak, uid, uidLen);
  hasTag = true;

  Serial.print("Tag: ");
  Serial.println(currentTag.name);
  Serial.print("  UID (");
  Serial.print(uidLen);
  Serial.print("): ");
  printUid(uid, uidLen);
  Serial.println();
  Serial.print("  ATQA: 0x");
  if (atqa < 0x1000) Serial.print("0");
  if (atqa < 0x100) Serial.print("0");
  if (atqa < 0x10) Serial.print("0");
  Serial.print(atqa, HEX);
  Serial.print("  SAK: 0x");
  printHex(sak);
  Serial.println();
}

// ============================================================
// Command: DUMP
// ============================================================

void dumpClassic(uint8_t *uid, uint8_t uidLen, TagType type) {
  uint16_t totalBlocks = (type == TAG_MIFARE_CLASSIC_4K) ? 256 : 64;
  uint8_t data[16];

  Serial.println("--- MIFARE Classic Memory Dump ---");
  Serial.println("Blk | Data                                          | ASCII");
  Serial.println("----+--------------------------------------------------+------------------");

  for (uint16_t block = 0; block < totalBlocks; block++) {
    uint16_t sectorFirst = (block < 128) ? (block - (block % 4)) : (block - (block % 16));

    if (block == sectorFirst) {
      bool auth = (tryAuthBlock(uid, uidLen, block, 0) >= 0);
      if (!auth) auth = (tryAuthBlock(uid, uidLen, block, 1) >= 0);
      if (!auth) {
        uint16_t blocksInSector = (block < 128) ? 4 : 16;
        for (uint16_t b = 0; b < blocksInSector && (block + b) < totalBlocks; b++) {
          Serial.print(" ");
          if ((block + b) < 10) Serial.print(" ");
          if ((block + b) < 100) Serial.print(" ");
          Serial.print(block + b);
          Serial.println(" | AUTH FAILED                                      |");
        }
        block = sectorFirst + ((block < 128) ? 3 : 15);
        continue;
      }
    }

    if (nfc.mifareclassic_ReadDataBlock(block, data)) {
      if (block < 10) Serial.print(" ");
      if (block < 100) Serial.print(" ");
      Serial.print(block);
      Serial.print(" | ");
      for (uint8_t i = 0; i < 16; i++) { printHex(data[i]); Serial.print(" "); }
      Serial.print("| ");
      for (uint8_t i = 0; i < 16; i++) {
        Serial.print((data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.');
      }
      Serial.println();
    } else {
      if (block < 10) Serial.print(" ");
      if (block < 100) Serial.print(" ");
      Serial.print(block);
      Serial.println(" | READ ERROR                                        |");
    }
  }
}

void dumpUltralight() {
  uint8_t data[4];

  Serial.println("--- Ultralight / NTAG Memory Dump ---");
  Serial.println("Page | Data        | ASCII");
  Serial.println("-----+-------------+------");

  for (uint16_t page = 0; page < 231; page++) {
    if (!nfc.mifareultralight_ReadPage(page, data)) break;

    if (page < 10) Serial.print(" ");
    if (page < 100) Serial.print(" ");
    Serial.print(page);
    Serial.print("  | ");
    for (uint8_t i = 0; i < 4; i++) { printHex(data[i]); Serial.print(" "); }
    Serial.print("| ");
    for (uint8_t i = 0; i < 4; i++) {
      Serial.print((data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.');
    }
    Serial.println();
  }
}

void cmdDump() {
  if (!hasTag) { Serial.println("No tag scanned. Run SCAN first."); return; }

  Serial.println("Hold tag on reader for dump...");
  if (!reselectCard()) { Serial.println("Tag not present."); return; }

  if (currentTag.type == TAG_MIFARE_CLASSIC_1K || currentTag.type == TAG_MIFARE_CLASSIC_4K) {
    dumpClassic(currentTag.uid, currentTag.uidLen, currentTag.type);
  } else if (currentTag.type == TAG_MIFARE_ULTRALIGHT) {
    dumpUltralight();
  } else {
    Serial.println("Dump not supported for this tag type.");
  }
}

// ============================================================
// Command: KEYS
// ============================================================

void cmdKeys() {
  if (!hasTag) { Serial.println("No tag scanned. Run SCAN first."); return; }
  if (currentTag.type != TAG_MIFARE_CLASSIC_1K && currentTag.type != TAG_MIFARE_CLASSIC_4K) {
    Serial.println("Key audit only applies to MIFARE Classic.");
    return;
  }

  Serial.println("Hold tag on reader for key audit...");
  if (!reselectCard()) { Serial.println("Tag not present."); return; }

  uint8_t numSectors = (currentTag.type == TAG_MIFARE_CLASSIC_4K) ? 40 : 16;

  Serial.println("--- MIFARE Classic Key Audit ---");
  Serial.println("Sect | Key A found              | Key B found");
  Serial.println("-----+--------------------------+--------------------------");

  for (uint8_t sector = 0; sector < numSectors; sector++) {
    uint8_t firstBlock = (sector < 32) ? sector * 4 : 128 + (sector - 32) * 16;

    if (sector < 10) Serial.print(" ");
    Serial.print(sector);
    Serial.print("   | ");

    int8_t keyA = tryAuthBlock(currentTag.uid, currentTag.uidLen, firstBlock, 0);
    if (keyA >= 0) {
      for (uint8_t i = 0; i < 6; i++) { printHex(KNOWN_KEYS[keyA][i]); if (i < 5) Serial.print(":"); }
      Serial.print(" (A)");
    } else {
      Serial.print("-- none matched --    ");
    }

    Serial.print(" | ");

    int8_t keyB = tryAuthBlock(currentTag.uid, currentTag.uidLen, firstBlock, 1);
    if (keyB >= 0) {
      for (uint8_t i = 0; i < 6; i++) { printHex(KNOWN_KEYS[keyB][i]); if (i < 5) Serial.print(":"); }
      Serial.print(" (B)");
    } else {
      Serial.print("-- none matched --");
    }
    Serial.println();
  }

  Serial.print("Keys tested: ");
  Serial.print(NUM_KNOWN_KEYS);
  Serial.println(" known keys x 2 (A+B) per sector");
}

// ============================================================
// NDEF Parser
// ============================================================

const char *URI_PREFIXES[] = {
  "", "http://www.", "https://www.", "http://", "https://",
  "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
  "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
  "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
  "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://",
  "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
  "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
};
const uint8_t NUM_URI_PREFIXES = sizeof(URI_PREFIXES) / sizeof(URI_PREFIXES[0]);

uint16_t parseNdefRecord(uint8_t *buf, uint16_t bufLen, uint8_t recordNum) {
  if (bufLen < 3) return 0;

  uint8_t header = buf[0];
  bool sr = header & 0x10;
  bool il = header & 0x08;
  uint8_t tnf = header & 0x07;
  uint8_t typeLen = buf[1];
  uint16_t offset = 2;

  uint32_t payloadLen;
  if (sr) {
    payloadLen = buf[offset++];
  } else {
    if (offset + 4 > bufLen) return 0;
    payloadLen = ((uint32_t)buf[offset] << 24) | ((uint32_t)buf[offset+1] << 16) |
                 ((uint32_t)buf[offset+2] << 8) | buf[offset+3];
    offset += 4;
  }

  uint8_t idLen = il ? buf[offset++] : 0;
  uint8_t *type = buf + offset;
  offset += typeLen;
  offset += idLen;
  uint8_t *payload = buf + offset;
  if (offset + payloadLen > bufLen) payloadLen = bufLen - offset;

  Serial.print("Record #");
  Serial.println(recordNum);

  Serial.print("  TNF: ");
  const char *tnfNames[] = {"Empty","Well-known","Media","Absolute URI","External","Unknown","Unchanged","Reserved"};
  Serial.println(tnfNames[tnf < 8 ? tnf : 7]);

  if (typeLen > 0) {
    Serial.print("  Type: ");
    for (uint8_t i = 0; i < typeLen; i++) Serial.print((char)type[i]);
    Serial.println();
  }

  if (tnf == 0x01 && typeLen == 1 && type[0] == 'U' && payloadLen >= 1) {
    uint8_t pc = payload[0];
    Serial.print("  URI: ");
    if (pc < NUM_URI_PREFIXES) Serial.print(URI_PREFIXES[pc]);
    for (uint32_t i = 1; i < payloadLen; i++) Serial.print((char)payload[i]);
    Serial.println();
  } else if (tnf == 0x01 && typeLen == 1 && type[0] == 'T' && payloadLen >= 3) {
    uint8_t langLen = payload[0] & 0x3F;
    Serial.print("  Lang: ");
    for (uint8_t i = 1; i <= langLen && i < payloadLen; i++) Serial.print((char)payload[i]);
    Serial.println();
    Serial.print("  Text: ");
    for (uint32_t i = 1 + langLen; i < payloadLen; i++) Serial.print((char)payload[i]);
    Serial.println();
  } else {
    Serial.print("  Data: ");
    for (uint32_t i = 0; i < payloadLen && i < 64; i++) {
      Serial.print((payload[i] >= 0x20 && payload[i] <= 0x7E) ? (char)payload[i] : '.');
    }
    if (payloadLen > 64) Serial.print("...");
    Serial.println();
  }

  return offset + payloadLen;
}

bool parseTlvNdef(uint8_t *buf, uint16_t bufLen) {
  uint16_t pos = 0;
  bool found = false;
  while (pos < bufLen) {
    uint8_t tlvType = buf[pos++];
    if (tlvType == 0x00) continue;
    if (tlvType == 0xFE) break;
    if (pos >= bufLen) break;

    uint16_t tlvLen;
    if (buf[pos] == 0xFF) {
      if (pos + 2 >= bufLen) break;
      tlvLen = (buf[pos+1] << 8) | buf[pos+2];
      pos += 3;
    } else {
      tlvLen = buf[pos++];
    }

    if (tlvType == 0x03) {
      found = true;
      uint16_t end = pos + tlvLen;
      if (end > bufLen) end = bufLen;
      uint8_t recNum = 1;
      uint16_t p = pos;
      while (p < end) {
        uint16_t c = parseNdefRecord(buf + p, end - p, recNum++);
        if (c == 0) break;
        p += c;
      }
      pos = end;
    } else {
      pos += tlvLen;
    }
  }
  return found;
}

void cmdNdef() {
  if (!hasTag) { Serial.println("No tag scanned. Run SCAN first."); return; }

  Serial.println("Hold tag on reader...");
  if (!reselectCard()) { Serial.println("Tag not present."); return; }

  Serial.println("--- NDEF Records ---");

  if (currentTag.type == TAG_MIFARE_ULTRALIGHT) {
    uint8_t buf[232 * 4];
    uint16_t bufLen = 0;
    for (uint16_t page = 4; page < 232; page++) {
      if (!nfc.mifareultralight_ReadPage(page, buf + bufLen)) break;
      bufLen += 4;
    }
    if (bufLen == 0 || !parseTlvNdef(buf, bufLen)) {
      Serial.println("No NDEF message found.");
    }

  } else if (currentTag.type == TAG_MIFARE_CLASSIC_1K || currentTag.type == TAG_MIFARE_CLASSIC_4K) {
    // Read MAD from sector 0
    if (tryAuthBlock(currentTag.uid, currentTag.uidLen, 0, 0) < 0) {
      Serial.println("Cannot read MAD (auth failed on sector 0).");
      return;
    }
    uint8_t block1[16], block2[16];
    if (!nfc.mifareclassic_ReadDataBlock(1, block1) || !nfc.mifareclassic_ReadDataBlock(2, block2)) {
      Serial.println("Cannot read MAD blocks.");
      return;
    }

    // Find NDEF sectors (AID 0x03E1)
    uint8_t ndefSectors[15];
    uint8_t numNdef = 0;
    for (uint8_t i = 0; i < 7; i++) {
      uint16_t aid = (block1[2 + i*2] << 8) | block1[2 + i*2 + 1];
      if (aid == 0x03E1) ndefSectors[numNdef++] = i + 1;
    }
    for (uint8_t i = 0; i < 8; i++) {
      uint16_t aid = (block2[i*2] << 8) | block2[i*2 + 1];
      if (aid == 0x03E1) ndefSectors[numNdef++] = i + 8;
    }

    if (numNdef == 0) { Serial.println("No NDEF application in MAD."); return; }

    uint8_t ndefBuf[720];
    uint16_t ndefLen = 0;
    for (uint8_t s = 0; s < numNdef; s++) {
      uint8_t fb = ndefSectors[s] * 4;
      if (tryAuthBlock(currentTag.uid, currentTag.uidLen, fb, 0) < 0) continue;
      for (uint8_t b = 0; b < 3; b++) {
        if (nfc.mifareclassic_ReadDataBlock(fb + b, ndefBuf + ndefLen)) ndefLen += 16;
      }
    }

    if (ndefLen == 0 || !parseTlvNdef(ndefBuf, ndefLen)) {
      Serial.println("No NDEF message found.");
    }
  } else {
    Serial.println("NDEF not supported for this tag type.");
  }
}

// ============================================================
// Command: WRITE <URL|TEXT> <content>
// ============================================================

void cmdWrite(String args) {
  if (!hasTag) { Serial.println("No tag scanned. Run SCAN first."); return; }

  args.trim();
  int spaceIdx = args.indexOf(' ');
  if (spaceIdx < 0) {
    Serial.println("Usage: WRITE URL <url>  or  WRITE TEXT <text>");
    return;
  }

  String recordType = args.substring(0, spaceIdx);
  String content = args.substring(spaceIdx + 1);
  recordType.toUpperCase();

  if (currentTag.type == TAG_MIFARE_ULTRALIGHT) {
    // Write NDEF to Ultralight/NTAG
    Serial.println("Hold tag on reader for write...");
    if (!reselectCard()) { Serial.println("Tag not present."); return; }

    if (recordType == "URL") {
      // Build NDEF URI message in TLV format
      // Determine URI prefix
      uint8_t prefixCode = 0x00;
      String uri = content;
      if (uri.startsWith("https://www.")) { prefixCode = 0x02; uri = uri.substring(12); }
      else if (uri.startsWith("http://www."))  { prefixCode = 0x01; uri = uri.substring(11); }
      else if (uri.startsWith("https://"))     { prefixCode = 0x04; uri = uri.substring(8); }
      else if (uri.startsWith("http://"))      { prefixCode = 0x03; uri = uri.substring(7); }
      else if (uri.startsWith("tel:"))         { prefixCode = 0x05; uri = uri.substring(4); }
      else if (uri.startsWith("mailto:"))      { prefixCode = 0x06; uri = uri.substring(7); }

      uint8_t uriLen = uri.length();
      uint8_t payloadLen = 1 + uriLen;  // prefix code + uri
      uint8_t ndefRecordLen = 3 + payloadLen;  // header(1) + typeLen(1) + payloadLen(1) + type(1) + payload
      // Actually: header(1) + typeLen(1) + payloadLen(1) + type(1) + payload = 4 + payloadLen
      // NDEF record: [header=0xD1] [typeLen=1] [payloadLen] [type='U'] [prefixCode] [uri...]
      // TLV: [0x03] [ndefLen] [ndef record] [0xFE]

      uint8_t ndefMsg[255];
      uint8_t pos = 0;
      ndefMsg[pos++] = 0x03;           // NDEF TLV type
      ndefMsg[pos++] = 4 + payloadLen; // NDEF TLV length
      ndefMsg[pos++] = 0xD1;           // NDEF record header: MB|ME|SR, TNF=0x01
      ndefMsg[pos++] = 0x01;           // Type length = 1
      ndefMsg[pos++] = payloadLen;     // Payload length
      ndefMsg[pos++] = 'U';            // Type = URI
      ndefMsg[pos++] = prefixCode;     // URI prefix code
      for (uint8_t i = 0; i < uriLen; i++) ndefMsg[pos++] = uri[i];
      ndefMsg[pos++] = 0xFE;           // Terminator TLV

      // Write page by page starting at page 4
      uint8_t numPages = (pos + 3) / 4;
      for (uint8_t p = 0; p < numPages; p++) {
        uint8_t pageData[4] = {0, 0, 0, 0};
        for (uint8_t b = 0; b < 4 && (p * 4 + b) < pos; b++) {
          pageData[b] = ndefMsg[p * 4 + b];
        }
        if (!nfc.mifareultralight_WritePage(4 + p, pageData)) {
          Serial.print("Write failed at page ");
          Serial.println(4 + p);
          return;
        }
      }
      Serial.print("Written URL: ");
      Serial.println(content);

    } else if (recordType == "TEXT") {
      uint8_t textLen = content.length();
      uint8_t langLen = 2;  // "en"
      uint8_t payloadLen = 1 + langLen + textLen;  // status + lang + text

      uint8_t ndefMsg[255];
      uint8_t pos = 0;
      ndefMsg[pos++] = 0x03;
      ndefMsg[pos++] = 4 + payloadLen;
      ndefMsg[pos++] = 0xD1;           // MB|ME|SR, TNF=0x01
      ndefMsg[pos++] = 0x01;           // Type length = 1
      ndefMsg[pos++] = payloadLen;
      ndefMsg[pos++] = 'T';            // Type = Text
      ndefMsg[pos++] = langLen;         // Status byte: UTF-8, lang length
      ndefMsg[pos++] = 'e';
      ndefMsg[pos++] = 'n';
      for (uint8_t i = 0; i < textLen; i++) ndefMsg[pos++] = content[i];
      ndefMsg[pos++] = 0xFE;

      uint8_t numPages = (pos + 3) / 4;
      for (uint8_t p = 0; p < numPages; p++) {
        uint8_t pageData[4] = {0, 0, 0, 0};
        for (uint8_t b = 0; b < 4 && (p * 4 + b) < pos; b++) {
          pageData[b] = ndefMsg[p * 4 + b];
        }
        if (!nfc.mifareultralight_WritePage(4 + p, pageData)) {
          Serial.print("Write failed at page ");
          Serial.println(4 + p);
          return;
        }
      }
      Serial.print("Written Text: ");
      Serial.println(content);

    } else {
      Serial.println("Unknown record type. Use URL or TEXT.");
    }

  } else if (currentTag.type == TAG_MIFARE_CLASSIC_1K || currentTag.type == TAG_MIFARE_CLASSIC_4K) {
    Serial.println("Hold tag on reader for write...");
    if (!reselectCard()) { Serial.println("Tag not present."); return; }

    if (recordType == "URL") {
      // Use the library's built-in Classic NDEF URI writer
      // Determine URI identifier
      uint8_t uriId = 0x00;
      char *uriStr = (char *)content.c_str();
      if (content.startsWith("https://www.")) { uriId = 0x02; uriStr += 12; }
      else if (content.startsWith("http://www."))  { uriId = 0x01; uriStr += 11; }
      else if (content.startsWith("https://"))     { uriId = 0x04; uriStr += 8; }
      else if (content.startsWith("http://"))      { uriId = 0x03; uriStr += 7; }

      if (nfc.mifareclassic_WriteNDEFURI(1, uriId, uriStr)) {
        Serial.print("Written URL to Classic sector 1: ");
        Serial.println(content);
      } else {
        Serial.println("Write failed.");
      }
    } else {
      Serial.println("Classic WRITE currently supports URL only.");
    }
  } else {
    Serial.println("Write not supported for this tag type.");
  }
}

// ============================================================
// Command: CLONE READ / CLONE WRITE
// ============================================================

void cmdCloneRead() {
  if (!hasTag) { Serial.println("No tag scanned. Run SCAN first."); return; }

  Serial.println("Hold SOURCE tag on reader...");
  if (!reselectCard()) { Serial.println("Tag not present."); return; }

  cloneLen = 0;
  cloneType = currentTag.type;
  cloneUidLen = currentTag.uidLen;
  memcpy(cloneUid, currentTag.uid, currentTag.uidLen);

  if (currentTag.type == TAG_MIFARE_CLASSIC_1K || currentTag.type == TAG_MIFARE_CLASSIC_4K) {
    uint16_t totalBlocks = (currentTag.type == TAG_MIFARE_CLASSIC_4K) ? 256 : 64;
    for (uint16_t block = 0; block < totalBlocks; block++) {
      uint16_t sectorFirst = (block < 128) ? (block - (block % 4)) : (block - (block % 16));
      if (block == sectorFirst) {
        bool auth = (tryAuthBlock(currentTag.uid, currentTag.uidLen, block, 0) >= 0);
        if (!auth) auth = (tryAuthBlock(currentTag.uid, currentTag.uidLen, block, 1) >= 0);
        if (!auth) {
          // Fill unauthenticated blocks with zeros
          uint16_t bInSec = (block < 128) ? 4 : 16;
          for (uint16_t b = 0; b < bInSec && cloneLen + 16 <= sizeof(cloneBuf); b++) {
            memset(cloneBuf + cloneLen, 0, 16);
            cloneLen += 16;
          }
          block = sectorFirst + ((block < 128) ? 3 : 15);
          continue;
        }
      }
      if (cloneLen + 16 > sizeof(cloneBuf)) break;
      if (!nfc.mifareclassic_ReadDataBlock(block, cloneBuf + cloneLen)) {
        memset(cloneBuf + cloneLen, 0, 16);
      }
      cloneLen += 16;
    }
    Serial.print("Read ");
    Serial.print(cloneLen / 16);
    Serial.println(" blocks into clone buffer.");

  } else if (currentTag.type == TAG_MIFARE_ULTRALIGHT) {
    for (uint16_t page = 0; page < 231; page++) {
      if (cloneLen + 4 > sizeof(cloneBuf)) break;
      if (!nfc.mifareultralight_ReadPage(page, cloneBuf + cloneLen)) break;
      cloneLen += 4;
    }
    Serial.print("Read ");
    Serial.print(cloneLen / 4);
    Serial.println(" pages into clone buffer.");
  } else {
    Serial.println("Clone not supported for this tag type.");
    return;
  }

  Serial.print("Source UID: ");
  printUid(cloneUid, cloneUidLen);
  Serial.println();
  Serial.println("Now place TARGET tag and run: CLONE WRITE");
}

void cmdCloneWrite() {
  if (cloneLen == 0) { Serial.println("Clone buffer empty. Run CLONE READ first."); return; }

  Serial.println("Place blank TARGET tag on reader...");
  uint8_t uid[7];
  uint8_t uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 10000)) {
    Serial.println("No tag found.");
    return;
  }

  Serial.print("Target UID: ");
  printUid(uid, uidLen);
  Serial.println();

  if (cloneType == TAG_MIFARE_CLASSIC_1K || cloneType == TAG_MIFARE_CLASSIC_4K) {
    uint16_t totalBlocks = cloneLen / 16;
    uint16_t written = 0;
    for (uint16_t block = 0; block < totalBlocks; block++) {
      // Skip block 0 (manufacturer block, read-only)
      if (block == 0) continue;
      // Skip sector trailer blocks (they contain keys + access bits)
      bool isTrailer;
      if (block < 128) {
        isTrailer = ((block + 1) % 4 == 0);
      } else {
        isTrailer = ((block + 1) % 16 == 0);
      }
      if (isTrailer) continue;

      uint16_t sectorFirst = (block < 128) ? (block - (block % 4)) : (block - (block % 16));
      if (block == sectorFirst || (block == 1)) {  // re-auth at sector boundary
        bool auth = false;
        // Try default key on target
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, 0, (uint8_t *)KNOWN_KEYS[0])) {
          auth = true;
        } else {
          reselectCard();
          auth = (tryAuthBlock(uid, uidLen, block, 0) >= 0);
        }
        if (!auth) {
          Serial.print("Auth failed on target block ");
          Serial.println(block);
          uint16_t bInSec = (block < 128) ? 4 : 16;
          block = sectorFirst + bInSec - 1;
          continue;
        }
      }

      if (nfc.mifareclassic_WriteDataBlock(block, cloneBuf + block * 16)) {
        written++;
      } else {
        Serial.print("Write failed at block ");
        Serial.println(block);
      }
    }
    Serial.print("Cloned ");
    Serial.print(written);
    Serial.println(" data blocks to target.");

  } else if (cloneType == TAG_MIFARE_ULTRALIGHT) {
    uint16_t totalPages = cloneLen / 4;
    uint16_t written = 0;
    // Skip pages 0-3 (UID + internal + lock + CC) — start at page 4
    for (uint16_t page = 4; page < totalPages; page++) {
      if (nfc.mifareultralight_WritePage(page, cloneBuf + page * 4)) {
        written++;
      } else {
        Serial.print("Write failed at page ");
        Serial.print(page);
        Serial.println(" (may be config/lock page)");
        break;
      }
    }
    Serial.print("Cloned ");
    Serial.print(written);
    Serial.println(" pages to target.");
  }
}

// ============================================================
// Command: EMULATE
// ============================================================

void cmdEmulate() {
  Serial.println("Entering card emulation mode...");
  Serial.println("The PN532 will appear as an NFC tag.");
  Serial.println("Bring a phone close to read it. Press any key to stop.");
  Serial.println();

  // Use the library's built-in AsTarget
  // It emulates a basic ISO14443A target
  while (!Serial.available()) {
    uint8_t result = nfc.AsTarget();
    if (result) {
      Serial.println("Activated by reader!");

      uint8_t cmd[64];
      uint8_t cmdLen;

      if (nfc.getDataTarget(cmd, &cmdLen)) {
        Serial.print("Received (");
        Serial.print(cmdLen);
        Serial.print(" bytes): ");
        for (uint8_t i = 0; i < cmdLen; i++) {
          printHex(cmd[i]);
          Serial.print(" ");
        }
        Serial.println();

        // Respond with a simple NDEF message if this is an NDEF read
        // Basic response: just echo back for now
        uint8_t resp[] = {0x8E, 0x00};  // TgSetData success
        nfc.setDataTarget(resp, sizeof(resp));
      }
    }
    delay(100);
  }
  // Flush serial
  while (Serial.available()) Serial.read();
  Serial.println("Emulation stopped.");
}

// ============================================================
// Command: SCANALL (multi-protocol)
// ============================================================

void cmdScanAll() {
  Serial.println("Scanning all protocols (10s timeout)...");
  Serial.println();

  // ISO 14443A
  Serial.println("[ISO 14443A]");
  uint8_t uid[7];
  uint8_t uidLen;
  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 3000)) {
    uint16_t atqa = (pn532_packetbuffer[9] << 8) | pn532_packetbuffer[10];
    uint8_t sak = pn532_packetbuffer[11];
    currentTag = identifyTag(atqa, sak, uid, uidLen);
    hasTag = true;

    Serial.print("  Found: ");
    Serial.println(currentTag.name);
    Serial.print("  UID: ");
    printUid(uid, uidLen);
    Serial.println();
    Serial.print("  ATQA: 0x");
    if (atqa < 0x1000) Serial.print("0");
    if (atqa < 0x100) Serial.print("0");
    if (atqa < 0x10) Serial.print("0");
    Serial.print(atqa, HEX);
    Serial.print("  SAK: 0x");
    printHex(sak);
    Serial.println();
  } else {
    Serial.println("  No ISO 14443A tag found.");
  }

  // ISO 14443B — baud rate 0x03
  // Note: library's InListPassiveTarget doesn't send AFI byte needed for 14443B,
  // so detection may not work for all 14443B tags
  Serial.println("[ISO 14443B]");
  {
    uint8_t uid14b[7];
    uint8_t uid14bLen;
    if (nfc.readPassiveTargetID(0x03, uid14b, &uid14bLen, 3000)) {
      Serial.print("  Found ISO 14443B! ID: ");
      printUid(uid14b, uid14bLen);
      Serial.println();
    } else {
      Serial.println("  No ISO 14443B tag found.");
    }
  }

  // FeliCa — baud rate 0x01 (212 kbps)
  // Note: library doesn't send FeliCa polling payload, so detection is limited
  Serial.println("[FeliCa (212 kbps)]");
  {
    uint8_t uidFe[7];
    uint8_t uidFeLen;
    if (nfc.readPassiveTargetID(0x01, uidFe, &uidFeLen, 3000)) {
      Serial.print("  Found FeliCa! ID: ");
      printUid(uidFe, uidFeLen);
      Serial.println();
    } else {
      Serial.println("  No FeliCa tag found.");
    }
  }
}

// ============================================================
// Command: HELP
// ============================================================

void cmdHelp() {
  Serial.println("--- PN532 NFC Multi-Tool ---");
  Serial.println("Commands:");
  Serial.println("  SCAN       - Scan for an ISO 14443A tag");
  Serial.println("  SCANALL    - Scan ISO 14443A + 14443B + FeliCa");
  Serial.println("  DUMP       - Dump tag memory (after SCAN)");
  Serial.println("  KEYS       - Audit MIFARE Classic keys (after SCAN)");
  Serial.println("  NDEF       - Parse NDEF records (after SCAN)");
  Serial.println("  WRITE URL <url>   - Write URL to tag");
  Serial.println("  WRITE TEXT <text>  - Write text to tag");
  Serial.println("  CLONE READ   - Read tag data into clone buffer");
  Serial.println("  CLONE WRITE  - Write clone buffer to blank tag");
  Serial.println("  EMULATE    - Enter card emulation mode");
  Serial.println("  HELP       - Show this help");
  Serial.println();
  if (hasTag) {
    Serial.print("Current tag: ");
    Serial.print(currentTag.name);
    Serial.print(" (");
    printUid(currentTag.uid, currentTag.uidLen);
    Serial.println(")");
  } else {
    Serial.println("No tag scanned yet.");
  }
}

// ============================================================
// Setup & Loop
// ============================================================

String serialBuffer = "";

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  Serial.println("\nPN532 NFC Multi-Tool v2");
  Serial.println("=======================");

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

  Serial.println("Type HELP for commands.\n");
  Serial.print("> ");
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (serialBuffer.length() > 0) {
        Serial.println();

        // Parse command
        String cmd = serialBuffer;
        cmd.trim();
        String upper = cmd;
        upper.toUpperCase();

        if (upper == "HELP" || upper == "?") {
          cmdHelp();
        } else if (upper == "SCAN") {
          cmdScan();
        } else if (upper == "SCANALL") {
          cmdScanAll();
        } else if (upper == "DUMP") {
          cmdDump();
        } else if (upper == "KEYS") {
          cmdKeys();
        } else if (upper == "NDEF") {
          cmdNdef();
        } else if (upper.startsWith("WRITE ")) {
          cmdWrite(cmd.substring(6));
        } else if (upper == "CLONE READ") {
          cmdCloneRead();
        } else if (upper == "CLONE WRITE") {
          cmdCloneWrite();
        } else if (upper == "EMULATE") {
          cmdEmulate();
        } else {
          Serial.print("Unknown command: ");
          Serial.println(cmd);
          Serial.println("Type HELP for available commands.");
        }

        serialBuffer = "";
        Serial.print("\n> ");
      }
    } else {
      serialBuffer += c;
      Serial.print(c);  // echo
    }
  }
}
