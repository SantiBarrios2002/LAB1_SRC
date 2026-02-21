# LAB1_SRC - PN532 NFC Multi-Tool

ESP32-based NFC multi-tool using the PN532 module. Scans, identifies, dumps, and audits NFC tags over SPI.

## Features

- **Tag Identification** — Automatically identifies tag type from ATQA/SAK (MIFARE Classic 1K/4K, Ultralight, NTAG, DESFire, ISO 14443-4)
- **Memory Dump** — Full hex + ASCII dump of tag memory
  - MIFARE Classic: authenticates and reads all 64/256 blocks
  - Ultralight/NTAG: reads all pages until end of memory
- **Key Audit** — Tests 10 common MIFARE Classic keys (factory default, MAD, NDEF, transport, Infineon, Gallagher, etc.) on every sector as both Key A and Key B
- **NDEF Parsing** — Decodes NDEF messages stored on tags
  - URI records (with prefix decoding)
  - Text records (with language code)
  - Media types
  - Supports both Ultralight/NTAG (TLV) and Classic (MAD) NDEF formats

## Wiring (SPI)

| PN532 | ESP32 |
|-------|-------|
| SS    | GPIO 5  |
| SCK   | GPIO 18 |
| MISO  | GPIO 19 |
| MOSI  | GPIO 23 |
| VCC   | 3.3V    |
| GND   | GND     |

Make sure the PN532 module is set to SPI mode (check the DIP switches on the board).

## Setup

1. Install [VS Code](https://code.visualstudio.com/)
2. Install the [PlatformIO IDE](https://platformio.org/install/ide?install=vscode) extension
3. Clone this repo:
   ```
   git clone https://github.com/SantiBarrios2002/LAB1_SRC.git
   ```
4. Open the `LAB1_SRC` folder in VS Code
5. PlatformIO will automatically download all dependencies

## Build & Upload

1. Connect your ESP32 via USB
2. Click the PlatformIO **Upload** button (arrow icon in the bottom toolbar) or run:
   ```
   pio run -t upload
   ```
3. Open the Serial Monitor at **115200 baud** to see scanned tags

## Output Example

```
PN532 NFC Multi-Tool
====================
PN532 fw 1.6
Ready. Scan a tag...

Tag: MIFARE Classic 1K
  UID (4): 3A:0C:DD:84
  ATQA: 0x0004  SAK: 0x08
  --- MIFARE Classic Memory Dump ---
  Blk | Data                                          | ASCII
  ----+--------------------------------------------------+------------------
    0 | 3A 0C DD 84 6F 08 04 00 62 63 64 65 66 67 68 69 | :...o...bcdefghi
    1 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
  ...

  --- MIFARE Classic Key Audit ---
  Sect | Key A found              | Key B found
  -----+--------------------------+--------------------------
   0   | A0:A1:A2:A3:A4:A5 (A)   | FF:FF:FF:FF:FF:FF (B)
  ...

  --- NDEF Records ---
  Record #1
    TNF: NFC Forum well-known
    Type: U
    Payload (12 bytes):
    URI: https://example.com

Tag: MIFARE Ultralight / NTAG
  UID (7): 04:F5:BF:1A:BF:76:80
  ATQA: 0x0044  SAK: 0x00
  --- Ultralight / NTAG Memory Dump ---
  Page | Data        | ASCII
  -----+-------------+------
    0  | 04 F5 BF C6 | ....
  ...
```
