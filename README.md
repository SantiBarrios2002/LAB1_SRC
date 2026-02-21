# LAB1_SRC - PN532 RFID Key Identifier

Simple NFC tag scanner for ESP32 DevKit that identifies the type of tag being scanned (Mifare Classic, Mifare Ultralight, NTAG2xx).

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
PN532 RFID Key Identifier
========================
PN532 fw 1.6
Ready. Scan a tag...

UID: AA:BB:CC:DD -> Mifare Classic
UID: 04:A1:B2:C3:D4:E5:F6 -> Mifare Ultralight / NTAG2xx
```
