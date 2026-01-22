# DFwe
(Dee-eff-wheee because its better with friends)


## What

This script polls for newly attached RP2040/RP2350 devices, kicks them into DFU mode if necessary, and flashes your specified firmware file. 

For batch programming needs, run the script once and keep plugging in new boards to flash :)

It was made to be cross-platform (worked well on linux/macos, YMMV on windows 😅)

This is vibe-slop with light manual fixes FWIW!

## Setup

* `pip3 install -r requirements.txt`
(pyserial, psutil)

## Usage

```
❯ python3 DFwe.py -h
usage: DFwe.py [-h] [--verify] [firmware]

AutoFlash - Automated RP2040/RP2350 firmware flasher

positional arguments:
  firmware    Firmware file to flash (default: firmware.uf2)

options:
  -h, --help  show this help message and exit
  --verify    Enable write verification (slower)
```


## How It Works

1. **Serial Monitor**:  Watches for RP2040/RP2350 devices on USB serial ports
2. **Auto-trigger**:    Opens serial at 1200 baud to trigger DFU bootloader mode
3. **Drive Detection**: Monitors for UF2 bootloader drives (RPI-RP2 or RP2350)
4. **Flash**:           Copies firmware to the 'drive'


## greetz
s/o DisCo and BT for making me do this