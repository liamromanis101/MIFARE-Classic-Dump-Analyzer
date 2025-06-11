# MIFARE Classic Dump Analyzer
This Python script analyzes .mfcdump files from Flipper Zero MIFARE Classic card reads, detects known keys, decodes access bits, reads accessible data blocks, and tries to identify the manufacturer from Block 0. Created for educational purposes. 

## Features

- Parses Flipper Zero `.mfcdump` files
- Brute-forces access keys using a supplied key list or defaults
- Displays access control bits in human-readable form
- Reads and prints sector data (when accessible)
- Identifies manufacturer from Block 0 (UID)

## Usage

```bash
python3 mifare_analyzer.py dump.mfcdump [keyfile.txt]
```

	•	dump.mfcdump: Path to the Flipper Zero dump file
	•	keyfile.txt: (Optional) List of possible keys, one per line in hex format (12 hex characters)

please see: https://github.com/RfidResearchGroup/proxmark3/tree/master/client/dictionaries

## Example Output
```bash
Sector 00:
  Key A: FFFFFFFFFFFF ✅ Known
  Key B: Unknown
  Access Bits: FF0780 -> C1:0 C2:0 C3:0
    Block 0: 6EA8CD949F08040003CC9EB088E4EB1D
      Manufacturer: NXP Semiconductors (04)
    Block 1: 14B6C3886A9C9C9CCDF84C2CCB721284
    Block 2: 01010000000000000000000000000000

Sector 01:
  Key A: FFFFFFFFFFFF ✅ Known
  Key B: Unknown
  Access Bits: FF0780 -> C1:0 C2:0 C3:0
    Block 4: 00000000000000000000000000000000
    Block 5: 00000000000000000000000000000000
    Block 6: 00000000000000000000000000000000

Sector 02:
  Key A: Unknown
  Key B: Unknown
  Access Bits: Unable to read (no known key)
```
## Recognized Manufacturers
The only manufacturers currently recognized are listed here. If you manage to map missing codes to manufacturers let me know and I will update the script. 

```bash
        0x00: "NXP Semiconductors",
        0x01: "Motorola",
        0x02: "STMicroelectronics",
        0x03: "Hitachi",
        0x04: "Texas Instruments",
        0x07: "Infineon",
        0x08: "Matsushita",
        0x09: "NEC",
        0x0A: "Oki",
        0x0B: "Toshiba",
        0x0C: "Mitsubishi",
        0x0D: "Samsung",
        0x0E: "Hyundai",
        0x0F: "Sony",
        0x10: "Fujitsu",
```

## Notes
	•	Only supports MIFARE Classic dumps in Flipper Zero format
	•	Manufacturer information (from UID) is only reliably available for NXP (04)
	•	Access control bit decoding is best-effort and based on known MIFARE specs

 There will likely be many updates to this repo so please check back :)

