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

## Notes
	•	Only supports MIFARE Classic dumps in Flipper Zero format
	•	Manufacturer information (from UID) is only reliably available for NXP (04)
	•	Access control bit decoding is best-effort and based on known MIFARE specs

