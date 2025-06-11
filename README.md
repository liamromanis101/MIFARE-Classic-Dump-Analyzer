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

