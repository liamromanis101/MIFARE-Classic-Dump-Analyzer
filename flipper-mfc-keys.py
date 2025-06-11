import sys
import binascii


def identify_manufacturer(block0_bytes):
    # Ensure we have at least one byte
    if len(block0_bytes) < 1:
        return "Unknown (no data)"

    manufacturer_id = block0_bytes[0]

    # Dictionary of some common MIFARE manufacturer IDs
    manufacturers = {
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
        # Add more manufacturer codes here if needed
    }

    return manufacturers.get(manufacturer_id, f"Unknown (ID 0x{manufacturer_id:02X})")

def load_keys(filename):
    keys = []
    with open(filename, 'r') as f:
        for line in f:
            key = line.strip()
            if len(key) == 12 and all(c in '0123456789ABCDEFabcdef' for c in key):
                keys.append(key.upper())
    return keys

def parse_dump(filename):
    blocks = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Block "):
                parts = line.split(":")
                block_num_str = parts[0].split()[1]
                block_num = int(block_num_str)
                data_str = parts[1].strip().replace("??", "00")  # Replace unknowns with zeros
                data_bytes = bytes.fromhex(data_str)
                blocks[block_num] = data_bytes
    return blocks

def decode_access_bits(ab_bytes):
    if len(ab_bytes) != 3:
        return "Invalid"
    def extract_bits(byte):
        return [(byte >> i) & 1 for i in reversed(range(8))]

    b6_bits = extract_bits(ab_bytes[0])
    b7_bits = extract_bits(ab_bytes[1])
    b8_bits = extract_bits(ab_bytes[2])

    access = []
    for i in range(4):  # 4 blocks in sector
        c1_bit = b6_bits[i*2+1]
        c2_bit = b7_bits[i*2+1]
        c3_bit = b8_bits[i*2+1]
        access.append((c1_bit, c2_bit, c3_bit))
    return access

def interpret_access_bits(access_bits):
    data_block_access = {
        (0,0,0): "Read/Write",
        (0,1,0): "Read only",
        (1,0,0): "Read Write with restrictions",
        (1,1,0): "Read only",
        (0,0,1): "Read/Write",
        (0,1,1): "Read only",
        (1,0,1): "Key B restrictions",
        (1,1,1): "No access"
    }

    trailer_access = {
        (0,0,0): "Key A|B: Read/Write keys and access bits",
        (0,1,0): "Key A: Read/write keys; Key B: read keys only",
        (1,0,0): "Key B read/write access",
        (1,1,0): "No access to keys",
        (0,0,1): "Read keys only",
        (0,1,1): "Key B read only",
        (1,0,1): "No access",
        (1,1,1): "No access"
    }

    result = []
    for i, bits in enumerate(access_bits):
        if i < 3:
            meaning = data_block_access.get(bits, "Unknown")
            result.append(f"Block {i}: {meaning} (C1={bits[0]} C2={bits[1]} C3={bits[2]})")
        else:
            meaning = trailer_access.get(bits, "Unknown")
            result.append(f"Trailer block: {meaning} (C1={bits[0]} C2={bits[1]} C3={bits[2]})")
    return "\n    ".join(result)

def try_key(blocks, sector, key, key_type):
    trailer_block = sector * 4 + 3
    if trailer_block not in blocks:
        return False
    trailer = blocks[trailer_block]
    if key_type == 'A':
        trailer_key_a = trailer[0:6]
        return trailer_key_a.hex().upper() == key
    else:
        trailer_key_b = trailer[10:16]
        return trailer_key_b.hex().upper() == key

def print_sector_data(blocks, sector):
    trailer_block = sector * 4 + 3
    if trailer_block not in blocks:
        print(f"  Trailer block {trailer_block} missing, can't read sector data")
        return

    access_bits = blocks[trailer_block][6:9]
    access = decode_access_bits(access_bits)
    print(f"  Access Bits: {access_bits.hex().upper()} ->")
    print("    " + interpret_access_bits(access))

    for block_offset in range(3):
        block_num = sector * 4 + block_offset
        block_data = blocks.get(block_num, bytes(16))
        print(f"    Block {block_num}: {block_data.hex().upper()}")
	
#        if sector == 0 and block_offset == 0:
#            print(f"    Debug: block_data length = {len(block_data)}")
#            manufacturer = identify_manufacturer(block_data)
#            print(f"      Manufacturer: {manufacturer}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <dumpfile> <keysfile>")
        sys.exit(1)

    dumpfile = sys.argv[1]
    keysfile = sys.argv[2]

    keys = load_keys(keysfile)
    if not keys:
        print("No valid keys loaded from keys file.")
        sys.exit(1)

    blocks = parse_dump(dumpfile)
    if not blocks:
        print("No blocks found in dump file.")
        sys.exit(1)

    print("=== MIFARE Classic Trailer Key Check ===\n")

    for sector in range(16):
        trailer_block = sector * 4 + 3
        if trailer_block not in blocks:
            print(f"Sector {sector:02d}: ❌ Trailer block unreadable")
            continue
        trailer = blocks[trailer_block]

        key_a_found = None
        key_b_found = None

        for key in keys:
            if key_a_found is None and try_key(blocks, sector, key, 'A'):
                key_a_found = key
            if key_b_found is None and try_key(blocks, sector, key, 'B'):
                key_b_found = key
            if key_a_found and key_b_found:
                break

        print(f"Sector {sector:02d}:")
        if key_a_found:
            print(f"  Key A: {key_a_found} ✅ Known")
        else:
            print(f"  Key A: Unknown")

        if key_b_found:
            print(f"  Key B: {key_b_found} ✅ Known")
        else:
            print(f"  Key B: Unknown")

        access_bits = trailer[6:9]
        access = decode_access_bits(access_bits)
        print(f"  Access Bits: {access_bits.hex().upper()} ->")
        print("    " + interpret_access_bits(access))

        # Print sector data blocks if we found either key
        if key_a_found or key_b_found:
            for block_offset in range(3):
                block_num = sector * 4 + block_offset
                block_data = blocks.get(block_num, bytes(16))
                print(f"    Block {block_num}: {block_data.hex().upper()}")

                # Insert manufacturer identification for sector 0 block 0 here
                if sector == 0 and block_offset == 0:
                    manufacturer = identify_manufacturer(block_data)
                    print(f"      Manufacturer: {manufacturer}")
        print()

if __name__ == "__main__":
    main()
