#!/usr/bin/env python3
"""
Creality K2/K1/CFS Filament RFID Encryption Helper
This script handles AES encryption/decryption for use with Proxmark3
"""

from Crypto.Cipher import AES
import argparse
import subprocess
import re
import sys
import time

# Constants - these match the JavaScript implementation
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 
                     0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])
# "q3bu^t1nqfZ(pf$1"

AES_KEY_CIPHER = bytes([0x48, 0x40, 0x43, 0x46, 0x6B, 0x52, 0x6E, 0x7A, 
                        0x40, 0x4B, 0x41, 0x74, 0x42, 0x4A, 0x70, 0x32])
# "H@CFkRnz@KAtBJp2"

# Proxmark3 Integration Functions
def check_pm3_available():
    """Check if Proxmark3 client is available"""
    try:
        result = subprocess.run(['pm3', '--help'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            # Try alternative command name
            result = subprocess.run(['proxmark3', '--help'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

def get_pm3_command():
    """Get the correct Proxmark3 command name"""
    try:
        subprocess.run(['pm3', '--help'], 
                      capture_output=True, 
                      timeout=5)
        return 'pm3'
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 'proxmark3'

def read_uid_from_tag():
    """Read UID from a tag on the Proxmark3"""
    print("\n[*] Place tag on Proxmark3 antenna...")
    print("[*] Reading UID from tag...")
    
    pm3_cmd = get_pm3_command()
    
    try:
        # Run hf 14a reader command to get UID
        result = subprocess.run(
            [pm3_cmd, '-c', 'hf mf info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Parse UID from output
        # Looking for patterns like "UID : 3a 14 ac f1" or "UID: 3A14ACF1"
        uid_patterns = [
            r'UID\s*:\s*([0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2})',
            r'UID\s*:\s*([0-9a-fA-F]{8})',
            r'UID\s*=\s*([0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2})',
        ]
        
        for pattern in uid_patterns:
            match = re.search(pattern, result.stdout, re.IGNORECASE)
            if match:
                uid = match.group(1).replace(' ', '').upper()
                print(f"[+] UID detected: {uid}")
                return uid
        
        # If no match found, print output for debugging
        print("[!] Could not parse UID from output:")
        print(result.stdout)
        return None
        
    except subprocess.TimeoutExpired:
        print("[!] Timeout reading from Proxmark3")
        return None
    except Exception as e:
        print(f"[!] Error reading UID: {e}")
        return None

def execute_pm3_command(command, description=""):
    """Execute a Proxmark3 command and return result"""
    pm3_cmd = get_pm3_command()
    
    if description:
        print(f"[*] {description}")
    
    print(f"[>] {command}")
    
    try:
        result = subprocess.run(
            [pm3_cmd, '-c', command],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        # Check for success indicators in output
        if 'isOk:01' in result.stdout or 'write block' in result.stdout.lower():
            print("[+] Command executed successfully")
            return True
        elif 'error' in result.stdout.lower() or 'failed' in result.stdout.lower():
            print("[!] Command may have failed. Check output:")
            print(result.stdout[-200:])  # Last 200 chars
            return False
        else:
            print("[?] Command completed (check result)")
            return True
            
    except subprocess.TimeoutExpired:
        print("[!] Command timeout")
        return False
    except Exception as e:
        print(f"[!] Error executing command: {e}")
        return False

def write_to_tag_pm3(uid, tag_data, is_encrypted=False):
    """Write encrypted data to tag using Proxmark3"""
    print(f"\n{'='*60}")
    print(f"  WRITING TO TAG VIA PROXMARK3")
    print(f"{'='*60}")
    
    # Generate key from UID
    print("\n[1/4] Generating encryption key from UID...")
    key_b = generate_key_from_uid(uid)
    print(f"      Key B: {key_b}")
    
    # Encrypt the data
    print("\n[2/4] Encrypting tag data...")
    block1, block2, block3 = encrypt_tag_data(tag_data)
    print(f"      Block 4: {block1}")
    print(f"      Block 5: {block2}")
    print(f"      Block 6: {block3}")
    
    # Write blocks
    print("\n[3/4] Writing encrypted data to tag...")
    
    if is_encrypted:
        # Tag is already encrypted, use the generated key
        print("      Using generated key (tag is already encrypted)")
        commands = [
            (f"hf mf wrbl --blk 4 -b -k {key_b} -d {block1}", "Writing block 4..."),
            (f"hf mf wrbl --blk 5 -b -k {key_b} -d {block2}", "Writing block 5..."),
            (f"hf mf wrbl --blk 6 -b -k {key_b} -d {block3}", "Writing block 6..."),
        ]
    else:
        # New tag, use default key first, then set security
        print("      Using default key (new/unencrypted tag)")
        commands = [
            (f"hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d {block1}", "Writing block 4..."),
            (f"hf mf wrbl --blk 5 -k FFFFFFFFFFFF -d {block2}", "Writing block 5..."),
            (f"hf mf wrbl --blk 6 -k FFFFFFFFFFFF -d {block3}", "Writing block 6..."),
        ]
    
    success = True
    for cmd, desc in commands:
        if not execute_pm3_command(cmd, desc):
            success = False
            break
        time.sleep(0.5)  # Small delay between commands
    
    if not success:
        print("\n[!] Writing failed. Please check your Proxmark3 connection and tag.")
        return False
    
    # Set sector security if new tag
    if not is_encrypted:
        print("\n[4/4] Setting sector 1 security...")
        security_cmd = f"hf mf wrbl --blk 7 -k FFFFFFFFFFFF -d {key_b}FF078069{key_b}"
        if not execute_pm3_command(security_cmd, "Encrypting tag..."):
            print("\n[!] Security setup failed.")
            return False
    else:
        print("\n[4/4] Security already set (skipped)")
    
    print(f"\n{'='*60}")
    print(f"  WRITE COMPLETE!")
    print(f"{'='*60}\n")
    return True

def string_to_hex(s):
    """Convert ASCII string to hex representation (like JavaScript stringToHex)"""
    return ''.join(format(ord(c), '02x') for c in s)

def generate_key_from_uid(uid_hex):
    """Generate authentication key from UID (matches JavaScript encrypt for key gen)"""
    # Clean up the input
    uid_clean = uid_hex.replace(' ', '').replace(':', '').upper()
    
    # Validate hex characters
    try:
        uid_bytes = bytes.fromhex(uid_clean)
    except ValueError as e:
        print(f"Error: Invalid UID format '{uid_hex}'")
        print(f"UID must be hexadecimal characters only (0-9, A-F)")
        raise ValueError(f"Invalid hexadecimal in UID: {e}")
    
    # Validate length (should be 4 or 7 bytes for MIFARE)
    if len(uid_clean) not in [8, 14]:
        print(f"Error: Invalid UID length")
        print(f"Expected: 8 characters (4 bytes) or 14 characters (7 bytes)")
        print(f"Got: {len(uid_clean)} characters")
        raise ValueError(f"UID must be 8 or 14 hex characters, got {len(uid_clean)}")
    
    # Concatenate UID 4 times to make 16 bytes (matches JavaScript: uid.concat(uid).concat(uid).concat(uid))
    uid_repeated = uid_clean * 4
    
    # Convert to bytes (treating the hex string as hex data)
    uid_data = bytes.fromhex(uid_repeated[:32])  # Take first 32 hex chars = 16 bytes
    
    # AES encrypt with AES_KEY_GEN using ECB mode
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    encrypted = cipher.encrypt(uid_data)
    
    # Return first 6 bytes as hex (first 12 hex characters)
    key = encrypted[:6]
    return key.hex().upper()

def encrypt_tag_data(ascii_data):
    """
    Encrypt tag data for writing to RFID
    Takes ASCII string, converts to hex, then encrypts (matches JavaScript flow)
    """
    # Convert ASCII string to hex representation (like JavaScript stringToHex)
    hex_data = string_to_hex(ascii_data)
    
    # Convert hex string to bytes
    data = bytes.fromhex(hex_data)
    
    # Should be exactly 48 bytes (3 blocks of 16)
    if len(data) != 48:
        print(f"Warning: Data is {len(data)} bytes, expected 48. Padding/truncating...")
        if len(data) < 48:
            data = data + b'\x00' * (48 - len(data))
        else:
            data = data[:48]
    
    # AES encrypt with AES_KEY_CIPHER using ECB mode (matches JavaScript)
    cipher = AES.new(AES_KEY_CIPHER, AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    
    # Split into 3 blocks of 16 bytes
    block1 = encrypted[0:16].hex().upper()
    block2 = encrypted[16:32].hex().upper()
    block3 = encrypted[32:48].hex().upper()
    
    return block1, block2, block3

def decrypt_tag_data(block1_hex, block2_hex, block3_hex):
    """Decrypt tag data read from RFID"""
    block1 = bytes.fromhex(block1_hex.replace(' ', ''))
    block2 = bytes.fromhex(block2_hex.replace(' ', ''))
    block3 = bytes.fromhex(block3_hex.replace(' ', ''))
    
    encrypted_data = block1 + block2 + block3
    
    cipher = AES.new(AES_KEY_CIPHER, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    
    # Convert back from hex representation to ASCII
    hex_str = decrypted.hex().upper()
    ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
    
    return ascii_str, hex_str

def build_tag_data(batch='1A5', date='24120', supplier='1B3D', material='01001', 
                   color='00000FF', length='0330', serial='000001', reserve='00000000000000'):
    """
    Build the tag data string to match HTML format exactly
    HTML format: batch(3) + date(5) + supplier(4) + material(5) + color(7) + length(4) + serial(6) + reserve(14)
    Total: 48 characters
    """
    # Validate lengths
    if len(batch) != 3:
        raise ValueError(f"Batch must be 3 characters, got {len(batch)}")
    if len(date) != 5:
        raise ValueError(f"Date must be 5 characters (YYMDD), got {len(date)}")
    if len(supplier) != 4:
        raise ValueError(f"Supplier must be 4 characters, got {len(supplier)}")
    if len(material) != 5:
        raise ValueError(f"Material must be 5 characters, got {len(material)}")
    if len(color) != 7:
        raise ValueError(f"Color must be 7 characters (0RRGGBB), got {len(color)}")
    if len(length) != 4:
        raise ValueError(f"Length must be 4 characters, got {len(length)}")
    if len(serial) != 6:
        raise ValueError(f"Serial must be 6 characters, got {len(serial)}")
    if len(reserve) != 14:
        raise ValueError(f"Reserve must be 14 characters, got {len(reserve)}")
    
    tag_data = batch + date + supplier + material + color + length + serial + reserve
    
    return tag_data

def parse_tag_data(ascii_data):
    """Parse decrypted tag data"""
    if len(ascii_data) < 48:
        print("Error: Data too short")
        return
    
    # Parse fields according to HTML format
    batch = ascii_data[0:3]
    date = ascii_data[3:8]
    supplier = ascii_data[8:12]
    material = ascii_data[12:17]
    color = ascii_data[17:24]
    length = ascii_data[24:28]
    serial = ascii_data[28:34]
    reserve = ascii_data[34:48]
    
    # Parse date (YYMDD format)
    year = date[0:2]
    month = date[2:3]  # Single digit
    day = date[3:5]
    
    # Material mapping (from HTML)
    material_map = {
        '10001': 'HP-TPU',
        '11001': 'CR-Nylon',
        '13001': 'CR-PLACarbon',
        '14001': 'CR-PLAMatte',
        '15001': 'CR-PLAFluo',
        '16001': 'CR-TPU',
        '17001': 'CR-Wood',
        '18001': 'HPUltraPLA',
        '19001': 'HP-ASA',
        '07001': 'CR-ABS',
        '06001': 'CR-PETG',
        '04001': 'CR-PLA',
        '05001': 'CR-Silk',
        '09001': 'EN-PLA+',
        '09002': 'ENDERFASTPLA',
        '08001': 'Ender-PLA',
        '00004': 'GenericABS',
        '00007': 'GenericASA',
        '00010': 'GenericBVOH',
        '00012': 'GenericHIPS',
        '00008': 'GenericPA',
        '00009': 'GenericPA-CF',
        '00015': 'GenericPA6-CF',
        '00016': 'GenericPAHT-CF',
        '00021': 'GenericPC',
        '00020': 'GenericPET',
        '00013': 'GenericPET-CF',
        '00003': 'GenericPETG',
        '00014': 'GenericPETG-CF',
        '00001': 'GenericPLA',
        '00006': 'GenericPLA-CF',
        '00002': 'GenericPLA-Silk',
        '00019': 'GenericPP',
        '00017': 'GenericPPS',
        '00018': 'GenericPPS-CF',
        '00011': 'GenericPVA',
        '00005': 'GenericTPU',
        '03001': 'HyperABS',
        '06002': 'HyperPETG',
        '01001': 'HyperPLA',
        '02001': 'HyperPLA-CF',
    }
    
    # Length to weight mapping
    length_to_weight = {
        '0330': '1.0 kg',
        '0165': '0.5 kg',
    }
    
    material_name = material_map.get(material, f'Unknown ({material})')
    weight = length_to_weight.get(length, f'Unknown ({length})')
    
    print("\n=== Parsed Tag Data ===")
    print(f"Batch: {batch}")
    print(f"Date: 20{year}-{month.zfill(2)}-{day} (YYMDD format)")
    print(f"Supplier: {supplier}")
    print(f"Material: {material_name} (Code: {material})")
    print(f"Color: {color} (RGB: #{color[1:]})")
    print(f"Length Code: {length} ({weight})")
    print(f"Serial: {serial}")
    print(f"Reserve: {reserve}")

def print_material_table():
    """Print a formatted table of all material codes and names"""
    materials = [
        ('10001', 'HP-TPU'),
        ('11001', 'CR-Nylon'),
        ('13001', 'CR-PLACarbon'),
        ('14001', 'CR-PLAMatte'),
        ('15001', 'CR-PLAFluo'),
        ('16001', 'CR-TPU'),
        ('17001', 'CR-Wood'),
        ('18001', 'HPUltraPLA'),
        ('19001', 'HP-ASA'),
        ('07001', 'CR-ABS'),
        ('06001', 'CR-PETG'),
        ('04001', 'CR-PLA'),
        ('05001', 'CR-Silk'),
        ('09001', 'EN-PLA+'),
        ('09002', 'ENDERFASTPLA'),
        ('08001', 'Ender-PLA'),
        ('00004', 'GenericABS'),
        ('00007', 'GenericASA'),
        ('00010', 'GenericBVOH'),
        ('00012', 'GenericHIPS'),
        ('00008', 'GenericPA'),
        ('00009', 'GenericPA-CF'),
        ('00015', 'GenericPA6-CF'),
        ('00016', 'GenericPAHT-CF'),
        ('00021', 'GenericPC'),
        ('00020', 'GenericPET'),
        ('00013', 'GenericPET-CF'),
        ('00003', 'GenericPETG'),
        ('00014', 'GenericPETG-CF'),
        ('00001', 'GenericPLA'),
        ('00006', 'GenericPLA-CF'),
        ('00002', 'GenericPLA-Silk'),
        ('00019', 'GenericPP'),
        ('00017', 'GenericPPS'),
        ('00018', 'GenericPPS-CF'),
        ('00011', 'GenericPVA'),
        ('00005', 'GenericTPU'),
        ('03001', 'HyperABS'),
        ('06002', 'HyperPETG'),
        ('01001', 'HyperPLA'),
        ('02001', 'HyperPLA-CF'),
    ]
    
    print("\n" + "="*50)
    print("  MATERIAL CODES")
    print("="*50)
    print(f"{'Code':<10} {'Material Name':<25}")
    print("-"*50)
    
    for code, name in sorted(materials, key=lambda x: x[1]):
        print(f"{code:<10} {name:<25}")
    
    print("="*50 + "\n")

def print_color_table():
    """Print a formatted table of common colors"""
    colors = [
        ('0FFFFFF', 'White'),
        ('0000000', 'Black'),
        ('0FF0000', 'Red'),
        ('000FF00', 'Green (Lime)'),
        ('00000FF', 'Blue'),
        ('0FFFF00', 'Yellow'),
        ('0FF00FF', 'Magenta'),
        ('000FFFF', 'Cyan'),
        ('0FFA500', 'Orange'),
        ('0800080', 'Purple'),
        ('0FFC0CB', 'Pink'),
        ('0A52A2A', 'Brown'),
        ('0808080', 'Gray'),
        ('0C0C0C0', 'Silver'),
        ('0FFD700', 'Gold'),
        ('08B4513', 'SaddleBrown'),
        ('0DC143C', 'Crimson'),
        ('0FF6347', 'Tomato'),
        ('0FF69B4', 'HotPink'),
        ('0FF1493', 'DeepPink'),
        ('0C71585', 'MediumTurquoise'),
        ('000CED1', 'DarkTurquoise'),
        ('000FA9A', 'DarkCyan'),
        ('048D1CC', 'DeepSkyBlue'),
        ('01E90FF', 'DodgerBlue'),
        ('04169E1', 'RoyalBlue'),
        ('00000CD', 'MediumBlue'),
        ('000008B', 'DarkBlue'),
        ('04B0082', 'Indigo'),
        ('09370DB', 'DarkViolet'),
        ('08A2BE2', 'BlueViolet'),
        ('0BA55D3', 'MediumOrchid'),
        ('09932CC', 'DarkOrchid'),
        ('0FF00FF', 'Fuchsia'),
        ('0EE82EE', 'Violet'),
        ('0DDA0DD', 'Plum'),
        ('0ADFF2F', 'LightCyan'),
        ('0F0E68C', 'Khaki'),
        ('032CD32', 'LimeGreen'),
        ('098FB98', 'PaleGreen'),
        ('090EE90', 'LightGreen'),
        ('000FF7F', 'SpringGreen'),
        ('000FA9A', 'MediumSpringGreen'),
        ('02E8B57', 'SeaGreen'),
        ('03CB371', 'MediumSeaGreen'),
        ('0228B22', 'ForestGreen'),
        ('0006400', 'DarkGreen'),
        ('06B8E23', 'OliveDrab'),
        ('0808000', 'Olive'),
        ('0556B2F', 'DarkOliveGreen'),
        ('0BDB76B', 'DarkSeaGreen'),
    ]
    
    print("\n" + "="*70)
    print("  COMMON COLOR CODES (Format: 0RRGGBB)")
    print("="*70)
    print(f"{'Code':<12} {'Color Name':<25} {'RGB':<20}")
    print("-"*70)
    
    for code, name in colors:
        rgb = code[1:]  # Remove leading 0
        r = int(rgb[0:2], 16)
        g = int(rgb[2:4], 16)
        b = int(rgb[4:6], 16)
        rgb_str = f"({r}, {g}, {b})"
        print(f"{code:<12} {name:<25} {rgb_str:<20}")
    
    print("="*70)
    print("\nNote: Prefix colors with '0' not '#' (e.g., 0FF0000 for red)")
    print("="*70 + "\n")

def print_length_table():
    """Print weight to length code mapping"""
    print("\n" + "="*40)
    print("  LENGTH CODES")
    print("="*40)
    print(f"{'Code':<10} {'Weight':<15}")
    print("-"*40)
    print(f"{'0330':<10} {'1.0 kg':<15}")
    print(f"{'0165':<10} {'0.5 kg':<15}")
    print("="*40 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Creality RFID Encryption Helper - Fixed to match HTML implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show reference tables
  %(prog)s list --materials
  %(prog)s list --colors
  %(prog)s list --all

  # Generate key from UID
  %(prog)s genkey 3A14ACF1

  # Build and encrypt custom tag data
  %(prog)s build --batch 1A5 --date 24120 --supplier 1B3D --material 01001 --color 00000FF --length 0330 --serial 000001

  # Complete write workflow (outputs commands)
  %(prog)s write -u 3A14ACF1 --batch 1A5 --date 24120 --material 01001 --color 00000FF

  # Decrypt read data
  %(prog)s decrypt <block4_hex> <block5_hex> <block6_hex>

  # PROXMARK3 INTEGRATION:
  # Write to tag using Proxmark3 (auto-reads UID)
  %(prog)s pm3write --material 01001 --color 0FF0000 --length 0330 --serial 000001
  
  # Write to already-encrypted tag
  %(prog)s pm3write --material 04001 --color 000FF00 --encrypted
  
  # Read and decrypt tag using Proxmark3
  %(prog)s pm3read
  
  # Read with manual UID
  %(prog)s pm3read --uid 3A14ACF1
"""
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='Show reference tables for materials, colors, and length codes')
    list_parser.add_argument('--materials', action='store_true', help='Show material codes table')
    list_parser.add_argument('--colors', action='store_true', help='Show color codes table')
    list_parser.add_argument('--lengths', action='store_true', help='Show length codes table')
    list_parser.add_argument('--all', action='store_true', help='Show all reference tables')
    
    # Generate key command
    key_parser = subparsers.add_parser('genkey', help='Generate key from UID')
    key_parser.add_argument('uid', help='UID in hex (e.g., 04A1B2C3 or 3A14ACF1)')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt tag data')
    encrypt_parser.add_argument('data', help='Tag data as ASCII string (48 chars)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt tag data')
    decrypt_parser.add_argument('block1', help='Block 4 data (32 hex chars)')
    decrypt_parser.add_argument('block2', help='Block 5 data (32 hex chars)')
    decrypt_parser.add_argument('block3', help='Block 6 data (32 hex chars)')
    
    # Build command
    build_parser = subparsers.add_parser('build', help='Build and encrypt tag data')
    build_parser.add_argument('--batch', default='1A5', help='Batch (3 chars, default: 1A5)')
    build_parser.add_argument('--date', default='24120', help='Date YYMDD (5 chars, default: 24120)')
    build_parser.add_argument('--supplier', default='1B3D', help='Supplier (4 chars, default: 1B3D)')
    build_parser.add_argument('--material', default='01001', help='Material code (5 chars, default: 01001=HyperPLA)')
    build_parser.add_argument('--color', default='00000FF', help='Color 0RRGGBB (7 chars, default: 00000FF=blue)')
    build_parser.add_argument('--length', default='0330', help='Length (4 chars, 0330=1kg, 0165=0.5kg)')
    build_parser.add_argument('--serial', default='000001', help='Serial (6 chars, default: 000001)')
    build_parser.add_argument('--reserve', default='00000000000000', help='Reserve (14 chars, default: zeros)')
    build_parser.add_argument('-u', '--uid', help='Tag UID (will generate key automatically)')
    
    # Write command (all-in-one)
    write_parser = subparsers.add_parser('write', help='Complete write workflow with UID')
    write_parser.add_argument('-u', '--uid', required=True, help='Tag UID (e.g., 3A14ACF1)')
    write_parser.add_argument('--batch', default='1A5', help='Batch (3 chars)')
    write_parser.add_argument('--date', default='24120', help='Date YYMDD (5 chars)')
    write_parser.add_argument('--supplier', default='1B3D', help='Supplier (4 chars)')
    write_parser.add_argument('--material', default='01001', help='Material code (5 chars)')
    write_parser.add_argument('--color', default='00000FF', help='Color 0RRGGBB (7 chars)')
    write_parser.add_argument('--length', default='0330', help='Length (4 chars)')
    write_parser.add_argument('--serial', default='000001', help='Serial (6 chars)')
    write_parser.add_argument('--encrypted', action='store_true', help='Tag is already encrypted (use generated key)')
    
    # PM3 Write command (auto-read UID and write to tag)
    pm3write_parser = subparsers.add_parser('pm3write', help='Write to tag using Proxmark3 (auto-reads UID)')
    pm3write_parser.add_argument('--batch', default='1A5', help='Batch (3 chars)')
    pm3write_parser.add_argument('--date', default='24120', help='Date YYMDD (5 chars)')
    pm3write_parser.add_argument('--supplier', default='1B3D', help='Supplier (4 chars)')
    pm3write_parser.add_argument('--material', default='01001', help='Material code (5 chars)')
    pm3write_parser.add_argument('--color', default='00000FF', help='Color 0RRGGBB (7 chars)')
    pm3write_parser.add_argument('--length', default='0330', help='Length (4 chars)')
    pm3write_parser.add_argument('--serial', default='000001', help='Serial (6 chars)')
    pm3write_parser.add_argument('--encrypted', action='store_true', help='Tag is already encrypted')
    pm3write_parser.add_argument('--skip-read', action='store_true', help='Skip UID read, use --uid instead')
    pm3write_parser.add_argument('--uid', help='Manual UID (use with --skip-read)')
    
    # PM3 Read command (read and decrypt tag data)
    pm3read_parser = subparsers.add_parser('pm3read', help='Read and decrypt tag data using Proxmark3')
    pm3read_parser.add_argument('--uid', help='Manual UID (if not auto-reading)')
    
    args = parser.parse_args()
    
    if args.command == 'list':
        # Show reference tables
        if args.all or (not args.materials and not args.colors and not args.lengths):
            # Show all if --all or no specific flags
            print_material_table()
            print_color_table()
            print_length_table()
        else:
            if args.materials:
                print_material_table()
            if args.colors:
                print_color_table()
            if args.lengths:
                print_length_table()
        return
    
    elif args.command == 'genkey':
        key = generate_key_from_uid(args.uid)
        print(f"\nGenerated Key B from UID {args.uid}:")
        print(key)
        print(f"\nFormatted for Proxmark3:")
        print(f"{' '.join([key[i:i+2] for i in range(0, len(key), 2)])}")
        
    elif args.command == 'encrypt':
        if len(args.data) != 48:
            print(f"Warning: Data should be 48 characters, got {len(args.data)}")
        block1, block2, block3 = encrypt_tag_data(args.data)
        print("\nEncrypted blocks:")
        print(f"Block 4: {block1}")
        print(f"Block 5: {block2}")
        print(f"Block 6: {block3}")
        
    elif args.command == 'decrypt':
        ascii_data, hex_data = decrypt_tag_data(args.block1, args.block2, args.block3)
        print("\nDecrypted ASCII data:")
        print(ascii_data)
        print("\nDecrypted hex data:")
        print(hex_data)
        parse_tag_data(ascii_data)
        
    elif args.command == 'build':
        tag_data = build_tag_data(
            batch=args.batch,
            date=args.date,
            supplier=args.supplier,
            material=args.material,
            color=args.color,
            length=args.length,
            serial=args.serial,
            reserve=args.reserve
        )
        print(f"\nBuilt tag data (ASCII):")
        print(tag_data)
        print(f"Length: {len(tag_data)} characters")
        
        block1, block2, block3 = encrypt_tag_data(tag_data)
        print("\n=== Encrypted blocks for writing ===")
        print(f"Block 4: {block1}")
        print(f"Block 5: {block2}")
        print(f"Block 6: {block3}")
        
        # Generate key if UID provided
        if args.uid:
            key_b = generate_key_from_uid(args.uid)
            print(f"\n=== Generated Key B from UID {args.uid} ===")
            print(f"Key: {key_b}")
            
            print("\n=== Proxmark3 commands for ENCRYPTED tag ===")
            print(f"hf mf wrbl --blk 4 -b -k {key_b} -d {block1}")
            print(f"hf mf wrbl --blk 5 -b -k {key_b} -d {block2}")
            print(f"hf mf wrbl --blk 6 -b -k {key_b} -d {block3}")
            
            # Also show sector 1 key setup for new tags
            print(f"\n=== If tag needs encryption setup (not encrypted yet) ===")
            print(f"# First write the data using default key:")
            print(f"hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d {block1}")
            print(f"hf mf wrbl --blk 5 -k FFFFFFFFFFFF -d {block2}")
            print(f"hf mf wrbl --blk 6 -k FFFFFFFFFFFF -d {block3}")
            print(f"# Then set sector 1 security:")
            print(f"hf mf wrbl --blk 7 -k FFFFFFFFFFFF -d {key_b}FF078069{key_b}")
        else:
            print("\n=== Proxmark3 commands ===")
            print("(Run with -u <UID> to generate the key)")
    
    elif args.command == 'write':
        # All-in-one write command
        print(f"\n{'='*60}")
        print(f"  COMPLETE WRITE SETUP FOR TAG UID: {args.uid}")
        print(f"{'='*60}")
        
        # Generate key
        print("\n[1/3] Generating authentication key from UID...")
        key_b = generate_key_from_uid(args.uid)
        print(f"      Key B: {key_b}")
        
        # Build tag data
        print(f"\n[2/3] Building tag data...")
        tag_data = build_tag_data(
            batch=args.batch,
            date=args.date,
            supplier=args.supplier,
            material=args.material,
            color=args.color,
            length=args.length,
            serial=args.serial
        )
        print(f"      Batch: {args.batch}")
        print(f"      Date: {args.date}")
        print(f"      Supplier: {args.supplier}")
        print(f"      Material: {args.material}")
        print(f"      Color: #{args.color[1:]}")
        print(f"      Length: {args.length}")
        print(f"      Serial: {args.serial}")
        print(f"      Raw ASCII: {tag_data}")
        
        # Encrypt
        print(f"\n[3/3] Encrypting data...")
        block1, block2, block3 = encrypt_tag_data(tag_data)
        print(f"      Block 4: {block1}")
        print(f"      Block 5: {block2}")
        print(f"      Block 6: {block3}")
        
        # Output commands
        print(f"\n{'='*60}")
        if args.encrypted:
            print(f"  COMMANDS FOR ALREADY-ENCRYPTED TAG:")
            print(f"{'='*60}\n")
            print(f"hf mf wrbl --blk 4 -b -k {key_b} -d {block1}")
            print(f"hf mf wrbl --blk 5 -b -k {key_b} -d {block2}")
            print(f"hf mf wrbl --blk 6 -b -k {key_b} -d {block3}")
        else:
            print(f"  COMMANDS FOR NEW TAG (not encrypted yet):")
            print(f"{'='*60}\n")
            print(f"# Write encrypted data using default key:")
            print(f"hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d {block1}")
            print(f"hf mf wrbl --blk 5 -k FFFFFFFFFFFF -d {block2}")
            print(f"hf mf wrbl --blk 6 -k FFFFFFFFFFFF -d {block3}")
            print(f"\n# Set sector 1 security (encrypts the tag):")
            print(f"hf mf wrbl --blk 7 -k FFFFFFFFFFFF -d {key_b}FF078069{key_b}")
            print(f"\nNote: After running these commands, use --encrypted flag for future writes")
        print(f"\n{'='*60}\n")
    
    elif args.command == 'pm3write':
        # Proxmark3 auto-write command
        # Check if Proxmark3 is available
        if not check_pm3_available():
            print("[!] Error: Proxmark3 client (pm3 or proxmark3) not found in PATH")
            print("[!] Please install Proxmark3 Iceman fork and ensure it's in your PATH")
            sys.exit(1)
        
        # Get UID
        if args.skip_read and args.uid:
            uid = args.uid
            print(f"[*] Using provided UID: {uid}")
        else:
            uid = read_uid_from_tag()
            if not uid:
                print("[!] Failed to read UID from tag")
                print("[!] Make sure tag is on antenna and try again")
                print("[!] Or use --skip-read --uid <UID> to provide UID manually")
                sys.exit(1)
        
        # Build tag data
        tag_data = build_tag_data(
            batch=args.batch,
            date=args.date,
            supplier=args.supplier,
            material=args.material,
            color=args.color,
            length=args.length,
            serial=args.serial
        )
        
        print(f"\n[*] Tag Configuration:")
        print(f"    Batch: {args.batch}")
        print(f"    Date: {args.date}")
        print(f"    Supplier: {args.supplier}")
        print(f"    Material: {args.material}")
        print(f"    Color: #{args.color[1:]}")
        print(f"    Length: {args.length}")
        print(f"    Serial: {args.serial}")
        
        # Write to tag
        success = write_to_tag_pm3(uid, tag_data, args.encrypted)
        
        if success:
            print("[✓] Tag written successfully!")
            sys.exit(0)
        else:
            print("[✗] Tag write failed!")
            sys.exit(1)
    
    elif args.command == 'pm3read':
        # Proxmark3 read and decrypt command
        # Check if Proxmark3 is available
        if not check_pm3_available():
            print("[!] Error: Proxmark3 client (pm3 or proxmark3) not found in PATH")
            print("[!] Please install Proxmark3 Iceman fork and ensure it's in your PATH")
            sys.exit(1)
        
        # Get UID
        if args.uid:
            uid = args.uid
            print(f"[*] Using provided UID: {uid}")
        else:
            uid = read_uid_from_tag()
            if not uid:
                print("[!] Failed to read UID from tag")
                sys.exit(1)
        
        # Generate key
        print(f"\n[*] Generating key from UID...")
        key_b = generate_key_from_uid(uid)
        print(f"[+] Key B: {key_b}")
        
        # Read blocks
        print(f"\n[*] Reading encrypted blocks from tag...")
        pm3_cmd = get_pm3_command()
        
        blocks = []
        for block_num in [4, 5, 6]:
            print(f"[*] Reading block {block_num}...")
            try:
                result = subprocess.run(
                    [pm3_cmd, '-c', f'hf mf rdbl --blk {block_num} -b -k {key_b}'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                # Parse block data from output
                # Iceman format: "[=]   4 | 0C CE 98 10 91 52 DC 97 CD 6F AA B5 49 71 70 EE | .....R...o..Iqp."
                # Also handle: "data: XX XX XX..." or "blk XX: XX XX XX..."
                patterns = [
                    # Iceman format with block number and pipe
                    rf'\[\=\]\s+{block_num}\s+\|\s+([0-9a-fA-F\s]{{47}})\s+\|',
                    # Alternative: data: format
                    r'data[:\s]+([0-9a-fA-F\s]{47})',
                    # Alternative: blk X: format
                    rf'blk\s+{block_num}[:\s]+([0-9a-fA-F\s]{{47}})',
                ]
                
                block_data = None
                for pattern in patterns:
                    match = re.search(pattern, result.stdout, re.IGNORECASE)
                    if match:
                        block_data = match.group(1).replace(' ', '').upper()
                        break
                
                if block_data and len(block_data) == 32:  # 32 hex chars = 16 bytes
                    blocks.append(block_data)
                    print(f"[+] Block {block_num}: {block_data}")
                else:
                    print(f"[!] Could not parse block {block_num} data")
                    print("[!] Output:")
                    print(result.stdout)
                    sys.exit(1)
                    
            except Exception as e:
                print(f"[!] Error reading block {block_num}: {e}")
                sys.exit(1)
        
        # Decrypt
        if len(blocks) == 3:
            print(f"\n[*] Decrypting tag data...")
            ascii_data, hex_data = decrypt_tag_data(blocks[0], blocks[1], blocks[2])
            print(f"\n[+] Decrypted ASCII data:")
            print(f"    {ascii_data}")
            parse_tag_data(ascii_data)
        else:
            print("[!] Failed to read all blocks")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
