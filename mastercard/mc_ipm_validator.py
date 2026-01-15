import os
import sys

# --- 1. DATA ELEMENT MAP & VALIDATION RULES ---
# Standard Mastercard IPM field specifications
DEFAULT_DE_MAP = {
    2: ('LLVAR', 19),   3: ('FIXED', 6),    4: ('FIXED', 12),
    5: ('FIXED', 12),   6: ('FIXED', 12),   9: ('FIXED', 8),
    10: ('FIXED', 8),   12: ('FIXED', 6),   14: ('FIXED', 4),
    22: ('FIXED', 3),   23: ('FIXED', 3),   24: ('FIXED', 3),
    30: ('FIXED', 8),   31: ('LLVAR', 23),  32: ('LLVAR', 11),
    37: ('FIXED', 12),  38: ('FIXED', 6),   42: ('FIXED', 15),
    43: ('FIXED', 40),  48: ('LLLVAR', 999), 49: ('FIXED', 3),
    50: ('FIXED', 3),   71: ('FIXED', 8),   124: ('LLLVAR', 999)
}

# Mandatory fields per MTI based on Mastercard IPM requirements
MTI_RULES = {
    "1240": [3, 4, 12, 24, 31, 42, 43, 49], # Presentment Requirements
    "1644": [1, 24, 48, 71]                 # File Bulk Response Requirements
}

class Logger(object):
    """Redirects stdout to both console and a log file."""
    def __init__(self, filename="mastercard_debug_report.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
    def flush(self): pass

# --- 2. CORE LOGIC FUNCTIONS ---

def validate_mastercard_rules(mti, fields_present):
    """Checks if the MTI contains all mandatory Data Elements."""
    if mti in MTI_RULES:
        required = MTI_RULES[mti]
        missing = [f for f in required if f not in fields_present]
        if missing:
            return f"❌ [RULE ERROR] MTI {mti} missing fields: {missing}"
        return f"✅ [RULE SUCCESS] MTI {mti} mandatory fields present"
    return "ℹ️ [INFO] No validation rules defined for this MTI"

def translate_data(data, encoding):
    """Converts raw bytes to text based on the selected encoding."""
    if encoding == 'EBCDIC':
        try:
            return data.decode('cp500') # International EBCDIC
        except:
            return "(Hex) " + data.hex().upper()
    return "".join([chr(b) if 32 <= b <= 126 else "." for b in data])

def parse_data_elements(buffer, fields_present):
    """Iterates through the buffer to extract fields based on the Bitmap."""
    ptr, results = 0, []
    for f_id in fields_present:
        if f_id == 1 or ptr >= len(buffer): continue
        f_type, f_len = DEFAULT_DE_MAP.get(f_id, ('FIXED', 0))
        if f_len == 0: continue # Skip if field definition is missing
        try:
            if f_type == 'FIXED': 
                actual_len = f_len
            elif f_type == 'LLVAR':
                actual_len = int(buffer[ptr:ptr+1].hex(), 16)
                ptr += 1
            elif f_type == 'LLLVAR':
                actual_len = int(buffer[ptr:ptr+2].hex(), 16)
                ptr += 2
            field_data = buffer[ptr:ptr+actual_len]
            results.append((f_id, field_data))
            ptr += actual_len
        except: 
            break
    return results

# --- 3. MAIN PROCESSING ---

def process_record(record, index, encoding):
    """Parses MTI, Bitmap, and Data Elements for a single record."""
    mti = record[12:14].hex()
    p_bitmap = record[14:22]
    has_sec = (p_bitmap[0] & 0x80) != 0
    bit_str = bin(int(p_bitmap.hex(), 16))[2:].zfill(64)
    
    data_start = 22
    if has_sec:
        bit_str += bin(int(record[22:30].hex(), 16))[2:].zfill(64)
        data_start = 30
    
    fields = [i+1 for i, b in enumerate(bit_str) if b == '1']
    
    # Run validation check
    validation_msg = validate_mastercard_rules(mti, fields)
    
    print(f"\n{'='*95}\n[RECORD #{index}] MTI: {mti} | {validation_msg}\n{'='*95}")
    
    parsed = parse_data_elements(record[data_start:], fields)
    for f_id, f_data in parsed:
        text = translate_data(f_data, encoding)
        print(f"DE {f_id:03d} | {f_data.hex().upper():<30} | {text}")

def main():
    f_path = input("Enter File Path: ").strip()
    try:
        b_size = int(input("Enter Block Size (e.g., 1012): "))
        p_len = int(input("Enter Length Prefix (default 4): ") or 4)
    except ValueError:
        print("Invalid numeric input. Exiting.")
        return

    print("\nSelect Encoding:\n1. EBCDIC (Standard for Mastercard)\n2. ASCII")
    encoding = 'EBCDIC' if input("Choice (1/2): ") == '1' else 'ASCII'

    # Initialize Logger
    sys.stdout = Logger()
    
    try:
        if not os.path.exists(f_path):
            print(f"File not found: {f_path}")
            return

        with open(f_path, 'rb') as f:
            # Read file in blocks
            all_data = b"".join(iter(lambda: f.read(b_size), b""))

        # Verify first record to ensure parameters are correct
        if len(all_data) < p_len:
            print("File is empty or too short.")
            return

        first_len = int.from_bytes(all_data[0:p_len], byteorder='big')
        if not (10 < first_len < 5000):
            print(f"CRITICAL: Verification failed. First record length ({first_len}) is unrealistic.")
            return

        print(f"🚀 Verification successful. Processing {len(all_data)} bytes...\n")
        
        offset, rec_num = 0, 1
        while offset + p_len < len(all_data):
            m_len = int.from_bytes(all_data[offset:offset+p_len], byteorder='big')
            if m_len == 0 or m_len > 10000: break # Break on padding or corruption
            
            record_raw = all_data[offset+p_len : offset+p_len+m_len]
            process_record(record_raw, rec_num, encoding)
            
            offset += (p_len + m_len)
            rec_num += 1
            
    except Exception as e:
        print(f"Runtime Error: {e}")
    finally:
        sys.stdout = sys.stdout.terminal
        print(f"\nProcess finished. Results saved to 'mastercard_debug_report.txt'.")

if __name__ == "__main__":
    main()