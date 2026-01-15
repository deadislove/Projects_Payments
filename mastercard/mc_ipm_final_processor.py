import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any

# ============================================================
# 1. Data Models & Configurations
# ============================================================

@dataclass
class TransactionContext:
    index: int
    mti: str
    fields: Dict[int, Any]
    status: str
    validation_msg: str
    correlation_key: Tuple = None

@dataclass
class BatchSummary:
    total_count: int = 0
    total_amount: int = 0
    errors: List[str] = field(default_factory=list)

# Mandatory field rules for Mastercard
MTI_RULES = {
    "1240": [3, 4, 12, 24, 31, 42, 43, 49],
    "1644": [1, 24, 48, 71]
}

# Field Mapping: {FieldNo: (Type, LengthIndicatorSize or FixedLength)}
FIELD_MAP = {
    2: ('LLVAR', 2),  3: ('FIXED', 6),   4: ('FIXED', 12),
    7: ('FIXED', 10), 11: ('FIXED', 6),  12: ('FIXED', 6),
    24: ('FIXED', 3), 31: ('LLVAR', 2),  32: ('LLVAR', 2),
    37: ('FIXED', 12), 41: ('FIXED', 8),  42: ('FIXED', 15),
    43: ('FIXED', 40), 48: ('LLLVAR', 3), 49: ('FIXED', 3),
    71: ('FIXED', 8), 124: ('LLLVAR', 3)
}

# ============================================================
# 2. Logger
# ============================================================

class Logger(object):
    def __init__(self, filename="mastercard_ipm_report.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
    def flush(self): pass

# ============================================================
# 3. Encoding & Length Detection
# ============================================================

def detect_and_translate(data: bytes) -> str:
    """Translate bytes intelligently: EBCDIC or ASCII fallback."""
    if not data: return ""
    if all(0x40 <= b <= 0xFF for b in data if b != 0x00):
        try: return data.decode('cp500')
        except: pass
    return data.decode('ascii', errors='replace')

def parse_length(data: bytes, offset: int, size: int) -> Tuple[int, int]:
    """Detect length encoding (Binary / ASCII / EBCDIC)"""
    raw = data[offset:offset+size]
    if len(raw) < size:
        raise ValueError(f"Insufficient data for length at offset {offset}")
    # 1-byte binary
    if size == 1: return raw[0], offset + 1
    # 2-byte binary
    if size == 2 and raw[0] < 0x10: return int.from_bytes(raw, 'big'), offset + 2
    # ASCII / EBCDIC numeric
    val_str = detect_and_translate(raw)
    try:
        return int(val_str), offset + size
    except ValueError:
        raise ValueError(f"Invalid length indicator at offset {offset}: {raw.hex()}")

# ============================================================
# 4. Subfield Parsing (DE48 / DE124)
# ============================================================

def parse_subfields(data: bytes) -> Dict[str, str]:
    """Parse IPM subfields [TAG2][LEN2][VALUE] recursively."""
    offset, result = 0, {}
    while offset + 4 <= len(data):
        tag = detect_and_translate(data[offset:offset+2])
        try:
            length = int(detect_and_translate(data[offset+2:offset+4]))
            val = detect_and_translate(data[offset+4:offset+4+length])
            result[tag] = val
            offset += 4 + length
        except:
            break
    return result

# ============================================================
# 5. Record Parsing
# ============================================================

def parse_record(data: bytes, index: int) -> TransactionContext:
    offset = 0
    try:
        # ---- MTI ----
        mti = detect_and_translate(data[offset:offset+4])
        offset += 4

        # ---- Bitmap ----
        bitmap = data[offset:offset+8]
        offset += 8
        fields_present = []
        for i, b in enumerate(bitmap):
            for bit in range(8):
                if b & (1 << (7-bit)): fields_present.append(i*8 + bit + 1)
        # Secondary Bitmap
        if 1 in fields_present:
            sec_bitmap = data[offset:offset+8]
            offset += 8
            for i, b in enumerate(sec_bitmap):
                for bit in range(8):
                    if b & (1 << (7-bit)): fields_present.append(64 + i*8 + bit + 1)
            fields_present.remove(1)

        # ---- Parse Fields ----
        parsed_fields = {}
        for f_no in sorted(fields_present):
            if f_no not in FIELD_MAP: continue
            f_type, f_size = FIELD_MAP[f_no]

            if f_type == 'FIXED':
                val = data[offset:offset+f_size]
                offset += f_size
            else: # LLVAR / LLLVAR
                length, offset = parse_length(data, offset, f_size)
                val = data[offset:offset+length]
                offset += length

            # Subfields
            if f_no in (48, 124):
                parsed_fields[f_no] = parse_subfields(val)
            else:
                parsed_fields[f_no] = detect_and_translate(val)

        # ---- Validation ----
        missing = [f for f in MTI_RULES.get(mti, []) if f not in fields_present]
        v_msg = "✅ Valid" if not missing else f"❌ Missing: {missing}"

        # ---- Correlation Key ----
        corr_key = (
            parsed_fields.get(11), # STAN
            parsed_fields.get(37), # RRN
            parsed_fields.get(41), # TID
            parsed_fields.get(42)  # MID
        )

        return TransactionContext(index, mti, parsed_fields, "Processed", v_msg, corr_key)
    except Exception as e:
        return TransactionContext(index, "ERR", {}, "Failed", str(e))

# ============================================================
# 6. Main Processing Logic
# ============================================================

def main():
    print("=== Mastercard IPM Pro Final Processor ===")
    f_path = input("File Path: ").strip()
    block_size = int(input("Block Size (e.g., 1012): "))
    p_len = int(input("Prefix Length (default 4): ") or 4)

    sys.stdout = Logger()
    summary = BatchSummary()

    try:
        # Load File
        with open(f_path, 'rb') as f:
            full_content = b"".join(iter(lambda: f.read(block_size), b""))

        offset, idx = 0, 1
        while offset + p_len < len(full_content):
            msg_len = int.from_bytes(full_content[offset:offset+p_len], 'big')
            if msg_len == 0: break

            record_data = full_content[offset+p_len : offset+p_len+msg_len]
            tx = parse_record(record_data, idx)

            # Print Result
            print(f"\nRecord #{tx.index:03d} | MTI: {tx.mti} | {tx.validation_msg}")
            for f_id, f_val in tx.fields.items():
                if isinstance(f_val, dict):
                    print(f"  DE {f_id:03d} Subfields: {f_val}")
                else:
                    print(f"  DE {f_id:03d}: {f_val}")

            # Update Summary
            summary.total_count += 1
            if 4 in tx.fields:
                try: summary.total_amount += int(tx.fields[4])
                except: pass

            offset += (p_len + msg_len)
            idx += 1

        # ---- Batch Summary ----
        print("\n" + "="*50)
        print(f"BATCH SUMMARY:")
        print(f"Total Records: {summary.total_count}")
        print(f"Total Amount : {summary.total_amount}")
        print("="*50)

    except Exception as e:
        print(f"[CRITICAL ERROR] {e}")

if __name__ == "__main__":
    main()
