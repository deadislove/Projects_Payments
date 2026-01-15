import string
from typing import List, Dict, Tuple

# ============================
# Transport Detection
# ============================

def is_hex(data: bytes) -> bool:
    try:
        text = data.decode("ascii").strip()
        return len(text) % 2 == 0 and all(c in string.hexdigits for c in text)
    except Exception:
        return False

def detect_transport(data: bytes) -> str:
    """Detect if transport is HEX, ASCII, or Binary"""
    if is_hex(data):
        return "HEX"
    printable_ratio = sum(1 for b in data if 32 <= b <= 126) / len(data)
    return "ASCII" if printable_ratio > 0.95 else "BINARY"

def strip_length_header(data: bytes) -> bytes:
    """Remove 2-byte or 4-byte message length header if present"""
    for size in (2, 4):
        if len(data) < size:
            continue
        length = int.from_bytes(data[:size], "big")
        if length == len(data) - size:
            return data[size:]
    return data

# ============================
# MTI Decode
# ============================

def decode_mti(data: bytes) -> Tuple[str, str]:
    """Detect MTI encoding: ASCII or EBCDIC (cp500)"""
    for enc in ("ascii", "cp500"):
        try:
            mti = data[:4].decode(enc)
            if mti.isdigit():
                return mti, enc.upper()
        except:
            continue
    raise ValueError("Invalid MTI")

# ============================
# Bitmap Parsing
# ============================

def bitmap_to_bits(bitmap: bytes) -> List[int]:
    """Convert bitmap bytes to a list of set DE numbers"""
    bits = []
    for i, b in enumerate(bitmap):
        for bit in range(8):
            if b & (1 << (7 - bit)):
                bits.append(i * 8 + bit + 1)
    return bits

# ============================
# DE Parsing Helper with Length Warning
# ============================

def parse_single_de_auto(data: bytes, offset: int) -> Tuple[bytes, int]:
    """
    Automatically detect DE length and return bytes slice
    - LLVAR: 2-digit length prefix
    - LLLVAR: 3-digit length prefix
    - BCD/Numeric/FIXED/Binary: fallback to remaining data
    - Warn if specified length exceeds remaining bytes
    """
    if offset >= len(data):
        return b"", offset

    remaining = len(data) - offset

    # Try LLLVAR (3 ASCII digits)
    if remaining >= 3 and data[offset:offset+3].isdigit():
        length = int(data[offset:offset+3].decode("ascii"))
        offset += 3
        if length > remaining - 3:
            print(f"Warning: LLLVAR DE length {length} exceeds remaining {remaining-3} bytes at offset {offset-3}")
            field_bytes = data[offset:]  # take remaining
            offset = len(data)
        else:
            field_bytes = data[offset:offset+length]
            offset += length
        return field_bytes, offset

    # Try LLVAR (2 ASCII digits)
    if remaining >= 2 and data[offset:offset+2].isdigit():
        length = int(data[offset:offset+2].decode("ascii"))
        offset += 2
        if length > remaining - 2:
            print(f"Warning: LLVAR DE length {length} exceeds remaining {remaining-2} bytes at offset {offset-2}")
            field_bytes = data[offset:]
            offset = len(data)
        else:
            field_bytes = data[offset:offset+length]
            offset += length
        return field_bytes, offset

    # Fallback: read remaining until next DE (or message end)
    field_bytes = data[offset:]
    offset = len(data)
    return field_bytes, offset

# ============================
# DE Display Helper
# ============================

def display_de_raw_safe(data: bytes, bits: List[int], offset: int) -> Dict[int, Dict[str, str]]:
    """
    Display each DE:
    - raw bytes (hex)
    - human-readable text (ASCII decode if possible, fallback hex)
    """
    de_dict = {}
    for bit in sorted(bits):
        if bit == 1:
            continue  # skip bitmap

        field_bytes, offset = parse_single_de_auto(data, offset)

        # Human-readable decode
        try:
            text = field_bytes.decode("ascii")
            if not any(c in string.printable for c in text):
                text = field_bytes.hex()
        except:
            text = field_bytes.hex()

        de_dict[bit] = {"raw": field_bytes.hex(), "text": text}

    return de_dict

# ============================
# Main Parser
# ============================

def parse_iso8583_safe(path: str) -> Dict:
    raw = open(path, "rb").read()

    transport = detect_transport(raw)
    if transport == "HEX":
        raw = bytes.fromhex(raw.decode())

    raw = strip_length_header(raw)

    mti, mti_enc = decode_mti(raw)
    offset = 4

    primary = raw[offset:offset+8]
    bits = bitmap_to_bits(primary)
    offset += 8

    if 1 in bits:  # secondary bitmap
        secondary = raw[offset:offset+8]
        bits += bitmap_to_bits(secondary)
        offset += 8

    de_raw = display_de_raw_safe(raw, bits, offset)

    return {
        "Transport Encoding": transport,
        "MTI": mti,
        "MTI Encoding": mti_enc,
        "Bitmap Bits": sorted(bits),
        "DE Raw Display": de_raw
    }

# ============================
# Entry Point
# ============================

if __name__ == "__main__":
    path = input("Enter ISO 8583 message file path: ").strip()
    try:
        result = parse_iso8583_safe(path)

        print("\n=== ISO 8583 RAW DISPLAY ===")
        print(f"Transport: {result['Transport Encoding']}")
        print(f"MTI: {result['MTI']} ({result['MTI Encoding']})")
        print(f"Bitmap Bits: {result['Bitmap Bits']}")
        print("\n--- DE Raw Content ---")
        for bit, val in result["DE Raw Display"].items():
            print(f"DE {bit:03d}: RAW={val['raw']}  TEXT={val['text']}")
    except Exception as e:
        print(f"Parsing failed: {e}")
