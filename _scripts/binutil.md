---
title: "Binutil (common operations)"
categories: [utility]
tags: [hash, base64, xor, convert, unpack, entropy, extract, yara, disassemble, pe-headers, iocs]
---

{% raw %}
```python
import argparse
import hashlib
import base64
import re
import struct
import os

def calc_hashes(filepath):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    for name, h in hashes.items():
        print(f"{name.upper()}: {h.hexdigest()}")

def base64_decode(input_str):
    decoded = base64.b64decode(input_str)
    print("Decoded (Base64):", decoded)

def xor_decode(hex_str, key):
    data = bytes.fromhex(hex_str)
    key_bytes = key.encode()
    decoded = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])
    print("Decoded (XOR):", decoded)

def string_to_bytes(string):
    print("Byte representation:", string.encode())

def hex_to_bytes(hex_string):
    print("Converted bytes:", bytes.fromhex(hex_string))

def unpack_le(hex_string):
    data = bytes.fromhex(hex_string)
    print("LE unpacked int:", struct.unpack('<I', data[:4])[0])

def calc_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        print("Empty file.")
        return
    occur = [0] * 256
    for b in data:
        occur[b] += 1
    entropy = 0
    for count in occur:
        if count:
            p = count / len(data)
            entropy -= p * (p).bit_length()
    print(f"Entropy: {entropy:.4f}")

def extract_strings(filepath, min_length=4):
    with open(filepath, 'rb') as f:
        data = f.read()
    strings = re.findall(rb'[ -~]{%d,}' % min_length, data)
    for s in strings:
        print(s.decode(errors='ignore'))

def yara_rule_from_strings(name, strings):
    rule = f"rule {name}\n    strings:\n"
    for i, s in enumerate(strings):
        rule += f"        $s{i} = \"{s}\"\n"
    rule += "    condition:\n        all of them\n}"
    print(rule)

def disassemble_shellcode(hex_string):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except ImportError:
        print("Capstone is not installed. Run: pip install capstone")
        return
    shellcode = bytes.fromhex(hex_string)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(shellcode, 0x1000):
        print(f"0x{i.address:x}:	{i.mnemonic}	{i.op_str}")

def parse_pe_headers(filepath):
    try:
        import pefile
    except ImportError:
        print("pefile is not installed. Run: pip install pefile")
        return
    pe = pefile.PE(filepath)
    print("[*] Sections:")
    for section in pe.sections:
        print(f"  {section.Name.strip().decode(errors='ignore')}: {hex(section.VirtualAddress)} - {hex(section.Misc_VirtualSize)}")

def extract_iocs(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    text = data.decode('utf-8', errors='ignore')
    urls = re.findall(r'https?://[\w./\-]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    emails = re.findall(r'[\w.-]+@[\w.-]+', text)
    print("[*] URLs:")
    for url in urls:
        print("  ", url)
    print("[*] IPs:")
    for ip in ips:
        print("  ", ip)
    print("[*] Emails:")
    for email in emails:
        print("  ", email)

def carve_pe_from_memory(filepath, output_dir="carved"):
    with open(filepath, "rb") as f:
        data = f.read()
    matches = [m.start() for m in re.finditer(b'MZ', data)]
    os.makedirs(output_dir, exist_ok=True)
    for i, offset in enumerate(matches):
        chunk = data[offset:offset + 1024*1024]
        out_path = os.path.join(output_dir, f"carved_{i}.exe")
        with open(out_path, "wb") as f:
            f.write(chunk)
        print(f"[+] Carved PE saved to: {out_path}")

def batch_scan(directory):
    print(f"[+] Scanning directory: {directory}")
    for root, dirs, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            try:
                size = os.path.getsize(path)
                sha256 = hashlib.sha256(open(path, 'rb').read()).hexdigest()
                print(f"{path} | {size} bytes | SHA256: {sha256}")
            except Exception as e:
                print(f"Failed to process {path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Binary Analysis Toolkit")
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('hash', help="Calculate MD5/SHA1/SHA256 hashes")
    subparsers.add_parser('entropy', help="Calculate file entropy")
    subparsers.add_parser('strings', help="Extract ASCII strings from file")

    b64_parser = subparsers.add_parser('b64decode', help="Decode Base64 string")
    b64_parser.add_argument('string')

    xor_parser = subparsers.add_parser('xordecode', help="XOR decode hex string with key")
    xor_parser.add_argument('hex_string')
    xor_parser.add_argument('key')

    str2b = subparsers.add_parser('str2bytes', help="Convert string to bytes")
    str2b.add_argument('string')

    hex2b = subparsers.add_parser('hex2bytes', help="Convert hex string to bytes")
    hex2b.add_argument('hex_string')

    unpack = subparsers.add_parser('unpackle', help="Unpack little-endian hex string to int")
    unpack.add_argument('hex_string')

    yara = subparsers.add_parser('yara', help="Generate YARA rule from strings")
    yara.add_argument('name')
    yara.add_argument('strings', nargs='+')

    shellcode = subparsers.add_parser('disasm', help="Disassemble shellcode (x86)")
    shellcode.add_argument('hex_string')

    peparse = subparsers.add_parser('peparse', help="Parse PE file headers")
    peparse.add_argument('file')

    ioc = subparsers.add_parser('iocs', help="Extract IOCs (URLs, IPs, Emails)")
    ioc.add_argument('file')

    carve = subparsers.add_parser('carvepe', help="Carve PE files from memory dump")
    carve.add_argument('file')
    carve.add_argument('--out', default='carved')

    batch = subparsers.add_parser('batchscan', help="Batch scan directory for SHA256 hashes")
    batch.add_argument('directory')

    
    args = parser.parse_args()

    if args.command == 'hash' and args.file:
        calc_hashes(args.file)
    elif args.command == 'entropy' and args.file:
        calc_entropy(args.file)
    elif args.command == 'strings' and args.file:
        extract_strings(args.file)
    elif args.command == 'b64decode':
        base64_decode(args.string)
    elif args.command == 'xordecode':
        xor_decode(args.hex_string, args.key)
    elif args.command == 'str2bytes':
        string_to_bytes(args.string)
    elif args.command == 'hex2bytes':
        hex_to_bytes(args.hex_string)
    elif args.command == 'unpackle':
        unpack_le(args.hex_string)
    elif args.command == 'yara':
        yara_rule_from_strings(args.name, args.strings)
    elif args.command == 'disasm':
        disassemble_shellcode(args.hex_string)
    elif args.command == 'peparse':
        parse_pe_headers(args.file)
    elif args.command == 'iocs':
        extract_iocs(args.file)
    elif args.command == 'carvepe':
        carve_pe_from_memory(args.file, args.out)
    elif args.command == 'batchscan':
        batch_scan(args.directory)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
```
{% endraw %}