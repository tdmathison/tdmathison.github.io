---
title: "Encryption: Detect XOR"
categories: [pe, encryption]
tags: [xor]
---

{% raw %}
```python
import sys

def detect_xor(data, threshold=5):
    """
    Detect possible XOR-encoded blocks in a binary blob.
    Looks for blocks with low entropy that become readable ASCII after XOR.
    """
    results = []
    for key in range(1, 256):
        decoded = bytes([b ^ key for b in data])
        printable = sum([32 <= c <= 126 for c in decoded])
        ratio = printable / len(decoded)
        if ratio > 0.85:
            results.append((key, decoded[:200]))
    return results

def sliding_windows(buf, size=256, step=128):
    for i in range(0, len(buf) - size, step):
        yield i, buf[i:i+size]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_xor.py <binary_file>")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, "rb") as f:
        data = f.read()

    print(f"[+] Scanning for XOR-encoded blocks in: {filename}")
    found = False
    for offset, block in sliding_windows(data):
        hits = detect_xor(block)
        for key, preview in hits:
            print(f"[!] Possible XOR key: 0x{key:02x} at offset 0x{offset:x}")
            print(f"    Decoded preview: {preview.decode(errors='ignore')[:100]}")
            found = True

    if not found:
        print("[-] No obvious XOR-encoded data found.")
```
{% endraw %}