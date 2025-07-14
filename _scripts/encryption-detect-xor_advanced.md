---
title: "Encryption: Detect XOR Advanced"
categories: [pe, encryption]
tags: [xor]
---

{% raw %}
```python
import sys
import math
import os
from itertools import cycle

def entropy(data):
    if not data:
        return 0
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1
    entropy = 0
    for count in occurences:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
    return entropy

def detect_xor(data, max_key_len=4, min_ascii_ratio=0.85, max_entropy=5.5):
    results = []
    for key_len in range(1, max_key_len + 1):
        for i in range(0, len(data) - key_len):
            key = data[i:i+key_len]
            decoded = bytes([b ^ k for b, k in zip(data, cycle(key))])
            printable = sum([32 <= c <= 126 for c in decoded])
            ratio = printable / len(decoded)
            ent = entropy(decoded)
            if ratio > min_ascii_ratio and ent < max_entropy:
                results.append({
                    'key': key,
                    'offset': i,
                    'ratio': ratio,
                    'entropy': ent,
                    'preview': decoded[:100],
                    'decoded': decoded
                })
    return results

def sliding_windows(buf, size=512, step=256):
    for i in range(0, len(buf) - size, step):
        yield i, buf[i:i+size]

def format_key(key):
    return ' '.join(f'{b:02x}' for b in key)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_xor_advanced.py <binary_file> [--output]")
        sys.exit(1)

    filename = sys.argv[1]
    enable_output = "--output" in sys.argv

    with open(filename, "rb") as f:
        data = f.read()

    if enable_output:
        os.makedirs("output", exist_ok=True)

    print(f"[+] Scanning for XOR-encoded blocks in: {filename}")
    found = False
    counter = 0
    for offset, block in sliding_windows(data):
        hits = detect_xor(block)
        for hit in hits:
            print(f"[!] XOR key: {format_key(hit['key'])} at offset 0x{offset + hit['offset']:x}")
            print(f"    Entropy: {hit['entropy']:.2f}, Printable Ratio: {hit['ratio']:.2f}")
            print(f"    Decoded preview: {hit['preview'].decode(errors='ignore')}")
            if enable_output:
                output_file = f"output/decoded_output_{counter}.bin"
                with open(output_file, "wb") as out:
                    out.write(hit['decoded'])
                print(f"    Full decoded output saved to: {output_file}")
            counter += 1
            found = True

    if not found:
        print("[-] No XOR-encoded data found.")
```
{% endraw %}