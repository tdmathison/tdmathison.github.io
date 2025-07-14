---
title: "Encryption: Detect RC4"
categories: [pe, encryption]
tags: [rc4]
---

{% raw %}
```python
import sys
import os
from collections import Counter

def rc4_stream(key, data_len):
    S = list(range(256))
    j = 0
    key = [k for k in key]
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    keystream = []
    for _ in range(data_len):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)

def is_mostly_ascii(data, threshold=0.85):
    return sum(32 <= b <= 126 for b in data) / len(data) > threshold

def try_rc4_keys(data, key_lengths=(5, 6, 8, 16)):
    results = []
    for offset in range(0, len(data) - 512, 256):
        chunk = data[offset:offset+512]
        for key_len in key_lengths:
            for i in range(0, len(chunk) - key_len - 256, 64):
                key_candidate = chunk[i:i+key_len]
                stream = rc4_stream(key_candidate, 256)
                plaintext = bytes([c ^ s for c, s in zip(chunk[i+key_len:i+key_len+256], stream)])
                if is_mostly_ascii(plaintext):
                    results.append({
                        'key': key_candidate,
                        'offset': offset + i,
                        'preview': plaintext[:100],
                        'full': plaintext
                    })
    return results

def format_key(key):
    return ' '.join(f'{b:02x}' for b in key)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_rc4.py <binary_file>")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, "rb") as f:
        data = f.read()

    print(f"[+] Scanning for RC4-encrypted blocks in: {filename}")
    results = try_rc4_keys(data)

    if results:
        os.makedirs("rc4_output", exist_ok=True)
        for i, result in enumerate(results):
            print(f"[!] Potential RC4 key found at offset 0x{result['offset']:x}")
            print(f"    Key: {format_key(result['key'])}")
            print(f"    Preview: {result['preview'].decode(errors='ignore')}")
            out_file = f"rc4_output/rc4_candidate_{i}.bin"
            with open(out_file, "wb") as f:
                f.write(result['full'])
            print(f"    Full output saved to: {out_file}")
    else:
        print("[-] No RC4-encrypted content detected.")
```
{% endraw %}