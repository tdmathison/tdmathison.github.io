---
title: "Generate file hash"
categories: [file]
tags: [hash, md5]
---

```python
import hashlib

def hash_file(filepath):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hashes.items()}

print(hash_file("sample.exe"))
```