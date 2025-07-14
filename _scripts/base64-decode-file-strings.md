---
title: "Base64 decode strings in file"
categories: [file]
tags: [decoder]
---

```python
import re
import base64

def extract_base64(filename):
    with open(filename, "r", errors="ignore") as f:
        content = f.read()
    pattern = r"[A-Za-z0-9+/=]{20,}"
    return [base64.b64decode(match) for match in re.findall(pattern, content)]

decoded_blobs = extract_base64("sample.txt")
for blob in decoded_blobs:
    print(blob[:100])
```