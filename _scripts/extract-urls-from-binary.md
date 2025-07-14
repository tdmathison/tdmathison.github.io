---
title: "Extract URLs from binary"
categories: [pe]
tags: [extract]
---

```python
import re

def extract_urls(filename):
    with open(filename, "rb") as f:
        data = f.read()
    urls = re.findall(rb"https?://[^\s\"']+", data)
    return [u.decode("utf-8", errors="ignore") for u in urls]

print(extract_urls("malware_sample.bin"))
```