---
title: "Config extractor: Redline Stealer"
categories: [extractor]
tags: [redlinestealer]
---

{% raw %}
```python
import re
import base64

def extract_redline_config(data):
    urls = re.findall(rb'(https?://[^\s\'"]+)', data)
    b64_configs = re.findall(rb'([A-Za-z0-9+/=]{50,})', data)
    decoded_configs = []

    for b64 in b64_configs:
        try:
            decoded = base64.b64decode(b64)
            if b"http" in decoded:
                decoded_configs.append(decoded)
        except Exception:
            continue
    return {"urls": urls, "configs": decoded_configs}

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_redline_config(data)
    print(config)
```
{% endraw %}