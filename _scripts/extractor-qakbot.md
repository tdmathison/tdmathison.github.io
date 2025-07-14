---
title: "Config extractor: Qakbot"
categories: [extractor]
tags: [qakbot]
---

{% raw %}
```python
import re

def extract_qakbot_config(data):
    pattern = rb'\x00\x00\x00\x01.{4}(.{256})'
    matches = re.findall(pattern, data, re.DOTALL)
    return matches

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_qakbot_config(data)
    print(config)
```
{% endraw %}