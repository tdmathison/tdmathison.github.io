---
title: "Config extractor: Lokibot"
categories: [extractor]
tags: [lokibot]
---

{% raw %}
```python
import re

def extract_lokibot_config(data):
    pattern = rb'(http[s]?://[a-zA-Z0-9\.\-]+/panel/[^\s]+)'
    return re.findall(pattern, data)

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_lokibot_config(data)
    print(config)
```
{% endraw %}