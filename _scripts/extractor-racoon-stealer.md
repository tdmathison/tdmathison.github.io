---
title: "Config extractor: Racoon Stealer"
categories: [extractor]
tags: [racoonstealer]
---

{% raw %}
```python
import re

def extract_racoon_config(data):
    pattern = rb'(http[s]?://[\w\.-]+(:\d+)?/gateway)'
    return re.findall(pattern, data)

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_racoon_config(data)
    for url in config:
        print(url[0].decode())
```
{% endraw %}