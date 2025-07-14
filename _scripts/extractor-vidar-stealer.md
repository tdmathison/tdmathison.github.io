---
title: "Config extractor: Vidar Stealer"
categories: [extractor]
tags: [vidarstealer]
---

{% raw %}
```python
import re

def extract_vidar_config(data):
    pattern = rb'(http[s]?://[\w\.-]+/gate\.php)'
    return re.findall(pattern, data)

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_vidar_config(data)
    print(config)
```
{% endraw %}