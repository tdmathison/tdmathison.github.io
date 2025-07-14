---
title: "Config extractor: Formbook"
categories: [extractor]
tags: [formbook]
---

{% raw %}
```python
import re

def extract_formbook_config(data):
    pattern = rb'(http[s]?://[a-zA-Z0-9\.\-]+/[^\s]+\.php)'
    return re.findall(pattern, data)

if __name__ == "__main__":
    with open("sample.bin", "rb") as f:
        data = f.read()
    config = extract_formbook_config(data)
    print(config)
```
{% endraw %}