---
title: "Find binary strings"
categories: [pe]
tags: [strings]
---

{% raw %}
```python
import re

def extract_strings(filename, min_len=4):
    with open(filename, "rb") as f:
        data = f.read()

    pattern = rb"[ -~]{%d,}" % min_len
    return re.findall(pattern, data)

for s in extract_strings("sample.bin"):
    print(s.decode(errors="ignore"))
```
{% endraw %}