---
title: "Packer detection"
categories: [pe]
tags: [packer, detection]
---

```python
import pefile

def is_packed(pe):
    entropy_threshold = 7.0
    for section in pe.sections:
        if section.get_entropy() > entropy_threshold:
            return True
    return False

pe = pefile.PE("sample.exe")
print("Likely Packed" if is_packed(pe) else "Not Packed")
```