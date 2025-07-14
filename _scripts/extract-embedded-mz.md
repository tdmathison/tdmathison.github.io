---
title: "Extract MZ from file"
categories: [pe]
tags: [extract]
---

```python
def extract_pe_from_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    pe_offsets = [m.start() for m in re.finditer(b'MZ', data)]
    for i, offset in enumerate(pe_offsets):
        with open(f"extracted_{i}.exe", "wb") as out:
            out.write(data[offset:offset + 1024 * 1024])  # 1MB max extract
```