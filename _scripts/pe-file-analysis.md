---
title: "PE file analysis"
categories: [pe]
tags: [analysis]
---

```python
import pefile

pe = pefile.PE("sample.exe")

# Print imported DLLs and functions
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"[*] {entry.dll.decode()}")
    for imp in entry.imports:
        print(f"\t{hex(imp.address)}: {imp.name}")
```