---
title: "Disassemble shellcode"
categories: [pe]
tags: [disassemble]
---

```python
from capstone import *

CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x1000):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
```