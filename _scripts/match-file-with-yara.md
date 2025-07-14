---
title: "Match file with yara rule"
categories: [yara]
tags: [detection]
---

```python
import yara

rules = yara.compile(filepath="rules.yar")
matches = rules.match("sample.exe")
print(matches)
```