---
title: "Generate yara rule template"
categories: [yara]
tags: [generator]
---

```python
def yara_rule_template(name, strings):
    rule = f"rule {name}\n    strings:\n"
    for i, s in enumerate(strings):
        rule += f"        $s{i} = \"{s}\"\n"
    rule += "    condition:\n        all of them\n}"
    return rule

print(yara_rule_template("SampleRule", ["malicious", "http://evil.com"]))
```