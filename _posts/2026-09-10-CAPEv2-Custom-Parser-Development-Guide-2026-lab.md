---
title: "CAPEv2 Custom Parser Development Guide (2026 lab)"
date: 2026-09-10 12:35:00 -0700
categories: [Blogging]
tags: [cape, parsers, decoders]
---

## 2026 Lab work
> This is part of multiple install guides that I have made as I built out a new personal lab environment.<br/>
> The following diagram shows a high-level view of the pipeline being built out.<br/>
> * Step 1: [Installing InetSim (2026 lab)](https://www.travismathison.com/posts/Installing-InetSim-2026-lab/)
> * Step 2: [Installing CAPEv2 sandbox (2026 lab)](https://www.travismathison.com/posts/Installing-CAPEv2-2026-lab/)
> * Step 3: [Installing AssemblyLine4 (2026 lab)](https://www.travismathison.com/posts/Installing-AssemblyLine4-2026-lab/)
> * Step 4: [CAPEv2 Custom Parser Development Guide (2026 lab)](https://www.travismathison.com/posts/CAPEv2-Custom-Parser-Development-Guide-2026-lab)
{: .prompt-tip }

<details>
<summary>Click to expand diagram</summary>

<pre>
                              MALWARE ANALYSIS LAB
=======================================================================================


                                  MALWARE INTAKE
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                  Sample              Hash               API
                    │                  │                  │
                    └──────────────────┴──────────────────┘
                                       │
                                       ▼
        ┌───────────────────────────────────────────────────────────────┐
        │                         ASSEMBLYLINE4                         │
        │                  Intake / Triage / Orchestration              │
        │                                                               │
        │   ┌───────────┐    ┌────────────┐    ┌───────────────────┐    │
        │   │ File Type │ -> │  Static    │ -> │ YARA / PE / Other │    │
        │   │ / Hashing │    │  Analysis  │    │ Analysis Services │    │
        │   └───────────┘    └────────────┘    └─────────┬─────────┘    │
        │                                                │              │
        │                                                ▼              │
        │                                         ┌─────────────┐       │
        │                                         │ CAPE Service│       │
        │                                         └──────┬──────┘       │
        │                                                │              │
        └────────────────────────────────────────────────┼──────────────┘
                                                         │
                                                   Submit Sample
                                                         │
                                                         ▼
        ┌───────────────────────────────────────────────────────────────┐
        │                            CAPEv2                             │
        │                    Automated Dynamic Analysis                 │
        │                                                               │
        │    API / Scheduler                                            │
        │          │                                                    │
        │          ▼                                                    │
        │    Machine Selection                                          │
        │          │                                                    │
        │          ▼                                                    │
        │   ┌──────────────────────────────┐                            │
        │   │      Windows Sandbox VM      │                            │
        │   │                              │                            │
        │   │  CAPE Agent                  │                            │
        │   │       │                      │                            │
        │   │       ▼                      │                            │
        │   │  Malware Execution           │                            │
        │   │       │                      │                            │
        │   │       ├── Process Behavior   │                            │
        │   │       ├── API Activity       │                            │
        │   │       ├── Memory             │                            │
        │   │       ├── Dropped Files      │                            │
        │   │       ├── CAPEMON            │                            │
        │   │       └── Network Traffic ───────────────┐                │
        │   └──────────────────────────────┘           │                │
        │                                              │                │
        │          CAPE Parsers                        │                │
        │          Config Extraction                   │                │
        │          PCAP                                │                │
        │          Behavioral Report                   │                │
        │                 │                            │                │
        └─────────────────┼────────────────────────────┼────────────────┘
                          │                            │
                          │                            ▼
                          │             ┌──────────────────────────────┐
                          │             │           INetSim            │
                          │             │   Simulated Malware Network  │
                          │             │                              │
                          │             │   DNS                        │
                          │             │   HTTP / HTTPS               │
                          │             │   FTP / SMTP                 │
                          │             │   Other Fake Services        │
                          │             │                              │
                          │             │  "Controlled Fake Internet"  │
                          │             └──────────────────────────────┘
                          │
                          ▼
        ┌───────────────────────────────────────────────────────────────┐
        │                       CAPE RESULTS                            │
        │                                                               │
        │  Behavior │ PCAP │ Extracted Files │ Config │ IOCs │ Dumps    │
        └──────────────────────────────┬────────────────────────────────┘
                                       │
                                       │
                   ┌───────────────────┴─────────────────────┐
                   │                                         │
                   ▼                                         ▼
        Return Results to AL4                    Escalate for Manual Analysis
                   │                                         │
                   ▼                                         ▼
        ┌───────────────────────┐          ┌────────────────────────────────┐
        │     ASSEMBLYLINE4     │          │           FLAREVM              │
        │                       │          │ Manual Analysis / Reverse Eng. │
        │ Aggregate Results     │          │                                │
        │ Scoring               │          │  Static Analysis               │
        │ Service Results       │          │       │                        │
        │ Search / Hunting      │          │       ├── IDA Pro              │
        │                       │          │       ├── FLOSS                │
        └───────────┬───────────┘          │       ├── capa                 │
                    │                      │       └── YARA                 │
                    │                      │                                │
                    │                      │  Dynamic / Debug Analysis      │
                    │                      │       │                        │
                    │                      │       ├── x64dbg               │
                    │                      │       ├── API tracing          │
                    │                      │       └── Manual execution     │
                    │                      │                                │
                    │                      │  Reverse Engineering           │
                    │                      │       │                        │
                    │                      │       ├── Config extraction    │
                    │                      │       ├── C2 protocol          │
                    │                      │       ├── Crypto               │
                    │                      │       └── Capability analysis  │
                    │                      │                                │
                    │                      └───────────────┬────────────────┘
                    │                                      │
                    └───────────────────┬──────────────────┘
                                        │
                                        ▼
                     ┌─────────────────────────────────────┐
                     │       MALWARE INTELLIGENCE          │
                     │                                     │
                     │  Malware Family                     │
                     │  Behavior / Capabilities            │
                     │  Configuration                      │
                     │  C2 Infrastructure                  │
                     │  IOCs                               │
                     │  Detection Opportunities            │
                     │  YARA / Signatures                  │
                     │  Reverse Engineering Findings       │
                     └──────────────────┬──────────────────┘
                                        │
                                        ▼
                             ┌─────────────────────┐
                             │      REPORTING      │
                             │                     │
                             │ Malware Report      │
                             │ Family Profile      │
                             │ Threat Intel        │
                             │ Detection Content   │
                             └─────────────────────┘
</pre>
</details>


## Purpose
CAPE malware configuration parsers extract useful configuration data from malware samples and unpacked payloads, such as:

* Command-and-control servers
* Campaign IDs
* Bot IDs
* Mutexes
* Encryption keys
* User agents
* Installation paths
* Persistence values
* Ports
* Credentials
* Cryptocurrency wallets
* Version information
* Other family-specific configuration

For locally developed or private parsers, CAPE supports placing pure Python parser modules in:
```bash
/opt/CAPEv2/custom/parsers/
```

This is the preferred location for private parsers. CAPE's built-in parsers were moved into the separate `CAPE-parsers` project in November 2024, but CAPE explicitly retains support for `custom/parsers/`. A custom parser with the same name as an installed CAPE parser can override that parser.

The default CAPE processing configuration currently points its CAPE extractor framework at:
```ini
[CAPE_extractors]
enabled = yes
modules_path = custom/parsers/
parsers = all
exclude=
```

## 1. How CAPE Config Extraction Works

The normal flow is roughly:
```text
Malware executes
      |
      v
CAPE captures original/unpacked/dumped files
      |
      v
CAPE YARA rules scan those files
      |
      v
A CAPE YARA rule identifies a malware family
      |
      v
CAPE determines the family/parser name
      |
      v
static_config_parsers()
      |
      v
custom/parsers/<family>.py
      |
      v
extract_config(data)
      |
      v
Extracted configuration added to CAPE report
```

CAPE's processing code runs CAPE YARA rules against captured files. When a YARA hit provides a CAPE detection, CAPE derives the malware family name and calls `static_config_parsers()` for that family.

This means that **writing the Python parser is only half of the job**.

You normally need:
1. A YARA rule capable of identifying the malware/config.
2. A parser whose name corresponds to the family detected by CAPE.
3. An `extract_config(data)` function capable of extracting the configuration.

CAPE recommends its native parser framework specifically because a parser can simply expose:
```python
def extract_config(data):
```

and CAPE will call it through its config parsing infrastructure.

## 2. Directory Layout
Your private parsers should live under:

```text
/opt/CAPEv2/custom/parsers/
```

For example:

```text
/opt/CAPEv2/
├── custom/
│   └── parsers/
│       ├── ExampleRAT.py
│       ├── QV02.py
│       ├── PrivateLoader.py
│       └── CompanySpecificMalware.py
```

Do **not** copy the entire CAPE-parsers repository into this directory.

The official CAPE parsers are installed as a Python dependency through Poetry. CAPE maintainers specifically recommend `custom/parsers/` for private pure-Python parsers.

## 3. Minimal CAPE Parser

The simplest useful parser looks like this:

```python
def extract_config(data):
    config = {}

    # Parse malware data here.

    config["C2"] = ["https://example.com"]
    config["Campaign ID"] = "example-campaign"

    return config
```

`data` is the malware/configuration file supplied to the parser as bytes.

A slightly safer skeleton is:

```python
def extract_config(data):
    config = {}

    if not data:
        return config

    try:
        # Perform extraction here.
        pass

    except Exception:
        return {}

    return config
```

For development, however, avoid swallowing every exception until the parser is working. Silent exception handling makes debugging unnecessarily difficult.

A better development version is:

```python
import logging

log = logging.getLogger(__name__)


def extract_config(data):
    config = {}

    if not data:
        return config

    try:
        # Extraction logic.
        pass

    except Exception:
        log.exception("Failed extracting ExampleRAT configuration")
        return {}

    return config
```

## 4. A Practical Example Parser

Imagine a malware family named `ExampleRAT`.

Assume its configuration appears in the binary as:

```text
CFG|
c2=https://evil.example.com
port=443
campaign=ATTACK01
mutex=Global\ExampleMutex
|ENDCFG
```

Create:

```bash
cd /opt/CAPEv2

sudo -u cape vim custom/parsers/ExampleRAT.py
```

Then:

```python
import logging
import re

log = logging.getLogger(__name__)


def extract_config(data):
    config = {}

    if not data:
        return config

    try:
        match = re.search(
            rb"CFG\|(.*?)\|ENDCFG",
            data,
            re.DOTALL,
        )

        if not match:
            return {}

        raw_config = match.group(1)

        for line in raw_config.splitlines():
            if b"=" not in line:
                continue

            key, value = line.split(b"=", 1)

            key = key.decode("utf-8", errors="ignore").strip()
            value = value.decode("utf-8", errors="ignore").strip()

            if key == "c2":
                config.setdefault("C2", []).append(value)

            elif key == "port":
                config["Port"] = value

            elif key == "campaign":
                config["Campaign ID"] = value

            elif key == "mutex":
                config["Mutex"] = value

        return config

    except Exception:
        log.exception("ExampleRAT config extraction failed")
        return {}
```

A successful return could look like:

```python
{
    "C2": [
        "https://evil.example.com"
    ],
    "Port": "443",
    "Campaign ID": "ATTACK01",
    "Mutex": "Global\\ExampleMutex",
}
```

## 5. Parser Naming Is Important

CAPE needs to associate the malware family identified by its CAPE YARA detection with the corresponding parser.

Conceptually:

```text
YARA identifies:
ExampleRAT

        ↓

CAPE parser:
ExampleRAT.py
```

The safest practice is therefore:

```text
YARA family name == parser module name
```

For example:

```text
Family:        ExampleRAT
Parser:        custom/parsers/ExampleRAT.py
```

Avoid unnecessary differences such as:

```text
Example-RAT
Example_RAT
examplerat
ExampleRatParser
```

unless you have verified how the particular CAPE YARA metadata resolves into the parser name.

CAPE's processor derives the CAPE family name from its YARA hit and passes that name into `static_config_parsers()`.


## 6. Creating the YARA Detection
A parser normally will not magically execute against every file CAPE encounters.

CAPE needs to know that the parser is relevant.

A simplified CAPE YARA rule might conceptually look like:

```yara
rule ExampleRAT
{
    meta:
        author = "Travis Mathison"
        description = "Detect ExampleRAT"
        cape_type = "ExampleRAT Payload"

    strings:
        $config_marker = "CFG|"
        $end_marker = "|ENDCFG"

    condition:
        uint16(0) == 0x5A4D and
        all of them
}
```

The important relationship is:

```text
Detection
    +
Family identification
    +
Parser
```

CAPE scans captured files with its CAPE YARA rules and uses qualifying YARA hits to derive a `cape_name`, which then causes `static_config_parsers()` to execute.

Your exact CAPE YARA metadata should follow the conventions already used by the YARA rules installed on your CAPE server.

A good development workflow is to find an existing malware family that behaves similarly and model both its YARA rule and parser after that implementation.


## 7. Recommended Parser Return Structure
Use Python-native structures that serialize cleanly into JSON.

Good:

```python
{
    "C2": [
        "https://one.example",
        "https://two.example",
    ],
    "Port": 443,
    "Campaign ID": "ABC123",
    "Mutex": "Global\\mutex",
}
```

Avoid returning:

```python
{
    "raw_object": SomeCustomPythonClass(),
}
```

or:

```python
{
    "binary": b"\x00\x01\x02"
}
```

unless you explicitly convert those values into something JSON-compatible.

For binary data, consider:

```python
config["Key"] = key.hex()
```

instead of:

```python
config["Key"] = key
```

## 8. Handling Multiple C2 Servers
For malware with multiple C2 servers:

```python
config["C2"] = []
```

Then:

```python
config["C2"].append(c2)
```

Better yet, deduplicate:

```python
c2s = set()

for value in extracted_values:
    c2s.add(value)

config["C2"] = sorted(c2s)
```

Example:

```python
{
    "C2": [
        "https://c2-a.example",
        "https://c2-b.example",
        "185.100.10.20:443",
    ]
}
```


## 9. Handling Encoded Configuration
Most real malware requires more than string extraction.

Typical parser operations include:

```text
Locate configuration
        |
        +-- PE section
        +-- resource
        +-- overlay
        +-- marker
        +-- RVA
        +-- pattern
        |
        v
Extract encrypted blob
        |
        v
Decrypt / decode
        |
        +-- XOR
        +-- RC4
        +-- AES
        +-- Base64
        +-- custom algorithm
        |
        v
Deserialize
        |
        +-- JSON
        +-- struct
        +-- protobuf
        +-- null-separated strings
        +-- custom TLV
        |
        v
Return Python dictionary
```

For example:

```python
def xor_decode(data, key):
    return bytes(
        byte ^ key[i % len(key)]
        for i, byte in enumerate(data)
    )
```

Then:

```python
decoded = xor_decode(encrypted_config, key)
```


## 10. PE Parsing
For PE malware, `pefile` is often useful.

Example:

```python
import io
import logging

import pefile

log = logging.getLogger(__name__)


def extract_config(data):
    config = {}

    try:
        pe = pefile.PE(data=data, fast_load=False)

        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode(
                "ascii",
                errors="ignore",
            )

            if name == ".data":
                section_data = section.get_data()

                # Parse config here.

        return config

    except pefile.PEFormatError:
        return {}

    except Exception:
        log.exception("Failed parsing malware configuration")
        return {}
```

Do not assume every file supplied to your parser will necessarily be a perfectly formed PE.

CAPE may be dealing with:

* Memory dumps
* Reconstructed executables
* Injected payloads
* Decompressed data
* Config blobs
* Truncated files

Design the parser accordingly.


## 11. Useful Helper Functions
For production parsers, small helper functions make maintenance much easier.

For example:

```python
def decode_string(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip("\x00")

    return str(value)
```

IPv4 conversion:

```python
import socket


def decode_ipv4(raw):
    return socket.inet_ntoa(raw)
```

Little-endian integer:

```python
import struct


def uint32_le(data):
    return struct.unpack("<I", data)[0]
```

Null-terminated string:

```python
def read_cstring(data):
    return data.split(b"\x00", 1)[0].decode(
        "utf-8",
        errors="ignore",
    )
```


## 12. Keep Extraction Separate From Identification
Avoid writing parsers like:

```python
def extract_config(data):
    if b"ExampleRAT" not in data:
        return {}

    ...
```

unless the marker is actually required to locate the config.

The YARA rule should generally handle:

```text
Is this ExampleRAT?
```

The parser should handle:

```text
Where is the ExampleRAT config,
how is it encoded,
and what fields does it contain?
```

This separation makes both components easier to maintain.


## 13. Local Parser Testing
Do not repeatedly submit malware to CAPE just to test minor parser changes.

You can test your parser directly.

Assume:

```text
custom/parsers/ExampleRAT.py
```

and:

```text
/tmp/example.exe
```

From `/opt/CAPEv2`:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3
```

Then:

```python
from custom.parsers.ExampleRAT import extract_config

with open("/tmp/example.exe", "rb") as f:
    data = f.read()

config = extract_config(data)

print(config)
```

Or create a very small test script:

```python
#!/usr/bin/env python3

import pprint

from custom.parsers.ExampleRAT import extract_config


with open("/tmp/example.exe", "rb") as f:
    data = f.read()

pprint.pp(extract_config(data))
```

Then:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 /tmp/test_parser.py
```

This is usually the fastest parser-development loop.


## 14. Syntax Checking
Before restarting CAPE:

```bash
cd /opt/CAPEv2
```

Run:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 -m py_compile \
    custom/parsers/ExampleRAT.py
```

No output normally means the file compiled successfully.

You can also test importing it:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 -c \
    'from custom.parsers.ExampleRAT import extract_config; print(extract_config)'
```


## 15. File Ownership
Because CAPE runs under the `cape` account, keep ownership consistent:

```bash
sudo chown cape:cape /opt/CAPEv2/custom/parsers/ExampleRAT.py
```

Recommended permissions:

```bash
sudo chmod 0644 /opt/CAPEv2/custom/parsers/ExampleRAT.py
```

Verify:

```bash
ls -la /opt/CAPEv2/custom/parsers/
```

Example:

```text
-rw-r--r-- 1 cape cape 2841 Aug 25 21:30 ExampleRAT.py
```


## 16. Restart CAPE Processing
Once the parser is installed or modified:

```bash
sudo systemctl restart cape-processor
```

The CAPE maintainers specifically recommend restarting `cape-processor` after parser installation/update.

Check it:

```bash
sudo systemctl status cape-processor --no-pager
```

And inspect logs:

```bash
sudo journalctl -u cape-processor -n 100 --no-pager
```

For live debugging:

```bash
sudo journalctl -u cape-processor -f
```


## 17. Debug Logging
Add:

```python
import logging

log = logging.getLogger(__name__)
```

Then during development:

```python
log.debug("ExampleRAT parser invoked")
```

or:

```python
log.info("Found ExampleRAT configuration")
```

For errors:

```python
log.exception("ExampleRAT parser failed")
```

Be careful not to permanently dump entire malware buffers into production logs.

Bad:

```python
log.debug(data)
```

Better:

```python
log.debug(
    "Parsing ExampleRAT candidate of %d bytes",
    len(data),
)
```


## 18. Verify That CAPE Is Actually Calling the Parser
A parser that works manually but never appears in CAPE reports usually means the problem is **detection/dispatch rather than extraction**.

Temporarily add:

```python
log.warning("ExampleRAT PARSER EXECUTED")
```

Restart:

```bash
sudo systemctl restart cape-processor
```

Submit the malware.

Then:

```bash
sudo journalctl -u cape-processor -f
```

If the message never appears, investigate:

```text
YARA rule
    |
    v
Did CAPE produce a CAPE YARA hit?
    |
    v
Did that hit resolve to ExampleRAT?
    |
    v
Does ExampleRAT.py exist?
    |
    v
Can the cape account import it?
```


## 19. A Better Production Parser Template
This is a good starting point for new private parsers:

```python
"""
CAPE configuration parser for ExampleRAT.

Author:
    Travis Mathison

Purpose:
    Extract ExampleRAT malware configuration.
"""

import logging
import re

log = logging.getLogger(__name__)


CONFIG_START = b"CFG|"
CONFIG_END = b"|ENDCFG"


def _decode(value):
    return value.decode(
        "utf-8",
        errors="ignore",
    ).strip().rstrip("\x00")


def _locate_config(data):
    pattern = (
        re.escape(CONFIG_START)
        + rb"(.*?)"
        + re.escape(CONFIG_END)
    )

    match = re.search(
        pattern,
        data,
        re.DOTALL,
    )

    if not match:
        return None

    return match.group(1)


def _parse_config(raw):
    config = {}

    for line in raw.splitlines():
        if b"=" not in line:
            continue

        key, value = line.split(b"=", 1)

        key = _decode(key)
        value = _decode(value)

        if not value:
            continue

        if key == "c2":
            config.setdefault("C2", []).append(value)

        elif key == "port":
            try:
                config["Port"] = int(value)
            except ValueError:
                config["Port"] = value

        elif key == "campaign":
            config["Campaign ID"] = value

        elif key == "mutex":
            config["Mutex"] = value

        elif key == "version":
            config["Version"] = value

    return config


def extract_config(data):
    """Extract ExampleRAT configuration."""

    if not isinstance(data, (bytes, bytearray)):
        return {}

    if not data:
        return {}

    try:
        raw_config = _locate_config(data)

        if raw_config is None:
            return {}

        config = _parse_config(raw_config)

        if config:
            log.debug(
                "Successfully extracted ExampleRAT configuration"
            )

        return config

    except Exception:
        log.exception(
            "Unexpected error extracting ExampleRAT configuration"
        )

        return {}
```

The benefit of this layout is that each stage can be tested independently:

```text
extract_config()
      |
      +-- _locate_config()
      |
      +-- decode/decrypt
      |
      +-- _parse_config()
```


## 20. Unit Testing Your Parser
For parsers your team expects to maintain, create tests.

Example:

```python
from custom.parsers.ExampleRAT import extract_config


def test_example_rat():
    sample = (
        b"MZ"
        + b"\x00" * 100
        + b"CFG|\n"
        + b"c2=https://c2.example\n"
        + b"port=443\n"
        + b"campaign=TEST01\n"
        + b"|ENDCFG"
    )

    result = extract_config(sample)

    assert result["C2"] == [
        "https://c2.example"
    ]

    assert result["Port"] == 443
    assert result["Campaign ID"] == "TEST01"
```

This becomes especially valuable when a malware family changes configuration versions.


## 21. Supporting Multiple Malware Versions

Avoid creating:

```text
ExampleRAT_v1.py
ExampleRAT_v2.py
ExampleRAT_v3.py
```

if they are clearly the same malware family.

Instead:

```python
def extract_config(data):
    version = identify_config_version(data)

    if version == 1:
        return parse_v1(data)

    if version == 2:
        return parse_v2(data)

    if version == 3:
        return parse_v3(data)

    return {}
```

Example:

```python
def identify_config_version(data):
    if b"CFG1" in data:
        return 1

    if b"CFG2" in data:
        return 2

    return None
```

This keeps CAPE reporting the same malware family while allowing the parser to evolve.


## 22. Overriding an Official CAPE Parser

One particularly useful feature of `custom/parsers/` is that a local parser can override an official CAPE parser with the same name. CAPE explicitly documents that custom parsers continue to load and overwrite a CAPE parser when the names match.

For example, suppose the official package contains:

```text
Lumma.py
```

You could create:

```text
/opt/CAPEv2/custom/parsers/Lumma.py
```

Your local implementation can then supersede the packaged implementation.

This is useful when:

* An upstream parser is temporarily broken.
* Your organization has support for a newer malware variant.
* You need private extraction logic.
* You need additional fields unavailable upstream.
* You are developing a fix before submitting it upstream.

It also means you should be careful with parser names, because accidentally naming a private parser after an official parser can override it.


## 23. Private vs Upstream Parsers

A useful operational policy is:

```text
custom/parsers/
       |
       +-- Private/internal malware
       |
       +-- Work in progress
       |
       +-- Proprietary extraction
       |
       +-- Emergency upstream overrides
       |
       +-- Research prototypes
```

If a parser is broadly useful and contains no proprietary information, consider contributing it to:

```text
CAPESandbox/CAPE-parsers
```

CAPE maintainers request a parser, unit test, and appropriate test sample when contributing parser support upstream.


## 24. Dependencies
Try to keep private parsers lightweight.

Prefer Python standard-library modules where practical:

```python
base64
binascii
hashlib
io
json
logging
re
socket
struct
urllib.parse
```

Before using a third-party dependency:

```python
from Crypto.Cipher import AES
```

verify it exists inside CAPE's Poetry environment.

Test:

```bash
cd /opt/CAPEv2

sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 -c \
    'from Crypto.Cipher import AES; print("OK")'
```

Do not install random packages globally with:

```bash
sudo pip install ...
```

CAPE should use its managed Poetry environment.


## 25. Common Failure Modes
### Parser works manually but CAPE never calls it

Most likely:

```text
YARA detection/metadata mismatch
```

Check the CAPE YARA hit and family name.


### `ModuleNotFoundError`

Usually:

* Third-party package missing from Poetry environment.
* Import path incorrect.
* Parser assumes a package from your shell environment rather than CAPE's environment.

Test with:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3
```


### Permission denied

Check:

```bash
namei -l /opt/CAPEv2/custom/parsers/ExampleRAT.py
```

and:

```bash
ls -ld \
    /opt/CAPEv2 \
    /opt/CAPEv2/custom \
    /opt/CAPEv2/custom/parsers
```

Then ensure the `cape` user can read the parser.


### Parser runs but returns nothing

Test:

```python
result = extract_config(data)

print(repr(result))
```

Then progressively test:

```python
print(_locate_config(data))
```

and:

```python
print(_parse_config(raw_config))
```

Break the parser into stages rather than debugging everything through CAPE.


### Parser imports but breaks `cape-processor`

Inspect:

```bash
sudo journalctl -u cape-processor \
    --since "10 minutes ago" \
    --no-pager
```

Typical causes:

```text
SyntaxError
ImportError
ModuleNotFoundError
NameError at import time
```

Avoid performing parsing work globally at module import.

Bad:

```python
pe = pefile.PE("/tmp/sample.exe")
```

at the top level.

Parsing should happen inside:

```python
extract_config()
```


## 26. Recommended Development Workflow
Use this workflow for every new malware family:

```text
1. Identify malware family
           |
           v
2. Reverse configuration format
           |
           v
3. Write standalone Python extractor
           |
           v
4. Convert extractor to:
       extract_config(data)
           |
           v
5. Test parser directly
           |
           v
6. Place under custom/parsers/
           |
           v
7. Create/verify CAPE YARA rule
           |
           v
8. Restart cape-processor
           |
           v
9. Submit known sample
           |
           v
10. Verify config in report
           |
           v
11. Add regression test
           |
           v
12. Document sample + parser version
```


## 27. Recommended Parser Header
For internally maintained parsers, use a standardized header:

```python
"""
Malware Family:
    ExampleRAT

Purpose:
    CAPEv2 configuration extractor.

Maintainer:
    Travis Mathison

Created:
    2026-08-25

Configuration Versions:
    v1

Known Sample SHA256:
    <SHA256>

References:
    <internal reference>
    <public reference if applicable>

Notes:
    Parser is intended for CAPEv2 custom/parsers/.
"""
```

This becomes extremely valuable months later when someone has to determine:

```text
Why does this parser exist?
Who wrote it?
What sample was used?
Which version does it support?
```


## 28. Suggested Repository Structure for Team Parsers
Rather than allowing `/opt/CAPEv2/custom/parsers/` to become the authoritative copy, maintain your parsers in Git.

For example:

```text
mare-cape/
├── README.md
├── parsers/
│   ├── ExampleRAT.py
│   ├── QV02.py
│   └── PrivateLoader.py
├── yara/
│   ├── ExampleRAT.yar
│   ├── QV02.yar
│   └── PrivateLoader.yar
├── tests/
│   ├── test_ExampleRAT.py
│   ├── test_QV02.py
│   └── test_PrivateLoader.py
└── docs/
    ├── ExampleRAT.md
    ├── QV02.md
    └── PrivateLoader.md
```

Deployment could then copy approved parsers into:

```text
/opt/CAPEv2/custom/parsers/
```

This gives the team:

```text
Version control
Code review
History
Rollback
Testing
Author attribution
```

and keeps locally developed malware intelligence separate from CAPE itself.


## 29. Quick Parser Creation Checklist
* [ ] Determine exact malware family name.
* [ ] Determine how CAPE/YARA will identify the family.
* [ ] Reverse the configuration location.
* [ ] Determine encoding/encryption.
* [ ] Write standalone extraction code.
* [ ] Expose `extract_config(data)`.
* [ ] Return a JSON-compatible dictionary.
* [ ] Name the parser consistently with the CAPE family.
* [ ] Copy parser to `/opt/CAPEv2/custom/parsers/`.
* [ ] Set ownership to `cape:cape`.
* [ ] Run `py_compile`.
* [ ] Test `extract_config()` directly against a known sample.
* [ ] Verify CAPE YARA detection.
* [ ] Restart `cape-processor`.
* [ ] Submit known-positive sample.
* [ ] Confirm parser execution in logs.
* [ ] Confirm configuration appears in the CAPE report.
* [ ] Add regression/unit test.
* [ ] Commit parser and YARA changes to internal source control.


## 30. Quick Command Reference
Create parser:

```bash
cd /opt/CAPEv2

sudo -u cape vim custom/parsers/ExampleRAT.py
```

Set ownership:

```bash
sudo chown cape:cape \
    custom/parsers/ExampleRAT.py
```

Compile test:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 -m py_compile \
    custom/parsers/ExampleRAT.py
```

Import test:

```bash
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
    /etc/poetry/bin/poetry run python3 -c \
    'from custom.parsers.ExampleRAT import extract_config; print(extract_config)'
```

Restart processor:

```bash
sudo systemctl restart cape-processor
```

Status:

```bash
sudo systemctl status cape-processor --no-pager
```

Logs:

```bash
sudo journalctl -u cape-processor \
    -n 100 \
    --no-pager
```

Live logs:

```bash
sudo journalctl -u cape-processor -f
```


## 31. Key Takeaways
The most important architectural point is that:

```text
custom/parsers/
```

is **not a replacement copy of CAPE-parsers**.

The modern model is:

```text
Official parsers
    |
    +-- Installed CAPE-parsers Python package
    |
    +-- Updated through CAPE/Poetry dependency management

Private parsers
    |
    +-- /opt/CAPEv2/custom/parsers/
```

CAPE's current configuration explicitly references `custom/parsers/`, and the CAPE maintainers recommend that directory for private pure-Python config parsers.

The second critical point is:

```text
Parser != Detection
```

Your Python extractor can be perfect, but CAPE still needs to identify the malware family before it knows which extractor to execute.

Think of the complete capability as:

```text
CAPE YARA Detection
        +
Python Config Parser
        +
Known-positive Regression Sample
        =
Reliable CAPE Family Support
```

For CAPE-native parsers, the core interface remains deliberately simple:

```python
def extract_config(data):
    ...
    return config
```

which is why this is the framework CAPE itself recommends for straightforward malware configuration extraction.