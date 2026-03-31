---
title: "Kimwolf botnet"
date: 2026-01-15 18:15:00 -0700
categories: [Blogging]
tags: [kimwolf, malware, botnet]
---

## Summary
Kimwolf is a new Android-based DDoS botnet that emerged in late 2025 as a variant or offshoot of the infamous Aisuru botnet. It primarily targets Android TV devices (TV boxes, smart TVs, set-top boxes, tablets) and has rapidly grown to an army of over 2 million infected devices worldwide.

Security researchers at QiAnXin XLab named it “Kimwolf” because the malware uses the wolfSSL library and displays North Korea-themed messages in some versions. Notably, Kimwolf is closely tied to Aisuru – they share code and even co-infected the same devices through late 2025, indicating the same hacker group operates both.

## Timeline
The following image represents the current timeline of how the botnet has emerged and developed.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260115_0/00.png"/><br/>
Figure 1: Kimwolf timeline chart</div>

## Infection Path
Kimwolf primarily compromises Android TV boxes and smart TVs by abusing exposed Android Debug Bridge (ADB) services, often reachable indirectly through residential proxy networks. 

Many low-cost Android TV devices ship with ADB enabled over TCP (commonly ports 5555, 5858, or 12108) and lack proper authentication. Kimwolf operators scan for these exposed services frequently routing their traffic through residential proxy providers to blend in and bypass ISP or geo-based filtering. Once an exposed ADB endpoint is reachable, the attacker executes shell commands to download and install a malicious APK or native binary directly onto the device.

After initial access, the dropper establishes persistence (boot receivers or system-level execution), deploys the Kimwolf native payload, and optionally reconfigures ADB (changing ports or locking it down) to prevent competing infections. 

The malware then performs encrypted command-and-control initialization: it resolves C2 endpoints using DNS-over-TLS (DoT) or blockchain-based resolution (ENS), verifies commands using elliptic-curve signatures, and registers the device with the botnet. Once enrolled, the device can be used for DDoS attacks, proxying traffic, tunneling, or remote command execution, effectively turning consumer Android hardware into a persistent botnet node with minimal user visibility.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260115_0/01.png"/><br/>
Figure 2: Kimwolf infection chain</div>

## Comparing Capabilities to Aisuru
Below is a feature-by-feature comparison table highlighting how Kimwolf differs from (and extends) Aisuru, focusing on architecture, infection vectors, C2 design, and operational use.

| **Category** | **Aisuru Botnet** | **Kimwolf Botnet** |
|----|----|----|
| **Primary Target Platform** | Traditional IoT devices (routers, DVRs, cameras, embedded Linux) | Android-based devices (Android TV boxes, smart TVs, set-top boxes) |
| **Operating System** | Embedded Linux (BusyBox-style environments) | Android (native ARM ELF via NDK + APK droppers) |
| **Initial Emergence** | Active throughout 2024, publicly reported mid-2024 | Emerged Aug–Oct 2025 as Android-focused expansion |
| **Relationship** | Original botnet | Direct evolution / sibling operated by same actor |
| **Infection Vector** | Credential brute-force, firmware compromise, exposed services | Exposed Android Debug Bridge (ADB) often accessed via residential proxies |
| **Propagation Method** | Scanning + exploit scripts, supply-chain abuse (e.g., router firmware) | ADB command execution, APK sideloading, native payload drop |
| **Dropper Mechanism** | Shell scripts, wget/curl payload delivery | Malicious APKs that extract and execute native ELF payloads |
| **Persistence** | Init scripts, cron jobs, filesystem modifications | Android boot receivers, native persistence, optional ADB reconfiguration |
| **Primary Binary Type** | ELF (Mirai-derived) | ARM ELF (UPX-packed) + Android APK installers |
| **Code Lineage** | Mirai variant with custom extensions | Mirai-derived core + reused Aisuru components |
| **C2 Transport** | Plain TCP / UDP, sometimes HTTP | TLS (wolfSSL), WebSocket (later versions) |
| **DNS Usage** | Standard DNS resolution | DNS-over-TLS (DoT) to evade DNS visibility |
| **C2 Obfuscation** | Hardcoded IPs/domains, fast rotation | XOR-obfuscated IPs, ENS (Ethereum Name Service) resolution |
| **Blockchain Usage** | None observed | ENS-based C2 discovery (Ethereum smart contracts) |
| **Command Authentication** | Minimal or none | ECDSA-signed commands (public key embedded in malware) |
| **Proxy Capability** | Limited / incidental | Explicit residential proxy functionality (monetization focus) |
| **DDoS Capability** | Extremely high (10–30 Tbps observed) | Comparable scale when combined with Aisuru; billions of commands issued |
| **Primary Monetization** | DDoS-for-hire | DDoS-for-hire + sale of residential proxy access |
| **C2 Resilience Strategy** | Rapid domain/IP rotation | Domain rotation → ENS migration → hardcoded IP fallback |
| **Detection Evasion** | Volume-based overwhelm, infrastructure churn | Encryption everywhere, decentralized C2 discovery, low AV detection |
| **Sample Packaging** | Standalone ELF binaries | APKs + embedded native payloads |
| **Certificate Usage** | Not applicable | Reused Android signing certificates across Kimwolf & Aisuru droppers |
| **Operational Scale (Observed)** | Hundreds of thousands to millions of IoT nodes | ~1.8–2M Android devices observed globally |
| **Geographic Spread** | Global, IoT-heavy regions | Global, with high concentration in Android TV–heavy markets |
| **Defensive Challenges** | Traffic volume, fast rotation | Encrypted DNS, blockchain C2, residential IP blending |

## Identifying Infected Clients
### Exposed or Abused ADB Services
Kimwolf relies heavily on ADB for initial compromise.
**Indicators**
* TCP ports 5555, 5858, 12108, 3222 open on Android-identified devices
* ADB sessions originating from residential IP ranges
* ADB port changes shortly after compromise (e.g., device rebinds ADB to 12108)
 
**NetFlow clues**
* Short-lived TCP sessions to port 5555 followed by outbound TLS traffic
* ADB access followed by APK or ELF download traffic (HTTP, raw TCP)

### Encrypted DNS Usage (Highly Distinctive)
Kimwolf resolves C2 infrastructure using DNS-over-TLS (DoT).
 
**Indicators**
* Outbound TCP connections to:
  * 8.8.8.8:853
  * 1.1.1.1:853
* From devices that normally do not use encrypted DNS (TVs, set-top boxes)
 
**NetFlow clues**
* Small, periodic TLS sessions to port 853
* Followed by new outbound TLS sessions to unrelated VPS IPs
* NOTE: Consumer Android TVs almost never use DoT legitimately.

### Suspicious TLS / C2 Communication
After DNS resolution, Kimwolf connects to C2 using TLS (wolfSSL).

**Indicators**
* TLS connections from Android/IoT networks to:
  * Unknown VPS providers
  * Rapidly changing IPs
  * Non-browser JA3 fingerprints (if available)
* Regular beaconing intervals (minutes to hours)
 
**NetFlow clues**
* Consistent destination changes with similar byte counts
* TLS sessions without SNI or with uncommon SNI values

### DDoS or Proxy Participation
Infected devices may be used as DDoS bots or residential proxies.

**Indicators**
* Sudden spikes in outbound UDP or TCP traffic
* High fan-out (many destinations, same source)
* Proxy-like behavior (many short TCP sessions to diverse IPs)
 
**NetFlow clues**
* Packet-heavy flows (especially UDP)
* Repeated bursts from the same source IP across time

## C2 Discovery
Because Kimwolf deliberately hides C2 (DoT + TLS + XOR’d IP indirection + ENS fallback), the best automation strategy is not a single technique but rather a pipeline that continuously harvests candidate C2s from multiple vantage points and then validates/triages them.

### Automate C2 extraction from new samples (most reliable)
Even if runtime communications are encrypted, the malware still has to bootstrap. That bootstrap material (domains, XOR keys, ENS name, contract, fallback IPs) is almost always recoverable from binaries/packers.

**How to automate:**
* Continuous sample intake from VT/feeds by pivoting on:
  * Known hashes
  * APK signer cert (when applicable)
  * Unique strings/family markers (e.g., socket/process markers used by the family, wolfSSL usage, etc.)
* Unpack + decrypt strings automatically:
  * UPX-unpack ELF where needed
  * Identify/decode the family’s XOR/string routine (or emulate it) and dump decrypted strings
* Extract:
  * Domains (including staging / fallback)
  * Any “domain → resolved IP → XOR → real IP” scheme
  * ENS name + record key + XOR key
  * Hardcoded IP:port fallbacks

### Monitor ENS (Ethereum Name Service) records
When Kimwolf uses ENS, the “new C2” problem becomes a blockchain monitoring problem. This may become highly effective post-December shift as Kimwolf is specifically designed to survive takedowns.
 
**How to automate:**
* Poll/subscribe to changes for the ENS name (e.g., pawsatyou[.]eth) and the specific text record key the malware reads.
* When the text record changes:
  * Parse the stored value (often IPv6-looking data or encoded bytes)
  * Apply the known transform (XOR last 4 bytes, etc.)
  * Emit the resulting IPv4/IPv6 C2 candidate(s)
* Store a change log (timestamp, old value, new value, derived IPs)

### Mine NetFlow for C2 candidates using behavioral clustering
Even if you can’t see DNS (DoT) or payloads (TLS), flow metadata is enough to discover new infra as it comes online. C2s must be reachable, and a botnet causes many-to-one flow patterns that stick out in peering netflow.
 
**How to automate:**
* Build a “likely Kimwolf host” cohort using high-signal behaviors:
  * IoT/Android subnets
  * DoT sessions (dst port 853 to known resolvers)
  * Prior ADB exposure history
* For that cohort, continuously compute:
  * New outbound destinations per day (IP, ASN, port)
  * Beacon-like periodicity (regular intervals, similar byte counts)
  * Destination concentration (many hosts → same small set of IPs)
* Rank destinations by a score like:
  * #unique_sources * recurrence * low_popularity_penalty * VPS_ASN_weight
* Auto-enrich top candidates:
  * Reverse DNS / passive DNS
  * TLS fingerprinting (JA3/JA4 if available)
  * Hosting/ASN reputation

## Finding new samples
The following Yara rules may be useful to track down new samples.

```yara
rule Kimwolf_Hunt_Domains_Protocol_Markers
{
  meta:
    author = "defender"
    purpose = "VT hunting for Kimwolf samples (strings/domains/protocol markers)"
    reference = "QiAnXin XLab Kimwolf report"
 
  strings:
    // Domains / infra artifacts called out in public reporting
    $d1 = "rtrdedge1.samsungcdn.cloud" ascii nocase
    $d2 = "staging.pproxy1.fun" ascii nocase
    $ens = "pawsatyou.eth" ascii nocase
 
    // Protocol/magic values described for Kimwolf message header evolution
    $m1 = "AD216CD4" ascii
    $m2 = "FD9177FF" ascii
    $m3 = "DPRK" ascii
 
    // Campaign group string example used by the bot (useful if present)
    $grp = "android-postboot-rt" ascii
 
  condition:
    (1 of ($d*)) or
    ($ens and 1 of ($m*)) or
    (2 of ($m*) and $grp)
}
```

V4 samples include some specific strings that may aid in discovery.

```yara
rule Kimwolf_V4_Console_Strings
{
  meta:
    author = "defender"
    purpose = "VT hunting for early Kimwolf v4 binaries (console strings)"
    reference = "QiAnXin XLab Kimwolf report"
 
  strings:
    $s1 = "ForeheadSDK v2.0 Premium Edition" ascii
    $s2 = "Kim Jong-un Leads Our Nation to Strength" ascii
 
  condition:
    any of them
}
```

Kimwolf APK / dropper artifacts (strings + ENS pivot).

```yara
rule Kimwolf_Android_APK_Hunt_Core
{
  meta:
    author = "defender"
    purpose = "Hunt Kimwolf-related Android droppers/APKs on VT (strings/infra pivots)"
    reference = "QiAnXin XLab Kimwolf report"
 
  strings:
    // ENS-based resolution seen in later evolution
    $ens1 = "pawsatyou.eth" ascii nocase
 
    // Known infra string seen in reports/feeds
    $d1 = "staging.pproxy1.fun" ascii nocase
 
    // Banner phrase referenced in reporting
    $b1 = "Android Support Center" ascii nocase
 
  condition:
    1 of ($ens*) or 1 of ($d*) or $b1
}
```

Kimwolf / Aisuru Android “systemservice” style droppers (package naming pivot).

```yara
rule Kimwolf_Aisuru_SystemService_APK_Hunt
{
  meta:
    author = "defender"
    purpose = "Hunt Android droppers consistent with Kimwolf/Aisuru campaign naming"
 
  strings:
    $p1 = "com.n2.systemservice" ascii nocase
    $r1 = "RECEIVE_BOOT_COMPLETED" ascii
    $r2 = "BOOT_COMPLETED" ascii
 
  condition:
    $p1 and (1 of ($r*))
}
```

## References
* https://blog.xlab.qianxin.com/kimwolf-botnet-en/
* https://krebsonsecurity.com/2026/01/who-benefited-from-the-aisuru-and-kimwolf-botnets/
* https://threatfox.abuse.ch/browse/tag/kimwolf/
* https://malpedia.caad.fkie.fraunhofer.de/details/apk.kimwolf

## Indicators of Compromise

| type | indicator | notes |
|----|----|----|
| android_package | com.n2.systemservice062 | Malicious APK package name observed in samples |
| android_package | com.n2.systemservice063 | Malicious APK package name observed in samples |
| android_package | com.n2.systemservice0644 | Malicious APK package name observed in Kimwolf/Aisuru-linked samples |
| certificate_sha1 | 182256bca46a5c02def26550a154561ec5b2b983 | APK signing certificate SHA1 fingerprint |
| domain | 14emeliaterracewestroxburyma02132\[.\]su | Kimwolf C2 / related domain |
| domain | api.groksearch\[.\]net | Kimwolf C2 / related domain |
| domain | fuckbriankrebs\[.\]com | Embedded in DDoS payload generation (udp_dns/mc_enc) |
| domain | fuckzachebt.meowmeowmeowmeowmeow.meow.indiahackgod\[.\]su | Kimwolf C2 / related domain |
| domain | greatfirewallisacensorshiptool.14emeliaterracewestroxburyma02132\[.\]su | Kimwolf C2 domain referenced by Black Lotus Labs |
| domain | lol.713mtauburnctcolumbusoh43085\[.\]st | Kimwolf C2 / related domain |
| domain | lolbroweborrowtvbro.713mtauburnctcolumbusoh43085\[.\]st | Kimwolf C2 / related domain |
| domain | nnkjzfaxkjanxzk.14emeliaterracewestroxburyma02132\[.\]su | Kimwolf C2 / related domain |
| domain | pawsatyou\[.\]eth | Kimwolf C2 / related domain |
| domain | proxy-sdk.14emeliaterracewestroxburyma02132\[.\]su | Proxy SDK endpoint (port 443 noted in report) |
| domain | rtrdedge1.samsungcdn\[.\]cloud | Kimwolf C2 / related domain |
| domain | sdk-bright.14emeliaterracewestroxburyma02132\[.\]su | Proxy SDK endpoint (port 443 noted in report) |
| domain | sdk-dl-prod.proxiessdk\[.\]online | Kimwolf C2 / related domain |
| domain | sdk-dl-production.proxiessdk\[.\]store | Kimwolf C2 / related domain |
| domain | staging.pproxy1\[.\]fun | Kimwolf C2 / related domain |
| domain | zachebt.chachasli\[.\]de | Kimwolf C2 / related domain |
| domain | zachebt.groksearch\[.\]net | Kimwolf C2 / related domain |
| ethereum_contract | 0xde569B825877c47fE637913eCE5216C644dE081F | ENS contract address for pawsatyou.eth (EtherHiding channel) |
| file | ji.so | Embedded/preset filename used for Kimwolf payload |
| file | libniggakernel | Resource ID / embedded binary name referenced in APK resources |
| hash_md5 | 1c03d82026b6bcf5acd8fc4bcf48ed00 | Sample MD5 (SO / ELF) |
| hash_md5 | 2078af54891b32ea0b1d1bf08b552fe8 | Sample MD5 (SO / ELF) |
| hash_md5 | 2fd5481e9d20dad6d27e320d5464f71e | Sample MD5 (APK) |
| hash_md5 | 33435ec640fbd3451f5316c9e45d46e8 | Sample MD5 (SO / ELF) |
| hash_md5 | 34dfa5bc38b8c6108406b1e4da9a21e4 | Sample MD5 (SO / ELF) |
| hash_md5 | 3a172e3a2d330c49d7baa42ead3b6539 | Sample MD5 (APK) |
| hash_md5 | 4cd750f32ee5d4f9e335751ae992ce64 | Sample MD5 (APK) |
| hash_md5 | 51cfe61eac636aae33a88aa5f95e5185 | Sample MD5 (SO / ELF) |
| hash_md5 | 5490fb81cf24a2defa87ea251f553d11 | Sample MD5 (Rust component) |
| hash_md5 | 5f4ed952e69abb337f9405352cb5cc05 | Sample MD5 (APK) |
| hash_md5 | 726557aaebee929541f9c60ec86d356e | Sample MD5 (SO / ELF) |
| hash_md5 | 8011ed1d1851c6ae31274c2ac8edfc06 | Sample MD5 (APK) |
| hash_md5 | 85ba20e982ed8088bb1ba7ed23b0c497 | Sample MD5 (SO / ELF) |
| hash_md5 | 887747dc1687953902488489b805d965 | Sample MD5 (APK) |
| hash_md5 | 9053cef2ea429339b64f3df88cad8e3f | Sample MD5 (SO / ELF) |
| hash_md5 | 95efbc9fdc5c7bcbf469de3a0cc35699 | Sample MD5 (APK) |
| hash_md5 | 9b37f3bf3b91aa4f135a6c64aba643bd | Sample MD5 (SO / ELF) |
| hash_md5 | b1d4739d692d70c3e715f742ac329b05 | Sample MD5 (Rust component) |
| hash_md5 | b688c22aabcd83138bba4afb9b3ef4fc | Sample MD5 (APK) |
| hash_md5 | b89ee1304b94f0951af31433dac9a1bd | Sample MD5 (SO / ELF) |
| hash_md5 | bda398fcd6da2ddd4c756e7e7c47f8d8 | Sample MD5 (APK) |
| hash_md5 | bf06011784990b3cca02fe997ff9b33d | Sample MD5 (SO / ELF) |
| hash_md5 | cf7960034540cd25840d619702c73a26 | Sample MD5 (Rust component) |
| hash_md5 | d086086b35d6c2ecf60b405e79f36d05 | Sample MD5 (SO / ELF) |
| hash_md5 | dfe8d1f591d53259e573b98acb178e84 | Sample MD5 (APK) |
| hash_md5 | e4be95de21627b8f988ba9b55c34380c | Sample MD5 (Downloader component) |
| hash_md5 | e96073b7ed4a8eb40bed6980a287bc9f | Sample MD5 (SO / ELF) |
| hash_md5 | ea7e4930b7506c1a5ca7fee10547ef6b | Sample MD5 (APK) |
| hash_md5 | f8a70ca813a6f5123c3869d418f00fe5 | Sample MD5 (SO / ELF) |
| ip | 104.171.170\[.\]201 | Later IP for greatfirewallisacensorshiptool... domain (Resi Rack LLC) |
| ip | 104.171.170\[.\]21 | Resolved IP for greatfirewallisacensorshiptool... domain (Resi Rack LLC) |
| ip | 136.243.146\[.\]140 | Example real C2 IP derived from ENS record pawsatyou.eth (after XOR) |
| ip | 176.65.149\[.\]19 | Malware hosting server (port 25565) referenced by Black Lotus Labs |
| ip | 194.46.59\[.\]169 | SSH-accessed host referenced in THN (proxy SDK related) |
| ip | 44.7.0\[.\]45 | Example DNS-resolved IP for rtrdedge1.samsungcdn.cloud (pre-XOR) |
| ip | 45.206.3\[.\]189 | Example real C2 IP after XOR (v5) |
| ip | 65.108.5\[.\]46 | Aisuru backend C2 IP (used in analysis referenced by Black Lotus Labs) |
| ip | 93.95.112\[.\]50 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]51 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]52 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]53 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]54 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]55 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| ip | 93.95.112\[.\]59 | Downloader infrastructure (Resi Rack L.L.C. per report) |
| process | netd_services | Kimwolf process disguise name |
| process | tv_helper | Kimwolf process disguise name |
| string | AD216CD4 | Current protocol magic value (header field) |
| unix_socket | @niggaboxv\[number\] | Unix domain socket used for single-instance control |
