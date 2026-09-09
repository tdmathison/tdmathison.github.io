---
title: "Installing InetSim (2026 lab)"
date: 2026-09-09 09:56:00 -0700
categories: [Blogging]
tags: [inetsim]
---

## 2026 Lab work
> [!NOTE] This is part of multiple install guides that I have made as I built out a new personal lab environment.<br/>
> The following diagram shows a high-level view of the pipeline being built out.<br/>
> * Step 1: [Installing InetSim (2026 lab)]()
> * Step 2: [Installing CAPEv2 sandbox (2026 lab)]()
> * Step 3: [Installing AssemblyLine4 (2026 lab)]()

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


## Summary
This guide walks through installing InetSim onto an Ubuntu 26.04 LTS VM.

## Download Ubuntu
1. Download, Install, and patch Ubuntu 26.04 LTS from the Canonical site.

## Setup network
1. Create a new vmnet2 with the following configuration.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_0/00.png"/><br/>
Figure 1: VMware vmnet setup</div><br />

2. Add a new NIC to the InetSim VM as shown below.
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_0/01.png"/><br/>
Figure 2: VMware new network adapter settings</div><br />

3. The following config file should be updated to the following.
```yaml
sudo cat /etc/netplan/01-network-manager-all.yaml 
# Let NetworkManager manage all devices on this system
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    ens37:
      dhcp4: false
      dhcp6: false
      addresses:
        - 10.10.10.2/24
```

4. Run the following commands
```bash
sudo netplan generate
sudo netplan apply
```

## Install InetSim
1. Run the following commands
```bash
sudo apt update
sudo apt install inetsim

inetsim --version
systemctl status inetsim --no-pager
ls -la /etc/inetsim/
grep -vE '^\s*(#|$)' /etc/inetsim/inetsim.conf
```

## Configure INetSim deliberately for this topology
1. Back up the original configuration and then edit original
```bash
sudo cp /etc/inetsim/inetsim.conf /etc/inetsim/inetsim.conf.orig
sudo vim /etc/inetsim/inetsim.conf
```

2. Find these settings and configure them as follows. If they're commented out, uncomment them
```bash
service_bind_address 10.10.10.2
dns_default_ip 10.10.10.2
```

3. Run the following commands to ensure inetsim is using the new configuration
```bash
sudo systemctl restart inetsim
sudo systemctl status inetsim --no-pager -l
```

## Fix DNS compatibility issue
There is an issue is that INetSim 1.3.2 was written around an older `Net::DNS` API. Upstream INetSim still uses the historical `main_loop`, while modern `Net::DNS` has moved to `start_server()`.

The reliable fix is to install an older compatible `Net::DNS` version specifically for INetSim, rather than trying to adapt ten-year-old INetSim internals to a 2026 Perl module API.

1. Install `cpanm`
```bash
sudo apt install cpanminus
```

2. You dont want to overwrite Ubuntu's system `Net::DNS 1.54` globally. Instead, install a private Perl library for INetSim:
```bash
sudo mkdir -p /opt/inetsim-perl

sudo cpanm --local-lib=/opt/inetsim-perl \
  https://cpan.metacpan.org/authors/id/N/NL/NLNETLABS/Net-DNS-1.37.tar.gz
```

3. Update DNS.pm
```bash
sudo cp /usr/share/perl5/INetSim/DNS.pm /usr/share/perl5/INetSim/DNS.pm.bak
sudo vim /usr/share/perl5/INetSim/DNS.pm

# Near the top of the file, after the `package` declaration and before `use Net::DNS...`, add:
use lib '/opt/inetsim-perl/lib/perl5';

# Further down the file replace
$server->start_server(0);

# With
$server->main_loop;
```

4. Restart inetsim
```bash
sudo systemctl daemon-reload
sudo systemctl restart inetsim
```
