---
title: "Installing AssemblyLine4 (2026 lab)"
date: 2026-09-09 11:21:00 -0700
categories: [Blogging]
tags: [assemblyline4]
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

## Summary
This guide walks through installing AssemblyLine4 onto an Ubuntu 24.04 LTS VM.

This tool fits into our pipeline as shown below:
```text
                     ┌──────────────────┐
                     │    Portal/API    │
                     └────────┬─────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │   Assemblyline   │
                     │     Intake       │
                     └────────┬─────────┘
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
          Identify          Extract           YARA
          File type         children          rules
              │               │                │
              └───────────────┼────────────────┘
                              │
                              ▼
                        Static analysis
                              │
                              ▼
                    ┌────────────────────┐
                    │ Should we detonate?│
                    └─────────┬──────────┘
                              │
                              ▼
                       Assemblyline
                        CAPE Service
                              │
                              ▼
                         CAPEv2 API
                              │
                     ┌────────┴─────────┐
                     ▼                  ▼
                Windows VM         Linux VM
                     │                  │
                     └────────┬─────────┘
                              ▼
                        CAPE Results
                              │
                              ▼
                       Assemblyline
                              │
                  ┌───────────┼───────────┐
                  ▼           ▼           ▼
                IoCs       Behavior    Extracted
                            ATT&CK       Payloads
                  │           │           │
                  └───────────┼───────────┘
                              ▼
                          Reporting /
                     Analyst Escalation
```

## Ubuntu Version
The AssemblyLine4 installation wants the 24.04 LTS version of Ubuntu and not the latest.  Install and fully patch version 24.04 LTS that can be downloaded from here:
* [https://ubuntu.com/download/alternative-downloads](https://ubuntu.com/download/alternative-downloads)

## AssemblyLine4 GitHub
**GitHub**
* [https://github.com/CybercentreCanada/assemblyline](https://github.com/CybercentreCanada/assemblyline)
Docs
* [https://cybercentrecanada.github.io/assemblyline4_docs/](https://cybercentrecanada.github.io/assemblyline4_docs/)

> During the local installation of AssemblyLine4 I found that is is quite resource heavy.  I had issues when allocating 8GB RAM and 2 CPUs.  
> 
> I switched this to instead use:
> * 32GB RAM
> * 4 CPUs w/4 Cores each
{: .prompt-warning }

## Install Docker
For this installation I will be using Docker and the documentation can be found at:
* [https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/docker/](https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/docker/)
* [https://docs.docker.com/engine/install/ubuntu](https://docs.docker.com/engine/install/ubuntu)

```bash
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
```

**Install Docker packages**
```bash
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Configure Docker
Add your user to the `docker` group
```bash
sudo usermod -aG docker $USER
```

Then activate the group without rebooting
```bash
newgrp docker
```

Configure Assemblyline's Docker address pool.  Create/Edit `/etc/docker/daemon.json` and add the following lines:
```bash
{
  "default-address-pools": [
    {
      "base": "10.201.0.0/16",
      "size": 24
    }
  ]
}
```

Restart the docker service
```bash
sudo systemctl restart docker
```
## Install AssemblyLine4
### Clone Assemblyline4.
```bash
mkdir -p ~/deployments

git clone https://github.com/CybercentreCanada/assemblyline-docker-compose.git \
  ~/deployments/assemblyline

cd ~/deployments/assemblyline
```

### Replace every default secret
Your `.env` currently contains intentionally insecure defaults:
```c
FILESTORE_PASSWORD=password_123
ELASTIC_PASSWORD=password_456
SERVICE_API_KEY=password_789
AL_ADMIN_PASSWORD=admin
KIBANA_PASSWORD=kb_password_456
```

Update the environment config
```bash
cd ~/deployments/assemblyline
vim .env
```

Generate strong random values for the secrets. You can do that locally with:
```bash
openssl rand -hex 24
openssl rand -hex 24
openssl rand -hex 24
openssl rand -hex 24
openssl rand -hex 24
```

Then make `.env` look conceptually like:
```c
AL_VERSION=4.7.4.stable13
DOMAIN=assemblyline.local

FILESTORE_PASSWORD=<random-value-1>
ELASTIC_PASSWORD=<random-value-2>
SERVICE_API_KEY=<random-value-3>

AL_ADMIN_USER=admin
AL_ADMIN_PASSWORD=<random-value-4>

KIBANA_USERNAME=kibana_system
KIBANA_PASSWORD=<random-value-5>

ELASTIC_MEM=2048
COMPOSE_ROOT=.
REGISTRY=
COMPOSE_PROJECT_NAME=al
COMPOSE_PROFILES=minimal
```

Protect `.env`
```bash
chmod 600 .env
```

> About `DOMAIN=assemblyline.local`
> * For my local instance I am keeping it the default and we'll create the self-signed certificate for this address.
> * We will later create a /etc/hosts entry to map the name to the IP
{: .prompt-tip }

### Generate the HTTPS certificate
```bash
cd ~/deployments/assemblyline

set -a
source .env
set +a

openssl req \
  -nodes \
  -x509 \
  -newkey rsa:4096 \
  -keyout ./config/nginx.key \
  -out ./config/nginx.crt \
  -days 365 \
  -subj "/C=US/ST=Oregon/O=MARE Lab/CN=$DOMAIN"
```

### Pull down the docker image
```bash
cd ~/deployments/assemblyline
sudo docker compose pull --ignore-buildable
sudo env COMPOSE_BAKE=true docker compose build
sudo docker compose -f bootstrap-compose.yaml pull
sudo docker compose up -d --wait
```

### Bootstrap compose AssemblyLine4
```bash
cd ~/deployments/assemblyline
sudo docker compose -f bootstrap-compose.yaml up
```

### Update /etc/hosts
```
sudo vim /etc/hosts

# Add the following line
192.168.190.133 assemblyline.local
```

## Login to AssemblyLine4
At this point you should be able to open a browser and log in.

Username: admin
Password: <AL_ADMIN_PASSWORD>

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_2/00.png"/><br/>
Figure 1: AssemblyLine4 logon page</div><br />


### Submit a benign sample to test
I submitted the `su` GNU/Linux application.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_2/01.png"/><br/>
Figure 2: AssemblyLine4 sample submit page</div><br />

We can see that it completes the ingest of the file and processes it.  In the details view you can see all of the static analysis it performed.
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_2/02.png"/><br/>
Figure 3: AssemblyLine4 submissions view</div><br />

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_2/03.png"/><br/>
Figure 4: AssemblyLine4 submission file details</div><br />

## CAPE Integration
The AssemblyLine4 documentation states there are a few changes to check and potentially make before connecting the two together.

### On the CAPE host
Edit the two config files with `vim`.
```bash
cd /opt/CAPEv2
sudo -u cape vim conf/reporting.conf
```

```bash
# Change
[litereport] 
enabled = no 
keys_to_copy = CAPE procdump info signatures dropped static target network shot malscore ttps 
behavior_keys_to_copy = processtree summary

# To
[litereport] 
enabled = yes 
keys_to_copy = info debug signatures network curtain sysmon target 
behavior_keys_to_copy = processtree processes summary
```

Restart the cape-processor for settings to take effect.
```bash
sudo systemctl restart cape-processor
```

```bash
sudo -u cape vim conf/api.conf
```

```bash
# Change the following sections
[api]
ratelimit = no

default_user_ratelimit = 99999999999999/s
default_subscription_ratelimit = 99999999999999/s

url = http://example.tld

token_auth_enabled = yes
mcp = no

[taskdelete]
enabled = yes
auth_only = yes
rps = 1/s
rpm = 5/m
mcp = no

[tasksearch]
enabled = yes
auth_only = yes
md5 = yes
sha1 = yes
sha256 = yes
rps = 2/s

[taskview]
enabled = yes
auth_only = yes
rps = 1/s
rpm = 10/m
mcp = no

[taskreport]
enabled = yes
auth_only = yes
all = yes
rps = 1/s
rpm = 6/m
mcp = no

[machinelist]
enabled = yes
auth_only = yes
rps = 1/s
#rpm = 10/m
mcp = no

[cuckoostatus]
enabled = yes
auth_only = yes
rps = 2/s
#rpm = 100/m
mcp = no
```

Enabling all of this will allow us to expose the following API endpoints to AssemblyLine4.
```
GET  /apiv2/cuckoo/status/
GET  /apiv2/machines/list/
GET  /apiv2/tasks/search/sha256/<sha256>/
POST /apiv2/tasks/create/file/
GET  /apiv2/tasks/view/<task-id>/
GET  /apiv2/tasks/get/report/<task-id>/lite/zip/
GET  /apiv2/tasks/delete/<task-id>/
```

Restart the CAPEv2 service
```bash
cd /opt/CAPEv2

sudo systemctl restart cape-web
sudo systemctl status cape-web --no-pager
```

Configure INetSim for CAPEv2
```bash
sudo -u cape vim conf/routing.conf

# Update to show
[inetsim]
enabled = yes
server = 10.10.10.2
dnsport = 53
interface = ens37
ports =
```

Update routing.conf
```bash
sudo -u cape vim conf/routing.conf

# Change
[routing]
route = internet

# To
[routing]
route = none
```


CAPE’s current docs specifically call out `no such table: auth_user` and prescribe running the migrations first.
```bash
sudo -u cape /etc/poetry/bin/poetry run python manage.py migrate
```


Create a user for assemblyline
```bash
cd /opt/CAPEv2/web
sudo -u cape /etc/poetry/bin/poetry run python manage.py createsuperuser

Username (leave blank to use 'cape'): assemblyline
Email address: 
Password: 
Password (again): 
Superuser created successfully.
```

Create a token for the `assemblyline` user:
```bash
cd /opt/CAPEv2/web
sudo -u cape /etc/poetry/bin/poetry run python manage.py drf_create_token assemblyline
```

### On the AssemblyLine host
Verify that it can reach CAPE and that the token works.
```bash
export CAPE_HOST='192.168.190.131'
export CAPE_TOKEN='PASTE_THE_TOKEN_HERE'

curl -sS \
  -H "Authorization: Token $CAPE_TOKEN" \
  "http://$CAPE_HOST:8000/apiv2/cuckoo/status/" \
  | python3 -m json.tool

curl -sS \
  -H "Authorization: Token $CAPE_TOKEN" \
  "http://$CAPE_HOST:8000/apiv2/machines/list/" \
  | python3 -m json.tool
```

Enabled CAPE service on AssemblyLine machine
* Log into AssemblyLine web interface
* Navigate to `Administration->Services`
* Find the `CAPE` service (which should currently be disabled)

Update the `remote_host_details [json]` field to be:
```json
{
  "hosts": [
    {
      "ip": "192.168.190.131",
      "port": 8000,
      "token": "YOUR_CAPE_TOKEN_HERE",
      "internet_connected": false,
      "inetsim_connected": true
    }
  ]
}
```

Set `auto_architecture [json]:` to:
```json
{
  "win": {
    "x64": ["win10"],
    "x86": []
  },
  "ub": {
    "x64": ["ubuntu2404"],
    "x86": []
  }
}
```

Also set the following fields to these values:
```json
allowed_images: ["win10", "ubuntu2404"]
delete_cape_runs: false
enforce_routing: false
allowed_images: []
Number of instances: 1
Accepted file types: "(executable/(windows|linux)|java|audiovisual|meta)/.*|document/(installer/windows|office/(excel|ole|powerpoint|rtf|unknown|word|mhtml|onenote)|pdf$)|code/(javascript|jscript|python|vbs|wsf|html|ps1|batch|hta|vbe|a3x|au3)|shortcut/windows|archive/(chm|iso|rar|vhd|udf|zip|7-zip)|text/windows/registry|audiovisual/flash|uri/https?$"
```

Save changes and enable
* Click the greyed out "disabled" button at the top of the settings page to enable it
* Click the "Save Changes" button at the bottom middle of the page

Select "Administration->Services->Safelist"  and make the following change
```json
Number of instances: 1
```

Save changes and enable
* Click the greyed out "disabled" button at the top of the settings page to enable it
* Click the "Save Changes" button at the bottom middle of the page

Do the same for other services that seem to hang and not complete:
* AVCheck
* TagCheck
* Badlist

