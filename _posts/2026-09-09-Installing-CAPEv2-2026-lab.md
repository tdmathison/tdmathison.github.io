---
title: "Installing CAPEv2 sandbox (2026 lab)"
date: 2026-09-09 10:25:00 -0700
categories: [Blogging]
tags: [cape, sandbox]
---

## 2026 Lab work
> This is part of multiple install guides that I have made as I built out a new personal lab environment.<br/>
> The following diagram shows a high-level view of the pipeline being built out.<br/>
> * Step 1: [Installing InetSim (2026 lab)](https://www.travismathison.com/posts/Installing-InetSim-2026-lab/)
> * Step 2: [Installing CAPEv2 sandbox (2026 lab)](https://www.travismathison.com/posts/Installing-CAPEv2-2026-lab/)
> * Step 3: [Installing AssemblyLine4 (2026 lab)](https://www.travismathison.com/posts/Installing-AssemblyLine4-2026-lab/)
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
This guide walks through installing CAPEv2 onto an Ubuntu 24.04 LTS VM.

## Ubuntu Version
The CAPEv2 sandbox wants the 24.04 LTS version of Ubuntu and not the latest.  Install and fully patch version 24.04 LTS that can be downloaded from here:
[https://ubuntu.com/download/alternative-downloads](https://ubuntu.com/download/alternative-downloads)

## VM's Virtualization Engine
Make sure that the VM has the "Virtualize Intel VT-x/EPT" checkbox selected.
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_1/00.png"/><br/>
Figure 1: VMware VT-x setting</div><br />

## Update kernel to specific version
>MongoDB 8.0 has a documented incompatibility with Linux kernels **6.19 through 7.0.13**. MongoDB deliberately detects those kernels and refuses to start because of a TCMalloc incompatibility. Kernel **7.0.14+** fixes it.

If you don't change this now you will be able to confirm it through the logs (post-CAPE install).
```bash
capev2@capev2:/opt/CAPEv2/installer$ uname -r
sudo journalctl -u mongodb.service -b --no-pager -n 100
7.0.0-30-generic

Aug 25 15:24:23 capev2 mongodb[1753]: {"t":{"$date":"2026-08-25T15:24:23.933Z"},"s":"F",  "c":"CONTROL",  "id":12257600,"ctx":"main","msg":"MongoDB cannot start: Linux kernel versions 6.19 and newer has a known incompatibility with this version of MongoDB. See https://jira.mongodb.org/browse/SERVER-121912 for more information."}
```

Check for currently installed kernels
```bash
capev2@capev2:/opt/CAPEv2/installer$ ls -1 /boot/vmlinuz-*
/boot/vmlinuz-7.0.0-30-generic
capev2@capev2:/opt/CAPEv2/installer$ dpkg -l | grep -E '^ii +linux-(image|headers|generic)' | grep -E '6\.8|7\.0'
ii  linux-generic-hwe-24.04                                     7.0.0-30.30~24.04.1                              amd64        Complete Generic Linux kernel and headers
ii  linux-headers-7.0.0-30-generic                              7.0.0-30.30~24.04.1                              amd64        Linux kernel headers for version 7.0.0
ii  linux-headers-generic-hwe-24.04                             7.0.0-30.30~24.04.1                              amd64        Generic Linux kernel headers
ii  linux-image-7.0.0-30-generic                                7.0.0-30.30~24.04.1                              amd64        Signed kernel image generic
ii  linux-image-generic-hwe-24.04                               7.0.0-30.30~24.04.1                              amd64        Generic Linux kernel image
```

If there is no 6.8 kernel installed, install the Ubuntu 24.04 GA kernel metapackage:
```bash
sudo apt update
sudo apt install linux-generic
```

You should now see a new version available
```bash
capev2@capev2:/opt/CAPEv2/installer$ ls -1 /boot/vmlinuz-*
/boot/vmlinuz-6.8.0-138-generic
/boot/vmlinuz-7.0.0-30-generic
```

Reboot and enter the GRUB menu to switch to use the 6.8 kernel.
```bash
sudo reboot
```

Make the 6.8 kernel the prefered version
```bash
sudo vim /etc/default/grub
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.8.0-xx-generic"
sudo update-grub
sudo reboot
```
## Initial tool installs
```bash
sudo apt update
sudo apt install -y git tmux vi
```

## Clone CAPEv2 GitHub repo
```bash
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2/installer
```


## Change \<WOOT\> placeholders
The list is shown below:

```bash
grep -n '<WOOT>' kvm-qemu.sh
116:PEN_REPLACER='<WOOT>'
127:SCSI_REPLACER='<WOOT>'
130:ATAPI_REPLACER='<WOOT>'
133:MICRODRIVE_REPLACER='<WOOT>'
136:BOCHS_BLOCK_REPLACER='<WOOT>'
137:BOCHS_BLOCK_REPLACER2='<WOOT>'
138:BOCHS_BLOCK_REPLACER3='<WOOT>'
141:BXPC_REPLACER='<WOOT>'
144:BOCHS_SEABIOS_BLOCK_REPLACER='<WOOT>'
```

Generate a random value to replace the placeholders
```bash
capev2@capev2:/opt/CAPEv2/installer$ tr -dc 'A-Z0-9' </dev/urandom | head -c 4
```

Perform the replacement
```bash
vim kvm-qemu.sh
:%s/<WOOT>/R7KP/g
:wq
```

## Start the kvm/qemu build session
```bash
tmux new -s cape-kvm
cd /opt/CAPEv2/installer
sudo ./kvm-qemu.sh all capev2 2>&1 | tee kvm-qemu.log
```

After the installation completes; reboot
```bash
sudo reboot
```

Add the LIBVIRT_DEFAULT_URI to .bashrc
```bash
echo 'export LIBVIRT_DEFAULT_URI=qemu:///system' >> ~/.bashrc
source ~/.bashrc
```

## Install Virtual Machine Manager
```bash
cd /opt/CAPEv2/installer
sudo ./kvm-qemu.sh virtmanager capev2 2>&1 | tee kvm-qemu-virt-manager.log
```

## Check your network settings
Print out your network settings
```bash
capev2@capev2:/opt/CAPEv2/installer$ ip -br addr
lo               UNKNOWN        127.0.0.1/8 ::1/128 
ens33            UP             192.168.190.131/24 fe80::20c:29ff:fea0:33ac/64 
virbr0           DOWN           192.168.122.1/24
```

```bash
capev2@capev2:/opt/CAPEv2/installer$ ip route
ip -4 addr show ens33
default via 192.168.190.2 dev ens33 proto dhcp src 192.168.190.131 metric 100 
192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1 linkdown 
192.168.190.0/24 dev ens33 proto kernel scope link src 192.168.190.131 metric 100 
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default qlen 1000
    altname enp2s1
    inet 192.168.190.131/24 brd 192.168.190.255 scope global dynamic noprefixroute ens33
       valid_lft 1477sec preferred_lft 1477sec
```

```bash
capev2@capev2:/opt/CAPEv2/installer$ virsh net-dumpxml default
<network>
  <name>default</name>
  <uuid>32e13997-bf5d-4bae-8bf0-3c5eba079f23</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:d1:9d:3f'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
```

See how this compares against what is currently in the installer script
```bash
capev2@capev2:/opt/CAPEv2/installer$ cd /opt/CAPEv2/installer
grep -nE '^(NETWORK_IFACE|IFACE_IP|PASSWD|CAPE_USER|CAPE_PATH)=' cape2.sh
15:NETWORK_IFACE=virbr1
17:IFACE_IP="192.168.1.1"
21:PASSWD="SuperPuperSecret"
```

```bash
capev2@capev2:/opt/CAPEv2/installer$ grep -nE 'NETWORK_IFACE|IFACE_IP' cape2.sh | head -30
15:NETWORK_IFACE=virbr1
17:IFACE_IP="192.168.1.1"
100:    You need to edit NETWORK_IFACE, IFACE_IP and PASSWD for correct install
1160:TransPort ${IFACE_IP}:9040
1161:DNSPort ${IFACE_IP}:5353
1404:    sed -i "/interface =/cinterface = ${NETWORK_IFACE}" conf/auxiliary.conf
1739:    IFACE_IP=$2
```

## Making config edits
Use `cape-config.sh`, not edits to `cape2.sh`.

Create a new bash script called cape-config.sh
```bash
cd /opt/CAPEv2/installer
vim cape-config.sh
```

Put this in it
```bash
NETWORK_IFACE="virbr0"
IFACE_IP="192.168.122.1"
PASSWD="CHANGE_THIS_TO_A_LONG_RANDOM_PASSWORD"
```

You can generate a strong password via
```bash
capev2@capev2:/opt/CAPEv2/installer$ openssl rand -base64 32
Ld7ggraZu7y5Eq8hIuTmGPpzzlpa+9g9D8oKydv8Tgc=
```

Protect the file
```bash
chmod 600 cape-config.sh
```

## Run CAPE's installer
```bash
tmux new -s cape-install
cd /opt/CAPEv2/installer
```

Verify your override actually works.  This should reflect what you put into the cape-config.sh file.
```bash
capev2@capev2:/opt/CAPEv2/installer$ bash -c '. ./cape-config.sh; echo "NETWORK_IFACE=$NETWORK_IFACE"; echo "IFACE_IP=$IFACE_IP"'
NETWORK_IFACE=virbr0
IFACE_IP=192.168.122.1
```

Then run the upstream-recommended **base** installation
```bash
sudo ./cape2.sh base cape 2>&1 | tee cape-base.log
```

> During the cape2.sh installation it creates a new account called `cape`.  From this point on it is critical to not mix up the administrative Ubuntu admin account and the `cape` account.
>
{: .prompt-warning }

Your `capev2` user administers the host:

```text
> capev2
  ├── sudo
  ├── kvm
  └── libvirt
```

While CAPE itself should operate as:

```text
  cape
  └── /opt/CAPEv2
```

When installation finished, pip install psutil, fix some permissions, and reboot. 
```bash
cd /opt/CAPEv2

sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry install
sudo chown -R cape:cape /opt/CAPEv2/.cache/pypoetry

sudo reboot
```

## Post CAPE install issues and errors
There are a few things that you may observe in the logs.  Some are expected and some may need attention.

> [!NOTE]
> You may see a fatal error in the logs stating:
> "Error checking snapshot state for VM 'cuckoo1' ... Domain not found"
>
>CAPE is starting its scheduler/processor and immediately validating the configured analysis VM named `cuckoo1`. We simply **haven’t created that Windows guest yet**, so libvirt correctly reports that no such domain exists. That is what is killing `cape-processor.service` right now.

**Stop the two looping services for now** so they aren't restarting hundreds of times while we build the guest:
```bash
sudo systemctl stop cape.service
sudo systemctl stop cape-processor.service
```

### MongoDB
If you did not change your kernel to version 6.8 in the beginning, you will likely see the following error due to an incompatibility. Follow the instructions at the beginning of the guide to swith kernel versions.

> There is also a second, separate issue you may observe:
>
> `Cannot connect to MongoDB: 127.0.0.1:27017: Connection refused`
>
{: .prompt-warning }

CAPE warns that the web GUI has Mongo enabled but MongoDB is not currently available.

The following commands can be used to further understand the issue.
```bash
dpkg -l | grep -Ei 'mongo|mongodb'
systemctl status mongodb --no-pager -l
systemctl status mongod --no-pager -l
```

## Start the CAPE web service
```bash
sudo systemctl restart cape-web
```

## Install the Windows VM
Due to TPM 2.0 requirements on Windows 11 it is easier to install Windows 10 if possible.  Download the Windows 10 ISO and move it to the CAPEv2 VM.

Using `Virtual Machine Manager`, create a new VM called "cuckoo1" and mount the Windows 10 ISO to it and perform a default Windows 10 install.

>To fix a missing mouse cursor in a Windows virtual machine running on Ubuntu's Virtual Machine Manager (`virt-manager` / QEMU/KVM), you need to ==add a **Virtio Tablet** hardware.
>
> Add a USB Tablet Device
>
>- Shut down your Windows virtual machine completely.
>- Open **Virtual Machine Manager** on Ubuntu and double-click your Windows VM.
>- Click the **Show virtual hardware details** button (the lightbulb icon at the top).
>- Click the **Add Hardware** button at the bottom of the left-hand list.
>- Select **USB** or **Input** -> **Tablet** (choose **Evtouch USB Tablet** or **USB Tablet**).
>- Click **Finish**.
>- Power on your Windows virtual machine. The mouse pointer should now appear and track smoothly without needing to grab the screen.
{: .prompt-tip }

## Install and configure the CAPE agent inside `cuckoo1`
Locate the agent on the CAPE host.
```bash
capev2@capev2:~/Desktop$ ls -l /opt/CAPEv2/agent/
total 68
-rw-r--r-- 1 cape cape 26522 Aug 25 05:30 agent.py
drwxr-xr-x 2 cape cape  4096 Aug 25 05:30 go
-rw-r--r-- 1 cape cape    44 Aug 25 05:30 pytest.ini
-rw-r--r-- 1 cape cape 28415 Aug 25 05:30 test_agent.py
-rw-r--r-- 1 cape cape   456 Aug 25 05:30 test_python_architecture.py
```

The CAPE agent is a small HTTP service running **inside Windows**
```text
                         CAPE Host
                      192.168.122.1
                             │
                             │ HTTP
                             │ TCP/8000
                             ▼
                  ┌──────────────────────┐
                  │      cuckoo1         │
                  │  192.168.122.105     │
                  │                      │
                  │   CAPE agent         │
                  │       │              │
                  │       └── :8000      │
                  │                      │
                  │   Malware executes   │
                  │       here           │
                  └──────────────────────┘
```

### Install 32-bit Python interpreter
Inside the Windows 10 `cuckoo1` VM, install a **32-bit Python 3.8.2** interpreter. During install, enable “Add Python to PATH.”

Download the 32-bit download from:<br/>
[https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)

>You need to install the Python 3.8.2 (x86) installer and not the latest due to compatibility issues with CAPEv2. If you install the latest you will likely have issues with the samples even running.
{: .prompt-warning }

### Copy agent to the Windows machine
Copy `/opt/CAPEv2/agent/agent.py` into the Windows guest. A simple temporary method is to serve it from the CAPE host:
```bash
cd /opt/CAPEv2/agent
python3 -m http.server 8080 --bind 192.168.122.1
```

Then from Windows browse to it and save it to C:\Users\Public\winupdate.pyw
```bash
http://192.168.122.1:8080/agent.py => C:\Users\Public\winupdate.pyw
```

### Create a new startup task
For Windows 10+, the clean way to auto-start it is Task Scheduler:
- Trigger: **At log on**
- Program: the 32-bit Python `C:\Users\Cipher\AppData\Local\Programs\Python\Python38-32\python.exe`
- Argument: `C:\Users\Public\winupdate.pyw`
- Enable: **Run with highest privileges**
- Enable: **Hidden** checkbox

### Test the agent is working
Run the agent manually in an elevated command prompt:
```bash
python C:\Users\Public\winupdate.pyw
```

From the CAPEv2 machine test the connection.
```bash
apev2@capev2:/opt/CAPEv2/agent$ curl http://192.168.122.105:8000
{"message": "CAPE Agent!", "version": "0.22", "features": ["execpy", "execute", "pinning", "logs", "largefile", "unicodepath", "subdir_upload", "mutex", "browser_extension"], "is_user_admin": true}
```

### Final configurations on Windows machine
1. Disable Windows sleep/hibernation/screensaver so the VM never suspends during analysis.
	1. Open "Power & sleep settings"
	2. Click "Change plan settings"
	3. Set "Turn off the display" to "Never"
	4. Click "Change advanced power settings"
	5. Set "Turn off hard disk after" to 0
	6. Set "Display -> Turn off display after" to "Never"
2. Disable Windows Update inside the guest so the baseline does not drift unexpectedly.
	1. Open Windows Update Settings
	2. Click 'Advanced options"
	3. Enable "Pause update" which will disable it for a month
3. Disable or configure Defender appropriately for a malware-analysis guest.
	1. [https://disable-windows-defender.github.io/](https://disable-windows-defender.github.io/)
4. Disable UAC prompts or otherwise ensure the agent and analyzer can execute without interactive elevation prompts.
	1. Open the **Start menu**.
	2. Type `UAC` in the search box.
	3. Click **Change User Account Control settings**.
	4. Drag the slider down to **Never notify**.
	5. Click **OK**.
	6. Click **Yes** on the final confirmation prompt.

### Install software
1. Install the software baseline you actually want malware to encounter—browser, Office components if needed, archive tools, PDF reader, common runtimes, etc.
	1. Install Chocolately ([https://chocolatey.org/install](https://chocolatey.org/install))
	2. choco install -y googlechrome firefox 7zip notepadplusplus vlc adobereader winscp putty git python jre8 dotnetfx vcredist140 zoom everything
	3. Deploy Office LTSC 2024
		1. [https://learn.microsoft.com/en-us/office/ltsc/2024/deploy](https://learn.microsoft.com/en-us/office/ltsc/2024/deploy)
		2. [https://www.microsoft.com/en-us/download/details.aspx?id=49117&msockid=37cc5f5a46f0671f3f48485b473e66f3](https://www.microsoft.com/en-us/download/details.aspx?id=49117&msockid=37cc5f5a46f0671f3f48485b473e66f3)
		3. In the destination folder you extract it to create the file `cape-office.xml` with the following content:

```xml
<Configuration>
  <Add OfficeClientEdition="32"
	   Channel="PerpetualVL2024">

	<Product ID="ProPlus2024Volume">
	  <Language ID="en-us" />
	</Product>

  </Add>

  <Display Level="Full" AcceptEULA="TRUE" />

  <Updates Enabled="FALSE" />
</Configuration>
```

From an elevated command prompt run:

```bash
setup.exe /download cape-office.xml
setup.exe /configure cape-office.xml
```

### Download or create documents
You should download files, documents, and images to scatter on the system.
* Place files on the desktop, the Documents folder, the Pictures folder, and leave some files in the Downloads folder
* Browse the Internet a bit to get some history
* Open many files so get a history of recent files

## Snapshotting the Windows VM
For **CAPE with KVM/libvirt, take the operational snapshot while Windows is running at the desktop**, not after shutting it down.

> [!IMPORTANT]
> CAPE's current KVM code restores the snapshot and then expects the VM to already be in the `RUNNING` state. It explicitly raises an error saying the snapshot **must be in running state** if that isn't true.

### Prepare the VM immediately before snapshotting
Get `cuckoo1` into exactly the state you want every malware analysis to begin from:
- Windows logged into the analysis account.
- Desktop fully loaded and idle.
- No installers, Settings windows, Task Manager, Explorer windows, etc. open unless deliberately desired.
- CAPE agent running elevated and invisibly (`.pyw` is preferred).
- No pending reboot.
- Windows Update isn't actively doing anything.
- Software baseline is complete.
- Network is configured as `192.168.122.105`.
- Screen isn't locked.
- No malware/sample files are present.

### Take snapshot
Verify the name of the running VM
```bash
virsh list --all
 Id   Name      State
-------------------------
 5    cuckoo1   running
```

Create the snapshot
```bash
virsh snapshot-create-as \
    --domain cuckoo1 \
    --name "cape-clean" \
    --description "Clean Windows 10 CAPE analysis baseline"
```

If you receive the following error, you will need to convert the image.
> [!CAUTION]
> error: Operation not supported: internal snapshots of a VM with pflash based firmware require QCOW2 nvram format

If required, shut the VM down:
```bash
virsh shutdown cuckoo1
```

Back up the VM definition and existing NVRAM
```bash
sudo virsh dumpxml cuckoo1 > ~/cuckoo1-before-nvram-conversion.xml

sudo cp -a \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd.raw-backup
```

Verify the existing format:
```bash
capev2@capev2:/opt/CAPEv2/agent$ sudo qemu-img info /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd
image: /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd
file format: raw
virtual size: 528 KiB (540672 bytes)
disk size: 528 KiB
Child node '/file':
    filename: /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd
    protocol type: file
    file length: 528 KiB (540672 bytes)
    disk size: 528 KiB
```

Convert the NVRAM to QCOW2
```bash
sudo qemu-img convert \
  -f raw \
  -O qcow2 \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2
```

Verify the format of the new file
```bash
capev2@capev2:/opt/CAPEv2/agent$ sudo qemu-img info /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2
image: /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2
file format: qcow2
virtual size: 528 KiB (540672 bytes)
disk size: 836 KiB
cluster_size: 65536
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: false
    refcount bits: 16
    corrupt: false
    extended l2: false
Child node '/file':
    filename: /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2
    protocol type: file
    file length: 896 KiB (917504 bytes)
    disk size: 836 KiB
```

Fix ownership
```bash
sudo chown --reference=/var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2

sudo chmod --reference=/var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd \
  /var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2
```

Change the libvirt XML
```bash
virsh edit cuckoo1

# Change
<nvram template='/usr/share/OVMF/OVMF_VARS_4M.ms.fd' templateFormat='raw' format='raw'>/var/lib/libvirt/qemu/nvram/cuckoo1_VARS.fd</nvram>

# To
<nvram format='qcow2'>/var/lib/libvirt/qemu/nvram/cuckoo1_VARS.qcow2</nvram>
```

Boot back into Windows
```bash
virsh start cuckoo1
```

Create the snapshot
```bash
capev2@capev2:/opt/CAPEv2/agent$ virsh snavirsh snapshot-create-as \
    --domain cuckoo1 \
    --name "cape-clean" \
    --description "Clean Windows 10 CAPE analysis baseline"
Domain snapshot cape-clean created
```

You can view the snapshot via:
```bash
capev2@capev2:/opt/CAPEv2/agent$ virsh snapshot-list cuckoo1
 Name         Creation Time               State
---------------------------------------------------
 cape-clean   2026-08-25 23:15:08 +0000   running
```

## Test the snapshot manually
Perform the following commands to make sure the restore works.
```bash
virsh destroy cuckoo1
virsh snapshot-revert cuckoo1 cape-clean

# After restore, you should be able to reach it via the CAPEv2 machine
capev2@capev2:/opt/CAPEv2/agent$ curl --connect-timeout 10 http://192.168.122.105:8000
{"message": "CAPE Agent!", "version": "0.22", "features": ["execpy", "execute", "pinning", "logs", "largefile", "unicodepath", "subdir_upload", "mutex", "browser_extension"], "is_user_admin": true}
```

Finally, shut the VM down
```bash
virsh destroy cuckoo1
```

## Configure CAPE
### kvm.conf
```bash
sudo -u cape vim /opt/CAPEv2/conf/kvm.conf
```

Update the config to match the following
```c
[kvm]
machines = cuckoo1
interface = virbr0
dsn = qemu:///system

[cuckoo1]
label = cuckoo1
platform = windows
ip = 192.168.122.105
interface = virbr0
arch = x64
tags = win10,x64
snapshot = cape-clean
```

### cuckoo.conf
```bash
sudo -u cape vim /opt/CAPEv2/conf/cuckoo.conf
```

Update the config to match the following
```c
[resultserver]
ip = 192.168.122.1
```

### Setting up proper network architecture
We want to configure the machine to have the following architecture.
```text
                        CAPEv2 Ubuntu
                   ┌─────────────────────┐
Management/LAN ────┤ ens33               │
                   │                     │
Dirty Internet ────┤ ens37               │
                   │                     │
                   │ virbr0              ├──── cuckoo1
                   └─────────────────────┘     192.168.122.105
                         192.168.122.1
```

**Add new NIC**
* Power off the CAPEv2 VM
* VM->Settings->Add Network Adapter->Bridged

Boot CAPE and identify the new NIC
```bash
capev2@capev2:~/Desktop$ ip -br link
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
ens33            UP             00:0c:29:a0:33:ac <BROADCAST,MULTICAST,UP,LOWER_UP> 
ens37            UP             00:0c:29:a0:33:b6 <BROADCAST,MULTICAST,UP,LOWER_UP> 
virbr0           DOWN           52:54:00:d1:9d:3f <NO-CARRIER,BROADCAST,MULTICAST,UP>

capev2@capev2:~/Desktop$ ip -br addr
lo               UNKNOWN        127.0.0.1/8 ::1/128 
ens33            UP             192.168.190.131/24 
ens37            UP             192.168.1.110/24 fe80::8253:903e:104d:23c4/64 
virbr0           DOWN           192.168.122.1/24 

capev2@capev2:~/Desktop$ ip route
default via 192.168.190.2 dev ens33 proto dhcp src 192.168.190.131 metric 100 
default via 192.168.1.1 dev ens37 proto dhcp src 192.168.1.110 metric 101 
192.168.1.0/24 dev ens37 proto kernel scope link src 192.168.1.110 metric 101 
192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1 linkdown 
192.168.190.0/24 dev ens33 proto kernel scope link src 192.168.190.131 metric 100

apev2@capev2:~/Desktop$ ip rule
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default

capev2@capev2:~/Desktop$ networkctl status --no-pager 2>/dev/null | head -80
● Interfaces: n/a
       State: n/a
Online state: unknown
     Address: 192.168.190.131 on ens33
              192.168.1.110 on ens37
              192.168.122.1 on virbr0
              fe80::8253:903e:104d:23c4 on ens37
     Gateway: 192.168.190.2 on ens33
              192.168.1.1 on ens37
```

**Keep ens33 as the host's default route and disable ipv6**
```bash
ens33 = management
192.168.190.131
GW 192.168.190.2
Connection: netplan-ens33

ens37 = dirty line
192.168.1.110
GW 192.168.1.1
Connection: Wired connection 1
```

```bash
# Keep ens37 from becoming a host default route 
sudo nmcli connection modify "Wired connection 1" \ 
	ipv4.never-default yes \ 
	ipv4.route-table 100

# Explicit dirty-table Internet route 
sudo nmcli connection modify "Wired connection 1" \ 
	+ipv4.routes "0.0.0.0/0 192.168.1.1 table=100"

# Apply
sudo nmcli connection down "Wired connection 1"
sudo nmcli connection up "Wired connection 1"
```

**Create a dedicated dirty-line routing table**
```bash
capev2@capev2:~/Desktop$ echo "100 dirty" | sudo tee -a /etc/iproute2/rt_tables
100 dirty

capev2@capev2:~/Desktop$ tail /etc/iproute2/rt_tables
255	local
254	main
253	default
0	unspec
#
# local
#
#1	inr.ruhep
400 ens33
100 dirty
```

**Give CAPE's dirty table its route**
```bash
sudo ip route add 192.168.1.0/24 dev ens37 table dirty
sudo ip route add default via 192.168.1.1 dev ens37 table dirty
```

**We need to remove libvirt NAT**
Ultimately `virbr0` should be an **isolated libvirt network**. It should provide the private network between CAPE and `cuckoo1`, but it should **not** perform NAT itself.
```bash
virsh net-dumpxml default > ~/libvirt-default-before-cape.xml
virsh net-edit default

# Remove the entire `<forward>` block
<forward mode='nat'>
  <nat>
    <port start='1024' end='65535'/>
  </nat>
</forward>
```

**Restart the libvirt network**
```bash
virsh net-destroy default
virsh net-start default
```

### routing.conf
Change the `[routing]` section to:
```c
[routing]
enable_pcap = yes
route = internet
internet = ens37
nat = yes
no_local_routing = yes
rt_table = main
reject_segments = 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
reject_hostports = none
auto_rt = no
drop = yes
verify_interface = yes
verify_rt_table = yes
```

Enable Internet routing on dirty line for Windows 10 VM
```bash
cd /opt/CAPEv2

sudo env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry run python3 \
  utils/router_manager.py \
  -r internet \
  -e \
  --vm-name cuckoo1 \
  --verbose
```

Delete it
```bash
cd /opt/CAPEv2

sudo env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry run python3 \
  utils/router_manager.py \
  -r internet \
  -d \
  --vm-name cuckoo1 \
  --verbose
```

### Restart the CAPE services
```bash
sudo systemctl restart cape-rooter
sudo systemctl restart cape-web
sudo systemctl restart cape
sudo systemctl restart cape-processor
```


## First end-to-end analysis
Navigate to [http://192.168.190.131:8000/](http://192.168.190.131:8000/)
Submit a few samples to make sure it can process them.
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_1/01.png"/><br/>
Figure 2: CAPE sandbox start page</div><br />

It appears to be working after submitting the first two samples.
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260909_1/02.png"/><br/>
Figure 3: CAPE sandbox successful runs</div><br />

## CAPEv2 Additions
### CAPE Community
Some modules or other tools in this repo are written by the community and are not maintained by core devs.

**GitHub**<br/>
[https://github.com/CAPESandbox/community](https://github.com/CAPESandbox/community)

This can be installed/updated through CAPE's own `utils/community.py` utility
```bash
# Remove old files
sudo rm -rf \
  /opt/CAPEv2/data/capa-rules \
  /opt/CAPEv2/data/capa-rules-master

# Make sure permissions are set to cape:cape
sudo chown -R cape:cape /opt/CAPEv2

# Run the community installer
cd /opt/CAPEv2

sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry run python3 \
  utils/community.py -waf -cr
```

### CAPE-parsers
CAPE core and community parsers. Since November 2024, malware configuration parsers were moved out of CAPEv2 core into this dedicated repository/package.

GitHub<br/>
[https://github.com/CAPESandbox/CAPE-parsers](https://github.com/CAPESandbox/CAPE-parsers)

These parsers are already installed with CAPE sandbox.

### Custom Parsers
The location `custom/parsers/` is the location for your local overrides/custom parsers.
```bash
capev2@capev2:/opt/CAPEv2$ cd /opt/CAPEv2

sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry run pip show CAPE-parsers
Name: CAPE-parsers
Version: 0.1.36
Summary: CAPE: Malware Configuration Extraction
Home-page: 
Author: Kevin O'Reilly
Author-email: kev@capesandbox.com
License: MIT
Location: /opt/CAPEv2/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/lib/python3.12/site-packages
Requires: capstone, dncil, dnfile, netstruct, pefile, pycryptodomex, rat-king-parser, ruff, unicorn, yara-python
Required-by:
```

You can see the locations of the CAPE parsers in the `/opt/CAPEv2/conf/processing.conf` file.  Additionally, configurations like setting your VirusTotal API key can be set in this configuration file as well.


### Update script
The following `update-capev2.sh` script can be created and ran manually or through cron jobs to keep things up to date.
```bash
cd /opt/CAPEv2

# Update CAPE source
git pull

# Reconcile/update Python dependencies, including CAPE-parsers
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry install

# Update community content
sudo -u cape env POETRY_CACHE_DIR=/opt/CAPEv2/.cache/pypoetry \
  /etc/poetry/bin/poetry run python3 utils/community.py -waf -cr
```

## Adding a Linux machine
Now that we have an operational CAPEv2 host and a working Windows 10 VM we can add one more machine to be able to add Linux samples.

The best default version of Ubuntu for this is 24.04 LTS.  The following details should be used for the new VM.

```
VM name:      ubuntu2404
OS:           Ubuntu 24.04 LTS Desktop
Architecture: x86_64
CPU:          2-4 vCPU
RAM:          4 GB
Disk:         40-60 GB
NIC:          default / virbr0
```

The goal will be to have an architecture that looks like the following:
```text
CAPE host
   |
   +-- virbr0  192.168.122.1/24
          |
          +-- cuckoo1      Windows
          |    192.168.122.105
          |
          +-- ubuntu2404   Linux
               192.168.122.106
```

### Install Ubuntu 24.04 LTS
Install the Linux VM through Virtual Machine Manager on the CAPEv2 host.

### Update network settings
Update the network settings to be similar to below.  Note: If the adapter name is not `enp1s0` update it to what matches your system.
```bash
sudo vim /etc/netplan/01-network-manager-all.yaml

# Update the config to be the following
network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: false
      addresses:
        - 192.168.122.106/24
      routes:
        - to: default
          via: 192.168.122.1
      nameservers:
        addresses:
          - 192.168.122.1
```

Apply netplan change
```bash
sudo netplan generate
sudo netplan apply
```

> If you get err messages similar to:
>
> ** (generate:3201): WARNING **: 10:35:10.207: Permissions for /etc/netplan/01-network-manager-all.yaml are too open. Netplan configuration should NOT be accessible by others.
>
{: .prompt-danger }

Execute the following commands to fix the permissions:
```bash
sudo chmod 600 /etc/netplan/01-network-manager-all.yaml
sudo chown root:root /etc/netplan/01-network-manager-all.yam
```

### Install the Linux CAPE dependencies
Due to how the networking is setup, you can't immediately access the Internet.  As a workaround you can create a `provisioning-nat` network adapter to temporarily attach to the VM and remove later.

```bash
vim /tmp/provisioning-nat.xml

# Add the following content
<network>
  <name>provisioning-nat</name>
  <forward mode='nat'/>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.123.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.123.100' end='192.168.123.254'/>
    </dhcp>
  </ip>
</network>
```

Then define and start it
```bash
sudo virsh net-define /tmp/provisioning-nat.xml
sudo virsh net-start provisioning-nat
sudo virsh net-autostart provisioning-nat
```

Shutdown the Ubuntu2404 VM and add a new NIC that uses:
* Network source: `Virtual network 'provisioning-nat':NAT`

Start the Ubuntu2404 VM back up.

Install dependencies
```bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    systemtap-runtime
```

```bash
sudo pip3 install \
    pyinotify \
    Pillow \
    pyscreenshot \
    pyautogui \
    pyasyncore \
    --break-system-packages
```


### Improving Linux behavioral telemetry (Tracee/eBPF support)
```bash
sudo apt update

sudo apt install -y \
    docker.io \
    ca-certificates \
    curl

sudo systemctl enable --now docker
```

Then pull the exact Tracee image CAPE currently documents
```bash
sudo docker pull docker.io/aquasec/tracee:0.24.0

sudo docker image tag \
    aquasec/tracee:0.24.0 \
    aquasec/tracee:latest
```

Enable Tracee in CAPE
On the **CAPE host**:
```bash
cd /opt/CAPEv2
sudo -u cape vim conf/auxiliary.conf

# Change
tracee_linux = no

# To
tracee_linux = yes
```

Then for `processing.conf`
```bash
sudo -u cape vim conf/processing.conf

# Change
[tracee]
enabled = no

# To
[tracee]
enabled = yes
```


### Copy CAPE's agent.py into the Linux VM
On your CAPE host you already have
```bash
/opt/CAPEv2/agent/agent.py
```

Temporarily install SSH in the VM
```bash
sudo apt install openssh-server
```

Then from the CAPE host
```bash
scp /opt/CAPEv2/agent/agent.py \
    ubuntu@192.168.122.106:/tmp/agent.py
```

Inside the guest
```bash
sudo mkdir -p /opt/agent
sudo mv /tmp/agent.py /opt/agent/agent.py
sudo chmod 755 /opt/agent/agent.py
```

### Test the CAPE agent manually
Before doing anything with automatic startup, run:
```bash
sudo python3 /opt/agent/agent.py
```

From the CAPE host:
```bash
curl -v http://192.168.122.106:8000
```

### Configure automatic agent startup
```bash
sudo vim /etc/systemd/system/system-monitor.service
```

Add the following content and save
```c
[Unit]
Description=System Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/agent/agent.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
```

Start the new daemon
```bash
sudo systemctl daemon-reload
sudo systemctl enable system-monitor
sudo systemctl start system-monitor
```

### Disable things that create sandbox noise
CAPE recommends disabling the guest firewall, NTP, automatic updates and some other background services.
```bash
sudo ufw disable
sudo timedatectl set-ntp off
```

Disable unattended upgrades
```bash
sudo vim /etc/apt/apt.conf.d/20auto-upgrades

# Add the following values and save
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";

sudo systemctl disable --now unattended-upgrades.service
```

### Add the Linux VM to CAPE's KVM configuration
On the CAPEv2 host, edit the following file
```bash
cd /opt/CAPEv2
sudo -u cape vim conf/kvm.conf

# Change
[kvm]
machines = cuckoo1

# To
[kvm]
machines = cuckoo1,ubuntu2404

# Add
[ubuntu2404]
label = ubuntu2404
platform = linux
ip = 192.168.122.106
interface = virbr0
arch = x64
tags = linux,x64,ubuntu,ubuntu2404
snapshot = cape-clean
```

### Enable Linux as a valid VM to submit to in web.conf
By default, this is disabled in the config as CAPEv2 does not officially support Linux.
```bash
cd /opt/CAPEv2
sudo -u cape vim conf/web.conf

# Change
[linux]
enabled = no
static_only = no

# To
[linux]
enabled = yes
static_only = no
```

Then restart the CAPE web and scheduler services
```bash
sudo systemctl restart cape
sudo systemctl restart cape-web
```
### Test CAPE's ability to see the VM
Make sure you can see both ubuntu2404 and cuckoo1
```bash
capev2@capev2:/opt/CAPEv2$ sudo -u cape virsh -c qemu:///system list --all
 Id   Name         State
-----------------------------
 6    ubuntu2404   running
 -    cuckoo1      shut off
```

### Create the clean snapshot
Make sure the Ubuntu VM is running and at the desktop and prepared for a snapshot. If you have not already removed the `provisioning-nat` interface you should shutdown and remove it before bringing it back up for a snapshot.
```bash
# create snapshot
capev2@capev2:/opt/CAPEv2$ virsh -c qemu:///system snapshot-create-as \
    ubuntu2404 \
    cape-clean \
    "CAPE clean Ubuntu 24.04 with Tracee 0.24.1"
Domain snapshot cape-clean created

# shut the VM down
virsh destroy ubuntu2404

# verify it
virsh -c qemu:///system snapshot-list ubuntu2404
```
