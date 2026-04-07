# Security Auditing Agent Skills

![preview](/img/agentskills.png)

𝗰𝗹𝗶𝗰𝗸 𝘁𝗵𝗲 𝘃𝗶𝗱𝗲𝗼 👇
[![Watch The Video](https://images.steamusercontent.com/ugc/854976916434675605/0A7FF9FDC45305AB9F1B4F51DCAC315274B28F96/?imw=5000&imh=5000&ima=fit&impolicy=Letterbox&imcolor=%23000000&letterbox=false)](https://youtu.be/sQZspMsX85k)
( : oǝpᴉɅ ꓕ⅄

A comprehensive collection of AI agent skills focused on security auditing, continuous attack surface mapping, digital forensics, and hardware-level threat detection. Built for execution within Linux CLI environments, these skills enable agents to orchestrate automated security tasks, analyze raw tool outputs, and compile actionable intelligence reports.

## 🎯 Scope

This repository outlines agent skills designed specifically for:

* Performing rigorous domain reconnaissance and host vulnerability discovery
* Structuring automated pipeline workflows using industry-standard Golang tools
* Executing localized Bluetooth Low Energy (BLE) surveillance and payload decoding
* Identifying RF spoofing attacks and decoding cryptographic IoT handshakes

## 🛠️ Security Auditing Categories

### 1. Domain Reconnaissance & Attack Surface Mapping
Agent skills equipped for deep infrastructure analysis and vulnerability discovery. 

* **The 1Shot Pipeline:** An orchestrated workflow integrating the ProjectDiscovery suite (`Subfinder`, `ShuffleDNS`, `Naabu`, `HTTPX`, `Katana`, and `Nuclei`). 
* **Threat Evaluation:** Advanced log-parsing capabilities where the agent ingests raw JSONL outputs to map vulnerabilities against the OWASP Top 10, cross-reference active CVEs, filter false positives, and output tactical remediation reports.

### 2. Tactical BLE Sniffing Operations
Active and passive assessment skills for hardware, physical proximity tracking, and radio frequency analysis using an MDK Dongle (nRF52840) and `tshark`.

* **Threat Detection:** Live identification of BLE proximity spam, popup flooding attacks (e.g., Apple/Samsung spoofers), and malformed packet injection.
* **Protocol Decoding:** Capturing Security Manager Protocol (SMP) exchanges to track pairing events and the distribution of Identity Resolving Keys (IRK).
* **Targeted Telemetry Vacuuming:** Extracting deep memory reads/writes (ATT/GATT) and custom manufacturer payloads from specific IoT devices to build detection signatures.

## 🏗️ Repository Structure

When interacting with the agent, the skills are organized into dedicated subdirectories containing their specific prompts, scripts, and parsers. 

```text
security_skills/
├── README.md                # You are here
├── SKILL.md                 # Base template for generating new skills
├── img/                     # Dashboards, previews, and diagrams
└── skills/
    ├── domain_recon/
    │   ├── SKILL.md         # Assistant instructions for the recon pipeline
    │   └── scripts/
    │       └── 1shot.sh     # Bash wrapper for the ProjectDiscovery suite
    └── ble_sniffing/
        ├── SKILL.md         # Assistant instructions for BLE ops
        └── scripts/
            ├── mdk_stream.py
            ├── ble_dashboard.py
            ├── smp_decoder.py
            └── ble_target_vacuum.py
