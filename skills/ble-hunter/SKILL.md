# SKILL: Tactical BLE Sniffing Operations (MDK-nRF52840)

## 1. Skill Metadata
* **Name:** Tactical BLE Sniffing Operations
* **Target Hardware:** Geek Diary MDK Dongle (nRF52840) / Wireshark Extcap
* **Target OS:** Linux (Debian/Ubuntu)
* **Author:** nylar357
* **Version:** 1.0.0

## 2. Description
This skill defines the workflows for executing localized Bluetooth Low Energy (BLE) surveillance, threat detection (spoofing/flooding), cryptographic handshake capture, and deep ATT/GATT telemetry vacuuming using a pipeline of custom Python scripts.

## 3. Prerequisites & Environment Setup
Before executing any playbooks, ensure the environment is configured:
1. **Hardware Attached:** MDK Dongle is plugged in and recognized as a serial device (e.g., `/dev/ttyACM0`).
2. **Permissions:** The current user must be in the `dialout` and `wireshark` groups.
3. **Dependencies:** `tshark`, `python3`, and `jq` are installed.
4. **Scripts Available:**
   * `mdk_stream.py` (Raw PDU Firehose)
   * `ble_dashboard.py` (Tactical UI & Threat Detection)
   * `smp_decoder.py` (Security Manager Protocol Decoder)
   * `ble_target_vacuum.py` (Targeted ATT/GATT Extractor)
   * `vacuum_viewer.py` (Live ATT/GATT Telemetry Streamer)

---

## 4. Operational Playbooks (Pipelines)

### Playbook Alpha: Environmental Mapping & Threat Detection
**Objective:** Map all BLE devices in physical proximity, track RSSI, and detect active spoofing or flood attacks.
**Command Pipeline:**
```bash
python3 mdk_stream.py | python3 ble_dashboard.py -a alerts.jsonl -o session_intel.json
