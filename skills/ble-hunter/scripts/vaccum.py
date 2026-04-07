import sys
import json
import subprocess
import argparse

# --- Target Configuration ---
# Add your target MACs here. Must be lowercase.
TARGET_MACS = {
    "44:43:99:51:ff:c4",
    "70:34:74:b6:7a:ab"
}

def get_nrf_interfaces():
    interfaces = []
    try:
        output = subprocess.check_output(["tshark", "-D"], text=True)
        seen_devices = set()
        for line in output.splitlines():
            if "bluetooth0" in line:
                interface_num = line.split(".")[0].strip()
                device_str = line.split(" ")[1] if len(line.split(" ")) > 1 else ""
                if device_str not in seen_devices:
                    seen_devices.add(device_str)
                    interfaces.append(interface_num)
    except Exception as e:
        print(f"[!] Error finding nRF interfaces: {e}", file=sys.stderr)
    return interfaces

def clean_hex_array(data_layer):
    """Combines tshark's hex arrays into a clean, continuous string."""
    if isinstance(data_layer, list):
        return "".join(data_layer).replace(":", "")
    elif data_layer:
        return str(data_layer).replace(":", "")
    return None

def main():
    parser = argparse.ArgumentParser(description="Targeted BLE Vacuum")
    parser.add_argument("-o", "--output", help="Save the raw stream to a JSONL file", default=None)
    args = parser.parse_args()

    interfaces = get_nrf_interfaces()
    if not interfaces:
        print("[!] No nRF Sniffers found. Check your Linux dialout/wireshark groups.", file=sys.stderr)
        return

    print(f"[*] Locking onto targets: {', '.join(TARGET_MACS)}", file=sys.stderr)
    print(f"[*] Vacuuming Advertising, EIR, and GATT/ATT layers...", file=sys.stderr)
    
    cmd = ["tshark"]
    for interface in interfaces:
        cmd.extend(["-i", interface])
    
    # We are pulling significantly more fields here to capture deep intelligence
    cmd.extend([
        "-l", "-T", "ek",
        "-e", "btle.advertising_address",
        "-e", "btle.scanning_address",
        "-e", "btle.initiator_address",
        "-e", "btle.advertising_header.pdu_type",
        "-e", "nordic_ble.rssi",
        "-e", "btcommon.eir_ad.entry.device_name",
        "-e", "btcommon.eir_ad.entry.company_id",
        "-e", "btcommon.eir_ad.entry.data",
        "-e", "btcommon.eir_ad.entry.uuid_16",
        "-e", "btcommon.eir_ad.entry.uuid_128",
        "-e", "btatt.opcode",
        "-e", "btatt.handle",
        "-e", "btatt.value"
    ])

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    
    output_file = open(args.output, "a") if args.output else None

    try:
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            try:
                packet = json.loads(line)
                if "index" in packet or "layers" not in packet: continue
                
                layers = packet["layers"]
                
                # Extract all possible MACs involved in this packet
                adv_mac = layers.get('btle_advertising_address', [None])[0]
                scan_mac = layers.get('btle_scanning_address', [None])[0]
                init_mac = layers.get('btle_initiator_address', [None])[0]
                
                # IF none of the MACs match our targets, silently drop the packet
                packet_macs = {adv_mac, scan_mac, init_mac}
                if not TARGET_MACS.intersection(packet_macs):
                    continue

                # --- Deep Extraction Phase ---
                # Figure out which target is the primary actor in this packet
                target_mac = list(TARGET_MACS.intersection(packet_macs))[0]

                rssi = layers.get('nordic_ble_rssi', [None])[0]
                pdu_type = layers.get('btle_advertising_header_pdu_type', [None])[0]
                
                # Standard Advertising Data
                device_name = layers.get('btcommon_eir_ad_entry_device_name', [None])[0]
                company_id = clean_hex_array(layers.get('btcommon_eir_ad_entry_company_id', []))
                mfg_data = clean_hex_array(layers.get('btcommon_eir_ad_entry_data', []))
                
                # Service UUIDs (Crucial for identifying what the device does)
                uuid_16 = layers.get('btcommon_eir_ad_entry_uuid_16', [])
                uuid_128 = clean_hex_array(layers.get('btcommon_eir_ad_entry_uuid_128', []))
                
                # ATT/GATT Connection Data (This is the actual read/write data during a connection)
                att_opcode = layers.get('btatt_opcode', [None])[0]
                att_handle = layers.get('btatt_handle', [None])[0]
                att_value = clean_hex_array(layers.get('btatt_value', []))

                output_data = {
                    "timestamp": subprocess.check_output(["date", "+%Y-%m-%d %H:%M:%S.%3N"]).decode().strip(),
                    "target_mac": target_mac,
                    "rssi": int(rssi) if rssi else None,
                    "pdu_type": pdu_type,
                    "identifiers": {
                        "name": device_name,
                        "company_id": company_id,
                        "uuid_16": uuid_16,
                        "uuid_128": uuid_128
                    },
                    "payloads": {
                        "mfg_data_hex": mfg_data,
                        "att_opcode": att_opcode,
                        "att_handle": att_handle,
                        "att_value_hex": att_value
                    }
                }

                # Output to stdout for piping
                json_out = json.dumps(output_data)
                print(json_out, flush=True)

                # Persist to disk if requested
                if output_file:
                    output_file.write(json_out + "\n")
                    output_file.flush()

            except json.JSONDecodeError:
                continue
    except KeyboardInterrupt:
        print("\n[*] Halting vacuum operation...", file=sys.stderr)
        process.terminate()
        if output_file:
            output_file.close()

if __name__ == "__main__":
    main()
