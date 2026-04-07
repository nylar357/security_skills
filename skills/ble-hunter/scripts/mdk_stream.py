import sys
import json
import subprocess

def get_nrf_interfaces():
    # ... (same as before) ...
    interfaces = []
    try:
        output = subprocess.check_output(["tshark", "-D"], text=True)
        seen_devices = set()
        for line in output.splitlines():
            if "nRF Sniffer" in line:
                interface_num = line.split(".")[0].strip()
                device_str = line.split(" ")[1] if len(line.split(" ")) > 1 else ""
                if device_str not in seen_devices:
                    seen_devices.add(device_str)
                    interfaces.append(interface_num)
    except Exception as e:
        print(f"[!] Error finding nRF interfaces: {e}", file=sys.stderr)
    return interfaces

def main():
    interfaces = get_nrf_interfaces()
    if not interfaces:
        print("[!] No nRF Sniffers found.", file=sys.stderr)
        return

    print(f"[*] Starting raw capture on interfaces: {', '.join(interfaces)}...", file=sys.stderr)
    
    cmd = ["tshark"]
    for interface in interfaces:
        cmd.extend(["-i", interface])
    
    cmd.extend([
        "-l", "-T", "ek",
        "-e", "btle.advertising_address",
        "-e", "btle.advertising_header.pdu_type",
        "-e", "nordic_ble.rssi",
        "-e", "btcommon.eir_ad.entry.device_name",
        "-e", "btcommon.eir_ad.entry.company_id",
        "-e", "btcommon.eir_ad.entry.data",
        "-e", "btsmp.opcode"  # <--- NEW: Extract Security Manager Protocol Opcodes
    ])

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    try:
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            try:
                packet = json.loads(line)
                if "index" in packet or "layers" not in packet: continue
                
                layers = packet["layers"]
                
                mac_addr = layers.get('btle_advertising_address', [None])[0]
                if not mac_addr: continue

                # Extract standard fields
                rssi = layers.get('nordic_ble_rssi', [None])[0]
                pdu_type = layers.get('btle_advertising_header_pdu_type', [None])[0]
                
                # Extract SMP Opcode
                smp_opcode = layers.get('btsmp_opcode', [None])[0]

                output_data = {
                    "mac_address": mac_addr,
                    "rssi": int(rssi) if rssi else None,
                    "pdu_type": pdu_type,
                    "smp_opcode": smp_opcode  # <--- NEW: Pass to decoder
                }

                print(json.dumps(output_data), flush=True)

            except json.JSONDecodeError:
                continue
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...", file=sys.stderr)
        process.terminate()

if __name__ == "__main__":
    main()
