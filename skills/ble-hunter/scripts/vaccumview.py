import sys
import json
import time

# ANSI Terminal Colors
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

def format_hex(hex_string):
    """Adds spaces between hex bytes for readability (e.g., '0a1b' -> '0A 1B')"""
    if not hex_string: return ""
    return " ".join(hex_string[i:i+2].upper() for i in range(0, len(hex_string), 2))

def main():
    print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Initializing Live Vacuum Stream...{Colors.RESET}")
    print(f"{Colors.GRAY}Waiting for target activity from 44:43:99:51:ff:c4 or 70:34:74:b6:7a:ab...{Colors.RESET}\n")

    for line in sys.stdin:
        try:
            packet = json.loads(line.strip())
            
            ts = packet.get("timestamp", "").split(" ")[1] # Just grab the time, drop the date
            mac = packet.get("target_mac", "Unknown")
            rssi = packet.get("rssi", "-X")
            
            idents = packet.get("identifiers", {})
            payloads = packet.get("payloads", {})

            # 1. Check for ATT/GATT Connection Data (Highest Priority)
            att_opcode = payloads.get("att_opcode")
            if att_opcode:
                handle = payloads.get("att_handle", "N/A")
                val_hex = payloads.get("att_value_hex", "")
                
                # Determine operation type based on standard BLE opcodes
                op_name = "ATT_REQ"
                color = Colors.YELLOW
                if att_opcode == "0x12" or att_opcode == "0x52": # Write Request/Command
                    op_name = "GATT WRITE"
                    color = Colors.RED
                elif att_opcode == "0x0b": # Read Response
                    op_name = "GATT READ "
                    color = Colors.GREEN
                elif att_opcode == "0x1b": # Handle Value Notification
                    op_name = "GATT NOTIF"
                    color = Colors.CYAN
                
                print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {color}{Colors.BOLD}[{op_name}]{Colors.RESET} {mac} (RSSI:{rssi}) | Handle: {Colors.BOLD}{handle}{Colors.RESET} | Data: {format_hex(val_hex)}")
                continue

            # 2. Check for Custom Manufacturer Data Beacons
            mfg_data = payloads.get("mfg_data_hex")
            if mfg_data:
                name = idents.get("name")
                name_str = f"'{name}'" if name else "Unknown"
                print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {Colors.MAGENTA}[MFG DATA]  {Colors.RESET} {mac} (RSSI:{rssi}) | {name_str} | Payload: {format_hex(mfg_data)}")
                continue

            # 3. Check for Service UUIDs (Device Fingerprinting)
            uuid16 = idents.get("uuid_16")
            if uuid16:
                uuids = ", ".join(uuid16) if isinstance(uuid16, list) else uuid16
                print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {Colors.CYAN}[SVC UUID]  {Colors.RESET} {mac} (RSSI:{rssi}) | Services Advertised: {Colors.BOLD}{uuids}{Colors.RESET}")
                continue

        except json.JSONDecodeError:
            continue
        except Exception as e:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.MAGENTA}[*] Stream terminated by operator.{Colors.RESET}")
        sys.exit(0)
