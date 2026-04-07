import sys
import json

# The BLE Security Manager Protocol Opcodes
SMP_MAP = {
    "0x01": "[HANDSHAKE] Pairing Request",
    "0x02": "[HANDSHAKE] Pairing Response",
    "0x03": "[AUTH] Pairing Confirm",
    "0x04": "[AUTH] Pairing Random",
    "0x05": "[ALERT] Pairing Failed",
    "0x06": "[KEY DIST] Encryption Information (LTK)",
    "0x07": "[KEY DIST] Master Identification (EDIV/Rand)",
    "0x08": "[KEY DIST] Identity Information (IRK)",
    "0x09": "[KEY DIST] Identity Address Information (MAC)",
    "0x0a": "[KEY DIST] Signing Information (CSRK)",
    "0x0b": "[ALERT] Security Request",
    "0x0c": "[HANDSHAKE] Pairing Public Key (ECDH)",
    "0x0d": "[AUTH] Pairing DHKey Check",
    "0x0e": "[AUTH] Pairing Keypress Notification"
}

def main():
    print("[-] Waiting for BLE Handshakes and Key Exchanges...")
    
    for line in sys.stdin:
        try:
            packet = json.loads(line.strip())
            smp_opcode = packet.get("smp_opcode")
            
            # If the packet contains an SMP opcode, decode and print it
            if smp_opcode:
                # Some versions of tshark output integers, some hex strings. Normalize it.
                if isinstance(smp_opcode, int) or (isinstance(smp_opcode, str) and not smp_opcode.startswith("0x")):
                    smp_hex = f"0x{int(smp_opcode):02x}"
                else:
                    smp_hex = smp_opcode.lower()

                mac = packet.get("mac_address", "Unknown")
                rssi = packet.get("rssi", "N/A")
                
                event_name = SMP_MAP.get(smp_hex, f"Unknown SMP Opcode ({smp_hex})")
                
                # Use terminal colors to make security events pop out
                if "KEY DIST" in event_name:
                    color = "\033[92m" # Green for Key Distribution
                elif "HANDSHAKE" in event_name or "AUTH" in event_name:
                    color = "\033[94m" # Blue for Handshakes
                elif "ALERT" in event_name:
                    color = "\033[91m" # Red for Failures
                else:
                    color = "\033[0m"  # Default
                
                reset = "\033[0m"
                
                print(f"{color}[!] {event_name} detected from {mac} (RSSI: {rssi}){reset}")

        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
