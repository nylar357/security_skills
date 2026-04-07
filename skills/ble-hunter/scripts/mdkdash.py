import sys
import json
import time
import threading
from collections import defaultdict

# --- Configuration ---
ROLLING_WINDOW_SEC = 10     # How long to keep a device on the dashboard
NEW_DEVICE_WINDOW_SEC = 3   # How long to highlight a device as "NEW"
FLOOD_THRESHOLD = 30        # Packets per 2 seconds to trigger an anomaly
REFRESH_RATE = 0.5          # Dashboard redraw speed in seconds
MAX_DEVICES_DISPLAY = 50    # Maximum number of targets to draw on screen

class BLETracker:
    def __init__(self):
        self.devices = {}
        self.lock = threading.Lock()

    def ingest_packet(self, packet):
        mac = packet.get("mac_address")
        if not mac:
            return

        now = time.time()
        name = packet.get("device_name", "Unknown")
        rssi = packet.get("rssi", -100)
        
        with self.lock:
            if mac not in self.devices:
                self.devices[mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "name": name,
                    "rssi": rssi,
                    "names_seen": {name} if name != "Unknown" else set(),
                    "packet_timestamps": [now],
                    "total_packets": 1,
                    "is_anomalous": False,
                    "anomaly_reason": ""
                }
            else:
                dev = self.devices[mac]
                dev["last_seen"] = now
                dev["total_packets"] += 1
                dev["packet_timestamps"].append(now)
                
                # Update RSSI (keep it fresh)
                if rssi: dev["rssi"] = rssi
                
                # Track name changes (Spoofing detection)
                if name != "Unknown":
                    dev["name"] = name
                    dev["names_seen"].add(name)

                # Clean up old packet timestamps for flood detection (keep last 2 seconds)
                dev["packet_timestamps"] = [t for t in dev["packet_timestamps"] if now - t < 2]

                # --- Anomaly Heuristics ---
                if len(dev["packet_timestamps"]) > FLOOD_THRESHOLD:
                    dev["is_anomalous"] = True
                    dev["anomaly_reason"] = "FLOODING"
                elif len(dev["names_seen"]) > 2:
                    dev["is_anomalous"] = True
                    dev["anomaly_reason"] = "NAME SPOOFING"

def reader_thread(tracker):
    """Background thread that constantly reads from the tshark pipe."""
    for line in sys.stdin:
        try:
            packet = json.loads(line.strip())
            tracker.ingest_packet(packet)
        except (json.JSONDecodeError, TypeError):
            continue

def draw_dashboard(tracker):
    """Main loop that redraws the terminal UI."""
    # ANSI Color Codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    CYAN = "\033[96m"

    while True:
        now = time.time()
        
        with tracker.lock:
            # Filter devices seen in the last ROLLING_WINDOW_SEC
            active_devices = {
                mac: data for mac, data in tracker.devices.items() 
                if now - data["last_seen"] <= ROLLING_WINDOW_SEC
            }

        # Clear screen and move cursor to top left
        sys.stdout.write("\033[H\033[J")
        
        total_active = len(active_devices)
        display_count = min(total_active, MAX_DEVICES_DISPLAY)

        # Draw Header
        print(f"{BOLD}{CYAN}=== BLE TACTICAL DASHBOARD | Displaying: {display_count}/{total_active} Targets | Window: {ROLLING_WINDOW_SEC}s ==={RESET}")
        print(f"{GRAY}{'MAC Address':<18} | {'RSSI':<5} | {'Pkts':<6} | {'Device Name':<25} | {'Status'}{RESET}")
        print(f"{GRAY}" + "-" * 85 + f"{RESET}")

        # Sort by RSSI (strongest signal at the top)
        sorted_devices = sorted(active_devices.items(), key=lambda x: x[1]['rssi'] if x[1]['rssi'] else -100, reverse=True)

        # Apply the display limit
        sorted_devices = sorted_devices[:MAX_DEVICES_DISPLAY]

        for mac, data in sorted_devices:
            is_new = (now - data["first_seen"]) <= NEW_DEVICE_WINDOW_SEC
            is_anomalous = data["is_anomalous"]
            
            name = (data["name"][:22] + '...') if len(data["name"]) > 25 else data["name"]
            rssi = data["rssi"]
            pkts = data["total_packets"]

            # Format the row based on state
            row_text = f"{mac:<18} | {rssi:<5} | {pkts:<6} | {name:<25} | "
            
            if is_anomalous:
                # BOLD and RED for anomalies
                status = f"{BOLD}{RED}[!] ANOMALY: {data['anomaly_reason']}{RESET}"
                print(f"{BOLD}{RED}{row_text}{RESET}{status}")
            
            elif is_new:
                # GREEN for new devices
                status = f"{GREEN}[+] NEW{RESET}"
                print(f"{GREEN}{row_text}{RESET}{status}")
            
            else:
                # Standard output
                print(f"{row_text}")

        time.sleep(REFRESH_RATE)

def main():
    tracker = BLETracker()
    
    # Start the background ingestion thread
    t = threading.Thread(target=reader_thread, args=(tracker,), daemon=True)
    t.start()

    try:
        draw_dashboard(tracker)
    except KeyboardInterrupt:
        # Clear screen on exit
        sys.stdout.write("\033[H\033[J")
        print("[-] Exiting Dashboard...")
        sys.exit(0)

if __name__ == "__main__":
    main()
