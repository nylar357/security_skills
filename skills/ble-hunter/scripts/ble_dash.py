import sys
import json
import time
import threading
import argparse
from collections import defaultdict

# --- Configuration ---
ROLLING_WINDOW_SEC = 10
NEW_DEVICE_WINDOW_SEC = 3
FLOOD_THRESHOLD = 30
REFRESH_RATE = 0.5
MAX_DEVICES_DISPLAY = 50

class BLETracker:
    def __init__(self, alerts_file=None):
        self.devices = {}
        self.lock = threading.Lock()
        self.alerts_file = alerts_file
        self.logged_alerts = set() # Track to avoid spamming the log file

    def log_alert(self, mac, anomaly_reason, name):
        if not self.alerts_file: return
        
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mac_address": mac,
            "device_name": name,
            "threat_type": anomaly_reason
        }
        try:
            with open(self.alerts_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except IOError:
            pass

    def ingest_packet(self, packet):
        mac = packet.get("mac_address")
        if not mac: return

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
                
                if rssi: dev["rssi"] = rssi
                
                if name != "Unknown":
                    dev["name"] = name
                    dev["names_seen"].add(name)

                dev["packet_timestamps"] = [t for t in dev["packet_timestamps"] if now - t < 2]

                # --- Anomaly Heuristics & Alert Logging ---
                triggered_reason = None
                if len(dev["packet_timestamps"]) > FLOOD_THRESHOLD:
                    triggered_reason = "FLOODING"
                elif len(dev["names_seen"]) > 2:
                    triggered_reason = "NAME SPOOFING"

                if triggered_reason:
                    dev["is_anomalous"] = True
                    dev["anomaly_reason"] = triggered_reason
                    
                    alert_key = (mac, triggered_reason)
                    if alert_key not in self.logged_alerts:
                        self.logged_alerts.add(alert_key)
                        self.log_alert(mac, triggered_reason, dev["name"])

def reader_thread(tracker):
    for line in sys.stdin:
        try:
            packet = json.loads(line.strip())
            tracker.ingest_packet(packet)
        except (json.JSONDecodeError, TypeError):
            continue

def draw_dashboard(tracker):
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    CYAN = "\033[96m"

    while True:
        now = time.time()
        
        with tracker.lock:
            active_devices = {
                mac: data for mac, data in tracker.devices.items() 
                if now - data["last_seen"] <= ROLLING_WINDOW_SEC
            }

        sys.stdout.write("\033[H\033[J")
        
        total_active = len(active_devices)
        display_count = min(total_active, MAX_DEVICES_DISPLAY)

        print(f"{BOLD}{CYAN}=== BLE TACTICAL DASHBOARD | Displaying: {display_count}/{total_active} Targets | Window: {ROLLING_WINDOW_SEC}s ==={RESET}")
        print(f"{GRAY}{'MAC Address':<18} | {'RSSI':<5} | {'Pkts':<6} | {'Device Name':<25} | {'Status'}{RESET}")
        print(f"{GRAY}" + "-" * 85 + f"{RESET}")

        sorted_devices = sorted(active_devices.items(), key=lambda x: x[1]['rssi'] if x[1]['rssi'] else -100, reverse=True)
        sorted_devices = sorted_devices[:MAX_DEVICES_DISPLAY]

        for mac, data in sorted_devices:
            is_new = (now - data["first_seen"]) <= NEW_DEVICE_WINDOW_SEC
            is_anomalous = data["is_anomalous"]
            
            name = (data["name"][:22] + '...') if len(data["name"]) > 25 else data["name"]
            rssi = data["rssi"]
            pkts = data["total_packets"]

            row_text = f"{mac:<18} | {rssi:<5} | {pkts:<6} | {name:<25} | "
            
            if is_anomalous:
                status = f"{BOLD}{RED}[!] ANOMALY: {data['anomaly_reason']}{RESET}"
                print(f"{BOLD}{RED}{row_text}{RESET}{status}")
            elif is_new:
                status = f"{GREEN}[+] NEW{RESET}"
                print(f"{GREEN}{row_text}{RESET}{status}")
            else:
                print(f"{row_text}")

        time.sleep(REFRESH_RATE)

def export_summary(tracker, output_file):
    """Sanitizes the tracker dictionary and exports a clean JSON summary."""
    print(f"\n[*] Compiling session summary for {len(tracker.devices)} unique devices...")
    export_data = {}
    
    for mac, data in tracker.devices.items():
        export_data[mac] = {
            "first_seen": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data["first_seen"])),
            "last_seen": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data["last_seen"])),
            "primary_name": data["name"],
            "all_names_seen": list(data["names_seen"]),
            "last_rssi": data["rssi"],
            "total_packets": data["total_packets"],
            "was_anomalous": data["is_anomalous"],
            "anomaly_reason": data["anomaly_reason"]
        }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=4)
        print(f"[+] Successfully saved intelligence summary to: {output_file}")
    except Exception as e:
        print(f"[!] Failed to save summary: {e}")

def main():
    parser = argparse.ArgumentParser(description="Live BLE tactical dashboard.")
    parser.add_argument("-o", "--output", help="Save a JSON summary of all discovered devices on exit.", default=None)
    parser.add_argument("-a", "--alerts", help="Append anomalies in real-time to this JSONL log file.", default=None)
    args = parser.parse_args()

    tracker = BLETracker(alerts_file=args.alerts)
    
    t = threading.Thread(target=reader_thread, args=(tracker,), daemon=True)
    t.start()

    try:
        draw_dashboard(tracker)
    except KeyboardInterrupt:
        sys.stdout.write("\033[H\033[J")
        print("[-] Capture halted by user.")
        if args.output:
            export_summary(tracker, args.output)
        else:
            print("[-] No output file specified. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
