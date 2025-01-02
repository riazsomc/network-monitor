import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import ARP, Ether, srp
import psutil
import threading
import time

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface

    def scan(self):
        devices = []
        try:
            # Broadcast ARP request to the LAN
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
            answered_list = srp(broadcast, timeout=2, iface=self.interface, verbose=False)[0]

            for element in answered_list:
                devices.append({
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "device_type": self.get_device_type(element[1].psrc),
                    "dhcp": self.is_dhcp_enabled(element[1].psrc)
                })
        except Exception as e:
            messagebox.showerror("Error", f"Error scanning network: {str(e)}")

        return devices

    def get_device_type(self, ip):
        # Placeholder for identifying device type
        # You could use nmap or similar tools for a detailed scan
        return "Unknown"

    def is_dhcp_enabled(self, ip):
        # Placeholder for determining DHCP status
        return "Unknown"

class BandwidthMonitor:
    def __init__(self):
        self.previous_stats = psutil.net_io_counters(pernic=True)

    def get_bandwidth_usage(self):
        current_stats = psutil.net_io_counters(pernic=True)
        bandwidth_usage = {}
        for nic, stats in current_stats.items():
            if nic in self.previous_stats:
                prev_stats = self.previous_stats[nic]
                bandwidth_usage[nic] = {
                    "download": stats.bytes_recv - prev_stats.bytes_recv,
                    "upload": stats.bytes_sent - prev_stats.bytes_sent
                }
        self.previous_stats = current_stats
        return bandwidth_usage

class NetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIS DGHS LAN Device Monitor")
        self.root.geometry("1200x700")

        self.interface = tk.StringVar()
        self.scanner = None
        self.bandwidth_monitor = BandwidthMonitor()

        self.setup_ui()

    def setup_ui(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=10)

        tk.Label(control_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_entry = tk.Entry(control_frame, textvariable=self.interface)
        self.interface_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(control_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(self.root, columns=("#1", "#2", "#3", "#4", "#5"), show="headings")
        self.tree.heading("#1", text="IP Address")
        self.tree.heading("#2", text="MAC Address")
        self.tree.heading("#3", text="Device Type")
        self.tree.heading("#4", text="DHCP Status")
        self.tree.heading("#5", text="Bandwidth Usage (Download/Upload)")

        self.tree.column("#1", width=200)
        self.tree.column("#2", width=200)
        self.tree.column("#3", width=200)
        self.tree.column("#4", width=100)
        self.tree.column("#5", width=200)

        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)

        self.status_label = tk.Label(self.root, text="Status: Ready", anchor="w")
        self.status_label.pack(fill=tk.X, pady=5)

    def update_table(self, devices):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for device in devices:
            bandwidth = self.bandwidth_monitor.get_bandwidth_usage()
            self.tree.insert("", tk.END, values=(
                device.get("ip", "Unknown"),
                device.get("mac", "Unknown"),
                device.get("device_type", "Unknown"),
                device.get("dhcp", "Unknown"),
                bandwidth.get(device.get("ip", "Unknown"), "Unknown")
            ))

    def start_scan(self):
        interface = self.interface.get()
        if not interface:
            messagebox.showwarning("Input Error", "Please enter a network interface.")
            return

        self.status_label.config(text="Status: Scanning...")
        self.scanner = NetworkScanner(interface)

        def scan():
            devices = self.scanner.scan()
            self.update_table(devices)
            self.status_label.config(text=f"Status: Found {len(devices)} devices")

        threading.Thread(target=scan, daemon=True).start()

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                for row_id in self.tree.get_children():
                    row = self.tree.item(row_id)["values"]
                    file.write(", ".join(map(str, row)) + "\n")
            messagebox.showinfo("Save Results", "Results saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkApp(root)
    root.mainloop()
