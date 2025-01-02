import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import ARP, Ether, srp
import psutil
import threading
import netifaces
import wmi
from mac_vendor_lookup import MacLookup
import socket


class NetworkScanner:
    def __init__(self, interface, ip_range):
        self.interface = interface
        self.ip_range = ip_range
        self.mac_lookup = MacLookup()

        # Update the MAC vendor database during initialization
        try:
            print("Updating MAC vendor database...")
            self.mac_lookup.update_vendors()  # Correct method call on the instance
            print("MAC vendor database updated.")
        except Exception as e:
            print(f"Error updating MAC vendor database: {e}")

    def scan(self):
        """Discover devices and collect detailed information."""
        devices = self.discover_devices()

        for device in devices:
            mac = device["mac"]
            ip = device["ip"]

            # Add device type based on MAC OUI
            device["type"] = self.get_device_type(mac)

            # Check open ports to infer active services
            device["open_ports"] = self.check_open_ports(ip)

        return devices

    def discover_devices(self):
        """Discover devices on the network using ARP."""
        devices = []
        try:
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range)
            answered_list = srp(broadcast, timeout=2, iface=self.interface, verbose=False)[0]

            for sent, received in answered_list:
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc
                })
        except Exception as e:
            print(f"Error during ARP discovery: {e}")

        return devices

    def get_device_type(self, mac):
        """Retrieve the device type (vendor) for a given MAC address."""
        try:
            return self.mac_lookup.lookup(mac)
        except Exception as e:
            print(f"Error in MAC lookup for {mac}: {e}")
            return "Unknown Vendor"

    def check_open_ports(self, ip, ports=[22, 80, 443]):
        """Check common open ports to infer device type."""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception as e:
                print(f"Error scanning port {port} on {ip}: {e}")
        return open_ports


class BandwidthMonitor:
    def __init__(self):
        self.previous_stats = psutil.net_io_counters(pernic=True)

    def get_bandwidth_usage(self):
        """Fetch bandwidth usage statistics for all interfaces."""
        current_stats = psutil.net_io_counters(pernic=True)
        bandwidth_usage = {}
        try:
            for nic, stats in current_stats.items():
                if nic in self.previous_stats:
                    prev_stats = self.previous_stats[nic]
                    bandwidth_usage[nic] = {
                        "download": stats.bytes_recv - prev_stats.bytes_recv,
                        "upload": stats.bytes_sent - prev_stats.bytes_sent
                    }
            self.previous_stats = current_stats
        except Exception as e:
            print(f"Error fetching bandwidth usage: {e}")
        return bandwidth_usage


class NetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIS DGHS LAN Device Monitor")
        self.root.geometry("1200x700")

        self.interface = tk.StringVar()
        self.ip_range = tk.StringVar(value="192.168.1.0/24")  # Default subnet range
        self.scanner = None
        self.bandwidth_monitor = BandwidthMonitor()

        self.setup_ui()

    def setup_ui(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=10)

        tk.Button(control_frame, text="Detect Interface", command=self.detect_interface).pack(side=tk.LEFT, padx=5)
        tk.Label(control_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_label = tk.Label(control_frame, textvariable=self.interface)
        self.interface_label.pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="IP Range:").pack(side=tk.LEFT, padx=5)
        tk.Entry(control_frame, textvariable=self.ip_range, width=15).pack(side=tk.LEFT, padx=5)

        tk.Button(control_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(self.root, columns=("#1", "#2", "#3", "#4", "#5"), show="headings")
        self.tree.heading("#1", text="IP Address")
        self.tree.heading("#2", text="MAC Address")
        self.tree.heading("#3", text="Device Type")
        self.tree.heading("#4", text="Open Ports")
        self.tree.heading("#5", text="Bandwidth Usage")

        self.tree.column("#1", width=150)
        self.tree.column("#2", width=200)
        self.tree.column("#3", width=200)
        self.tree.column("#4", width=100)
        self.tree.column("#5", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)

        self.status_label = tk.Label(self.root, text="Status: Ready", anchor="w")
        self.status_label.pack(fill=tk.X, pady=5)

    def detect_interface(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                interface_guid = default_gateway[1]
                wmi_obj = wmi.WMI()

                # Find the friendly name corresponding to the GUID
                for nic in wmi_obj.Win32_NetworkAdapter():
                    if nic.GUID == interface_guid:
                        friendly_name = nic.NetConnectionID
                        if friendly_name in psutil.net_if_addrs():
                            self.interface.set(friendly_name)
                            self.status_label.config(text=f"Detected Interface: {friendly_name}")
                            return

                messagebox.showwarning("Warning", "Detected interface not found in active interfaces.")
            else:
                messagebox.showwarning("Warning", "No default gateway found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to detect interface: {str(e)}")

    def update_table(self, devices):
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Get bandwidth usage for all interfaces
        bandwidth_usage = self.bandwidth_monitor.get_bandwidth_usage()

        for device in devices:
            # Check if the current interface matches the device's MAC
            interface_bandwidth = bandwidth_usage.get(self.interface.get(), {"download": 0, "upload": 0})
            bandwidth = f"{interface_bandwidth['download']} B / {interface_bandwidth['upload']} B"
            self.tree.insert("", tk.END, values=(
                device.get("ip", "Unknown"),
                device.get("mac", "Unknown"),
                device.get("type", "Unknown"),
                ", ".join(map(str, device.get("open_ports", []))),
                bandwidth
            ))

    def start_scan(self):
        interface = self.interface.get()
        ip_range = self.ip_range.get()
        if not interface or not ip_range:
            messagebox.showwarning("Input Error", "Please detect an interface and specify an IP range.")
            return

        self.status_label.config(text="Status: Scanning...")
        self.scanner = NetworkScanner(interface, ip_range)

        def scan():
            try:
                devices = self.scanner.scan()
                self.update_table(devices)
                self.status_label.config(text=f"Status: Found {len(devices)} devices")
            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {str(e)}")

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
