from scapy.all import ARP, Ether, srp, sniff
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import netifaces
from mac_vendor_lookup import MacLookup
import wmi
import socket
import psutil


class NetworkScanner:
    def __init__(self, interface, ip_range):
        self.interface = interface
        self.ip_range = ip_range
        self.mac_lookup = MacLookup()

        # # Update the MAC vendor database during initialization
        # try:
        #     print("Updating MAC vendor database...")
        #     self.mac_lookup.update_vendors()
        #     print("MAC vendor database updated.")
        # except Exception as e:
        #     print(f"Error updating MAC vendor database: {e}")

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
    def __init__(self, interface):
        self.interface = interface
        self.device_bandwidth = {}

    def start_sniffing(self):
        """Start sniffing packets to track per-device bandwidth."""
        threading.Thread(target=self._sniff_packets, daemon=True).start()

    def _sniff_packets(self):
        """Sniff packets and aggregate bandwidth usage per device."""
        sniff(iface=self.interface, prn=self._process_packet, store=False)

    def _process_packet(self, packet):
        """Process a packet to track bandwidth usage per device."""
        if packet.haslayer(ARP):
            return  # Ignore ARP packets

        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            length = len(packet)

            # Track bandwidth for the source device
            if src_ip not in self.device_bandwidth:
                self.device_bandwidth[src_ip] = {"download": 0, "upload": 0}
            self.device_bandwidth[src_ip]["upload"] += length

            # Track bandwidth for the destination device
            if dst_ip not in self.device_bandwidth:
                self.device_bandwidth[dst_ip] = {"download": 0, "upload": 0}
            self.device_bandwidth[dst_ip]["download"] += length

    def get_bandwidth_usage(self):
        """Fetch the current per-device bandwidth usage and reset counters."""
        usage = {
            ip: {
                "download": self._format_bytes(data["download"] * 8),
                "upload": self._format_bytes(data["upload"] * 8),
            }
            for ip, data in self.device_bandwidth.items()
        }

        # Reset the counters for instantaneous usage
        for data in self.device_bandwidth.values():
            data["download"] = 0
            data["upload"] = 0

        return usage

    @staticmethod
    def _format_bytes(size):
        """Convert bytes to human-readable format."""
        for unit in ['bit', 'Kb', 'Mb', 'Gb', 'Tb']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


class NetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIS DGHS LAN Device Monitor")
        self.root.geometry("1200x700")

        self.interface = tk.StringVar()
        self.ip_range = tk.StringVar(value=self.get_ip_range())  # Default subnet range
        self.scanner = None
        self.bandwidth_monitor = None
        self.devices = []

        self.setup_ui()

    def get_ip_range(self):
        gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        return gateway.rsplit('.', 1)[0] + ".0/24"

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
        self.tree.heading("#5", text="Bandwidth Usage (Download/Upload)")

        self.tree.column("#1", width=150)
        self.tree.column("#2", width=200)
        self.tree.column("#3", width=200)
        self.tree.column("#4", width=100)
        self.tree.column("#5", width=200)

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

    def update_table(self):
        """Update the treeview table with real-time bandwidth usage."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        bandwidth_usage = self.bandwidth_monitor.get_bandwidth_usage()

        for device in self.devices:
            ip = device.get("ip", "Unknown")
            usage = bandwidth_usage.get(ip, {"download": "0 B", "upload": "0 B"})
            bandwidth = f"{usage['download']} / {usage['upload']}"
            self.tree.insert("", tk.END, values=(
                device.get("ip", "Unknown"),
                device.get("mac", "Unknown"),
                device.get("type", "Unknown"),
                ", ".join(map(str, device.get("open_ports", []))),
                bandwidth
            ))

        self.root.after(1000, self.update_table)

    def start_scan(self):
        interface = self.interface.get()
        ip_range = self.ip_range.get()
        if not interface or not ip_range:
            messagebox.showwarning("Input Error", "Please detect an interface and specify an IP range.")
            return

        self.status_label.config(text="Status: Scanning...")
        self.scanner = NetworkScanner(interface, ip_range)
        self.bandwidth_monitor = BandwidthMonitor(interface)
        self.bandwidth_monitor.start_sniffing()

        def scan():
            try:
                self.devices = self.scanner.scan()
                self.update_table()
                self.status_label.config(text=f"Status: Found {len(self.devices)} devices")
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
