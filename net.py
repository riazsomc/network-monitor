import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import ARP, Ether, srp
import psutil
import threading
import netifaces
import wmi
import time
import win32com.client
import pythoncom


class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface

    def scan(self):
        devices = []
        try:
            pythoncom.CoInitialize()  # Initialize COM in the scanning thread
            ip_range = self.get_ip_range()
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
            answered_list = srp(broadcast, timeout=2, iface=self.interface, verbose=False)[0]

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "device_type": self.get_device_type(mac),
                    "dhcp": self.is_dhcp_enabled(ip)
                })
        except Exception as e:
            print(f"Error during scan: {e}")
        finally:
            pythoncom.CoUninitialize()  # Ensure COM is uninitialized in the thread
        return devices

    def get_ip_range(self):
        gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        return gateway.rsplit('.', 1)[0] + ".0/24"

    def get_device_type(self, mac):
        try:
            wmi_service = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            wmi_connection = wmi_service.ConnectServer(".", "root\\CIMV2")

            query = "SELECT Name, MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL"
            adapters = wmi_connection.ExecQuery(query)

            for adapter in adapters:
                if adapter.MACAddress and adapter.MACAddress.lower() == mac.lower():
                    return adapter.Name or "Unknown"
        except Exception as e:
            print(f"Pywin32 Error in get_device_type: {e}")
        return "Unknown"

    def is_dhcp_enabled(self, ip):
        try:
            wmi_service = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            wmi_connection = wmi_service.ConnectServer(".", "root\\CIMV2")

            query = "SELECT IPAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
            configs = wmi_connection.ExecQuery(query)

            for config in configs:
                if config.IPAddress and ip in config.IPAddress:
                    return "Enabled" if config.DHCPEnabled else "Disabled"
        except Exception as e:
            print(f"Pywin32 Error in is_dhcp_enabled: {e}")
        return "Unknown"



class BandwidthMonitor:
    def __init__(self):
        self.previous_stats = psutil.net_io_counters(pernic=True)

    def get_bandwidth_usage(self, ip):
        current_stats = psutil.net_io_counters(pernic=True)
        usage = {
            "download": 0,
            "upload": 0
        }
        try:
            for nic, stats in current_stats.items():
                if nic in self.previous_stats:
                    prev_stats = self.previous_stats[nic]
                    usage = {
                        "download": stats.bytes_recv - prev_stats.bytes_recv,
                        "upload": stats.bytes_sent - prev_stats.bytes_sent
                    }
            self.previous_stats = current_stats
        except Exception as e:
            print(f"Error fetching bandwidth usage: {e}")
        return f"{usage['download']} B / {usage['upload']} B"


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

        tk.Button(control_frame, text="Detect Interface", command=self.detect_interface).pack(side=tk.LEFT, padx=5)
        tk.Label(control_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_label = tk.Label(control_frame, textvariable=self.interface)
        self.interface_label.pack(side=tk.LEFT, padx=5)

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

    def detect_interface(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            interface_guid = default_gateway[1] if default_gateway else None

            print(f"Default Gateway: {default_gateway}")
            print(f"Detected Interface GUID: {interface_guid}")

            wmi_obj = wmi.WMI()
            friendly_name = None
            for nic in wmi_obj.Win32_NetworkAdapter():
                if nic.GUID == interface_guid:
                    friendly_name = nic.NetConnectionID
                    break

            if friendly_name and friendly_name in psutil.net_if_addrs():
                self.interface.set(friendly_name)
                self.status_label.config(text=f"Detected Interface: {friendly_name}")
            else:
                messagebox.showwarning("Warning", "Default interface not found in active interfaces.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to detect interface: {str(e)}")

    def update_table(self, devices):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for device in devices:
            bandwidth = self.bandwidth_monitor.get_bandwidth_usage(device.get("ip", "Unknown"))
            self.tree.insert("", tk.END, values=(
                device.get("ip", "Unknown"),
                device.get("mac", "Unknown"),
                device.get("device_type", "Unknown"),
                device.get("dhcp", "Unknown"),
                bandwidth
            ))

    def start_scan(self):
        interface = self.interface.get()
        if not interface:
            messagebox.showwarning("Input Error", "Please detect or enter a network interface.")
            return

        self.status_label.config(text="Status: Scanning...")
        self.scanner = NetworkScanner(interface)

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
