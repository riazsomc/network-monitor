import pythoncom
import win32com.client

def test_wmi():
    pythoncom.CoInitialize()  # Initialize COM
    wmi_service = None
    wmi_connection = None
    try:
        wmi_service = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        wmi_connection = wmi_service.ConnectServer(".", "root\\CIMV2")

        print("Testing NetworkAdapter query:")
        adapters = wmi_connection.ExecQuery("SELECT Name, MACAddress FROM Win32_NetworkAdapter")
        for adapter in adapters:
            print(f"Name: {adapter.Name}, MAC: {adapter.MACAddress}")

        print("\nTesting NetworkAdapterConfiguration query:")
        configs = wmi_connection.ExecQuery("SELECT IPAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE")
        for config in configs:
            print(f"IPs: {config.IPAddress}, DHCP: {config.DHCPEnabled}")

    except Exception as e:
        print(f"WMI Test Failed: {e}")

    finally:
        # Explicitly release references
        del wmi_service
        del wmi_connection
        pythoncom.CoUninitialize()  # Uninitialize COM

test_wmi()
