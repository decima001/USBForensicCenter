import winreg
from datetime import datetime, timedelta

def convert_registry_timestamp(low_time, high_time):
    """Converts a Windows 64-bit FILETIME timestamp structure to a human-readable string."""
    try:
        filetime = (high_time << 32) + low_time
        # Windows FILETIME starts from Jan 1, 1601. Convert to Unix epoch.
        microseconds = filetime / 10
        seconds = microseconds / 1000000
        converted_date = datetime(1601, 1, 1) + timedelta(seconds=seconds)
        return converted_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return "Unknown"

def extract_system_usb_history():
    """
    Scrapes host registry hives to build a defensive historical roadmap
    of all external mass storage media endpoints.
    """
    usb_devices = []
    usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    try:
        # Open raw handle to the hardware tracking hive
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path) as root_key:
            subkeys_count, _, _ = winreg.QueryInfoKey(root_key)
            
            # Enumerate through Device Class Names (e.g., Disk&Ven_SanDisk&Prod_Cruzer)
            for i in range(subkeys_count):
                device_class = winreg.EnumKey(root_key, i)
                device_path = f"{usbstor_path}\\{device_class}"
                
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path) as device_key:
                    instance_count, _, _ = winreg.QueryInfoKey(device_key)
                    
                    # Enumerate unique hardware serial instances inside that device class
                    for j in range(instance_count):
                        serial_number = winreg.EnumKey(device_key, j)
                        
                        # Clean up product/vendor strings from the device class
                        parsed_meta = device_class.split('&')
                        vendor = next((x.split('_')[1] for x in parsed_meta if 'Ven_' in x), "Unknown")
                        product = next((x.split('_')[1] for x in parsed_meta if 'Prod_' in x), "Generic Media")
                        
                        usb_devices.append({
                            "vendor": vendor,
                            "product": product,
                            "serial": serial_number,
                            "class_id": device_class
                        })
        return usb_devices
    except PermissionError:
        return {"error": "Access Denied: Administrative privileges required to read hardware hives."}
    except Exception as e:
        return {"error": f"Registry read aborted: {str(e)}"}