import winreg

def extract_system_usb_history():
    usb_devices = []
    usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path) as root_key:
            for i in range(winreg.QueryInfoKey(root_key)[0]):
                device_class = winreg.EnumKey(root_key, i)
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{usbstor_path}\\{device_class}") as device_key:
                    for j in range(winreg.QueryInfoKey(device_key)[0]):
                        serial = winreg.EnumKey(device_key, j)
                        usb_devices.append({"vendor": device_class.split('&')[1].split('_')[1], 
                                            "product": device_class.split('&')[2].split('_')[1], 
                                            "serial": serial})
        return usb_devices
    except Exception as e:
        return {"error": "Registry access denied."}