import os
import psutil
from ppadb.client import Client as AdbClient
from forensics.models import TargetDevice

def get_android_devices():
    """Scans for connected Android devices via ADB server."""
    discovered = []
    try:
        # Connect to the local ADB server running on default port 5037
        client = AdbClient(host="127.0.0.1", port=5037)
        devices = client.devices()
        
        for device in devices:
            serial = device.serial
            # Fetch basic device details via shell command
            brand = device.shell("getprop ro.product.brand").strip()
            model = device.shell("getprop ro.product.model").strip()
            label = f"{brand} {model}".strip() or "Unknown Android Device"
            
            discovered.append({
                'device_id': serial,
                'device_type': 'ANDROID',
                'label': label,
                'mount_point': serial  # In ADB, the serial acts as the address identifier
            })
    except Exception:
        # If ADB server isn't running or accessible, fail gracefully
        pass
    return discovered


def get_usb_storage_devices():
    """Scans for connected external hard drives or USB sticks on Windows."""
    discovered = []
    # psutil.disk_partitions(all=True) fetches all logical drives currently mounted
    partitions = psutil.disk_partitions(all=True)
    
    for partition in partitions:
        # Filter for external/removable storage devices
        if 'removable' in partition.opts or 'cdrom' in partition.opts:
            continue
        
        try:
            # Check drive usage metadata to confirm active mounting status
            usage = psutil.disk_usage(partition.mountpoint)
            
            # Formulate a unique identifier based on the mountpoint and total size
            drive_uuid = f"USB-DRIVE-{partition.mountpoint.replace(':', '').replace('\\', '')}-{usage.total}"
            
            discovered.append({
                'device_id': drive_uuid,
                'device_type': 'USB',
                'label': f"External Drive ({partition.mountpoint})",
                'mount_point': partition.mountpoint
            })
        except PermissionError:
            # Skip system partitions that the tool doesn't have privileges to read
            continue
        except Exception:
            continue
            
    return discovered


def monitor_and_update_devices():
    """Main execution block to update the Django database with active hardware states."""
    active_ids = []
    
    # Run active discovery routines
    all_detected = get_usb_storage_devices() + get_android_devices()
    
    for item in all_detected:
        active_ids.append(item['device_id'])
        
        # Atomically create or fetch the device state model within Django
        device, created = TargetDevice.objects.get_or_create(
            device_id=item['device_id'],
            defaults={
                'device_type': item['device_type'],
                'label': item['label'],
                'mount_point': item['mount_point'],
                'status': 'DETECTED'
            }
        )
        
        # If an existing device was reconnected, restore its active status
        if not created and device.status == 'FAILED':
            device.status = 'DETECTED'
            device.mount_point = item['mount_point']
            device.save()
            
    return f"Active hardware scan complete. Tracked {len(active_ids)} connected device(s)."