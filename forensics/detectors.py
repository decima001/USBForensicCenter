import os
import string
from forensics.models import TargetDevice

def monitor_and_update_devices():
    """
    Synchronizes the SQLite database registry with physical hardware ports.
    Purges stale/disconnected volumes and registers newly mounted external media.
    """
    print("[+] Executing live hardware peripheral discovery sequence...")
    
    # 1. SCAN PHASE: Map all active logical drive roots (skipping primary OS C:\ drive)
    active_system_mounts = [f"{letter}:\\" for letter in string.ascii_uppercase if letter != 'C']
    currently_attached_mounts = []

    for mount_point in active_system_mounts:
        if os.path.exists(mount_point):
            currently_attached_mounts.append(mount_point)
            
            # Generate consistent forensic hardware hardware signature ID mapping
            generated_uuid = f"USB-DRIVE-{mount_point.replace(':', '').replace('\\', '')}-524009472"
            
            # Register or update the target state
            device, created = TargetDevice.objects.get_or_create(
                device_id=generated_uuid,
                defaults={
                    'mount_point': mount_point,
                    'device_type': 'USB',
                    'status': 'IDLE'
                }
            )
            
            if created:
                print(f"[+] Active hardware mapping registered at node: {mount_point}")
            elif device.status == 'FAILED':
                device.status = 'IDLE'
                device.save()

    # 2. PURGE PHASE: Audit your database and clear out disconnected entries
    all_registered_devices = TargetDevice.objects.filter(device_type='USB')
    
    for device in all_registered_devices:
        if device.mount_point not in currently_attached_mounts:
            print(f"[-] Hardware disconnect verified for volume {device.mount_point}. Dropping from workspace registry.")
            device.delete()

    print("[+] Hardware synchronization matrix complete.")