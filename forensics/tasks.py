import os
import json
from datetime import datetime
from celery import shared_task
from ppadb.client import Client as AdbClient
import pytsk3

from forensics.models import TargetDevice, ForensicArtifact

@shared_task
def execute_usb_filesystem_scan(device_id):
    """
    Performs low-level file table analysis on external drives via pytsk3,
    targeting browser data caches and deleted configurations.
    """
    try:
        device = TargetDevice.objects.get(device_id=device_id)
        device.status = 'SCANNING'
        device.save()

        mount_point = device.mount_point  # e.g., "E:\\"
        
        # On Windows, raw logical volume access requires the \\.\ Physical/Logical Drive nomenclature
        # The script must run with Administrator privileges to access this layer natively
        volume_path = f"\\\\.\\{mount_point.strip('\\')}"
        
        try:
            # Open physical disk volume image interface
            img_info = pytsk3.Img_Info(volume_path)
            fs_info = pytsk3.FS_Info(img_info)
            
            # Root directory parsing entry pointer
            root_dir = fs_info.open_dir(path="/")
            
            # Low-level iteration through filesystem metadata entries
            for fs_file in root_dir:
                if not fs_file.info.meta:
                    continue
                
                filename = fs_file.info.name.name.decode('utf-8', errors='ignore')
                
                # Target common artifacts like browser history or configuration files
                if "history" in filename.lower() or "login data" in filename.lower():
                    ForensicArtifact.objects.create(
                        device=device,
                        title=f"Discovered Browser Data Store: {filename}",
                        category="Browser Cache",
                        severity="MEDIUM",
                        extracted_data={
                            "inode": fs_file.info.meta.addr,
                            "file_size_bytes": fs_file.info.meta.size,
                            "allocated": fs_file.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC
                        }
                    )
        except Exception as e:
            # Fallback to standard Python OS-level scraping if raw block access is locked by system
            for root, dirs, files in os.walk(mount_point):
                for file in files:
                    if any(target in file.lower() for target in ['history', 'login', 'config', 'cache']):
                        full_path = os.path.join(root, file)
                        ForensicArtifact.objects.create(
                            device=device,
                            title=f"Discovered Sensitive File Storage: {file}",
                            category="Application File System",
                            severity="LOW",
                            extracted_data={"file_path": full_path, "status": "Accessed via OS fallback"}
                        )

        device.status = 'COMPLETED'
        device.last_scanned_at = datetime.now()
        device.save()
        return f"USB Scan complete for device {device_id}"

    except Exception as e:
        if 'device' in locals():
            device.status = 'FAILED'
            device.save()
        return f"USB Scan Failed: {str(e)}"


@shared_task
def execute_android_vulnerability_scan(device_id):
    """
    Connects to target device via ADB to extract running security configurations,
    installed packages, and evaluate exploit indicators.
    """
    try:
        device = TargetDevice.objects.get(device_id=device_id)
        device.status = 'SCANNING'
        device.save()

        # Connect to ADB daemon engine
        client = AdbClient(host="127.0.0.1", port=5037)
        adb_device = client.device(device_id)

        if not adb_device:
            raise Exception("Target Android device not found on ADB server network.")

        # Task 1: Audit Security Patch & OS configuration versioning
        build_version = adb_device.shell("getprop ro.build.version.release").strip()
        security_patch = adb_device.shell("getprop ro.build.version.security_patch").strip()
        
        ForensicArtifact.objects.create(
            device=device,
            title="Android OS Baseline Verification",
            category="System Configuration",
            severity="INFO",
            extracted_data={
                "android_version": build_version,
                "security_patch_level": security_patch
            }
        )

        # Task 2: Audit Third-Party Packages for Dangerous Permissions
        # Pull packages installed via non-system registries
        packages_raw = adb_device.shell("pm list packages -3").strip().split('\n')
        
        for pkg in packages_raw:
            if not pkg: continue
            pkg_name = pkg.replace("package:", "").strip()
            
            # Query active permission bounds assigned to package structure
            dump_data = adb_device.shell(f"dumpsys package {pkg_name}")
            
            # Heuristic detection for dangerous patterns (e.g., READ_SMS or RECORD_AUDIO)
            has_sms = "READ_SMS" in dump_data
            has_storage = "READ_EXTERNAL_STORAGE" in dump_data

            if has_sms or has_storage:
                ForensicArtifact.objects.create(
                    device=device,
                    title=f"High Risk Application Permissions: {pkg_name}",
                    category="Application Access Permissions",
                    severity="HIGH",
                    extracted_data={
                        "package_identifier": pkg_name,
                        "sms_access_requested": has_sms,
                        "storage_access_requested": has_storage,
                        "context": "Third party application with wide-scale logging capacity"
                    }
                )

        device.status = 'COMPLETED'
        device.last_scanned_at = datetime.now()
        device.save()
        return f"Android Security Audit complete for {device_id}"

    except Exception as e:
        if 'device' in locals():
            device.status = 'FAILED'
            device.save()
        return f"Android Scan Failed: {str(e)}"