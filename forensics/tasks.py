import os
import re
import hashlib
import subprocess
from celery import shared_task
from django.utils import timezone
from forensics.models import TargetDevice, ForensicArtifact

SECRET_PATTERNS = {
    "Plaintext Password": re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*()_+]{4,20})["\']?', re.IGNORECASE),
    "Generic API Key": re.compile(r'(?:api_key|apikey|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9\-_\+]{16,40})["\']?', re.IGNORECASE)
}

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "N/A (Access Locked)"

@shared_task
def execute_usb_filesystem_scan(device_id):
    """
    Weaponized Forensic Task for USB Storage Media.
    """
    print(f"[+] Launching live hardware analysis sequence for target: {device_id}")
    try:
        device = TargetDevice.objects.get(device_id=device_id)
    except TargetDevice.DoesNotExist:
        return f"Error: Target device {device_id} missing."

    target_root = device.mount_point
    if not os.path.exists(target_root):
        device.status = 'FAILED'
        device.save()
        return f"Execution Failure: Mount path {target_root} is inaccessible."

    device.status = 'SCANNING'
    device.save()
    discovered_logs_count = 0

    for root, dirs, files in os.walk(target_root):
        if "$RECYCLE.BIN" in root or "System Volume Information" in root:
            ForensicArtifact.objects.get_or_create(
                device=device, category="System Volume",
                title=f"Protected Directory Monitored: {os.path.basename(root)}", severity="HIGH",
                extracted_data=f"Absolute System Path: {root}"
            )
            discovered_logs_count += 1

        for file in files:
            file_path = os.path.join(root, file)
            try:
                if os.path.getsize(file_path) > 10 * 1024 * 1024: continue
            except Exception: continue

            if "$RECYCLE.BIN" in root and file.startswith("$R") and file.endswith(('.txt', '.log', '.env', '.json', '.bak')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as deleted_file:
                        deleted_content = deleted_file.read().strip()
                        if deleted_content:
                            ForensicArtifact.objects.get_or_create(
                                device=device, category="Recycle Bin Carving",
                                title=f"Carved Content from Deleted File: {file}", severity="HIGH",
                                extracted_data=f"File: {file_path} | Deleted Snippet: {deleted_content[:120]} | SHA256: {calculate_sha256(file_path)}"
                            )
                            discovered_logs_count += 1
                except Exception: pass

            if file.endswith(('.txt', '.log', '.cfg', '.ini', '.env', '.json')) and "$RECYCLE.BIN" not in root:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_name, regex in SECRET_PATTERNS.items():
                            matches = regex.findall(content)
                            if matches:
                                ForensicArtifact.objects.get_or_create(
                                    device=device, category="Credential Leak",
                                    title=f"{pattern_name} Exposed in '{file}'", severity="CRITICAL",
                                    extracted_data=f"File: {file_path} | Leaked Snippet: {matches[0]} | SHA256: {calculate_sha256(file_path)}"
                                )
                                discovered_logs_count += 1
                except Exception: pass

            if file.endswith(('.exe', '.bat', '.ps1', '.vbs', '.scr')):
                ForensicArtifact.objects.get_or_create(
                    device=device, category="Executable Artifact",
                    title=f"Potential Hostile Executable: {file}", severity="HIGH",
                    extracted_data=f"Path: {file_path} | Forensics Hash Summary: {calculate_sha256(file_path)}"
                )
                discovered_logs_count += 1

    device.status = 'COMPLETED'
    device.last_scanned_at = timezone.now()
    device.save()
    return f"USB Scan complete for device {device_id}. Found {discovered_logs_count} flags."


@shared_task
def execute_android_vulnerability_scan(device_id):
    """
    NEW: Active Mobile Telemetry Ingestion via local ADB interfacing.
    Pulls running environment properties and connected parameters automatically.
    """
    try:
        device = TargetDevice.objects.get(device_id=device_id)
    except TargetDevice.DoesNotExist:
        return "Error: Android device missing from local database index."

    device.status = 'SCANNING'
    device.save()

    # Formulate base diagnostic command structure (queries basic system properties)
    # Assumes 'adb' tool is pre-installed via toolkit environment paths
    try:
        # 1. Fetch system properties
        prop_output = subprocess.check_output(["adb", "shell", "getprop", "ro.build.version.release"], text=True, stderr=subprocess.STDOUT).strip()
        model_output = subprocess.check_output(["adb", "shell", "getprop", "ro.product.model"], text=True, stderr=subprocess.STDOUT).strip()
        
        ForensicArtifact.objects.create(
            device=device,
            category="Mobile Profiling",
            title=f"Device Blueprint Established: {model_output}",
            severity="LOW",
            extracted_data=f"OS Version: Android {prop_output} | Hardware Target Verified."
        )

        # 2. Fetch active connected packages to screen for risk metrics
        package_output = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"], text=True, stderr=subprocess.STDOUT)
        packages = package_output.strip().split('\n')
        
        ForensicArtifact.objects.create(
            device=device,
            category="Software Inventory",
            title=f"Discovered {len(packages)} Custom Applications Installed",
            severity="LOW",
            extracted_data=f"Third-Party Software Inventory: {', '.join(packages[:5])}..."
        )

    except Exception as e:
        # Fallback handle if device is locked or authorization prompt is pending confirmation
        ForensicArtifact.objects.create(
            device=device,
            category="Interface Warning",
            title="ADB Communication Blocked or Unauthorized",
            severity="HIGH",
            extracted_data=f"Details: Ensure USB Debugging is turned on and RSA pairing key is confirmed on-screen. Error context: {str(e)}"
        )

    device.status = 'COMPLETED'
    device.last_scanned_at = timezone.now()
    device.save()
    return f"Android profiling complete for {device_id}."