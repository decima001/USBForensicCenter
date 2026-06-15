import os
import re
import hashlib
import subprocess
import magic  # <--- NEW: High-performance file signature identification library
from celery import shared_task
from django.utils import timezone
from forensics.models import TargetDevice, ForensicArtifact

# PRESERVED: Your exact core credential scraping regex signatures
SECRET_PATTERNS = {
    "Plaintext Password": re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*()_+]{4,20})["\']?', re.IGNORECASE),
    "Generic API Key": re.compile(r'(?:api_key|apikey|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9\-_\+]{16,40})["\']?', re.IGNORECASE)
}

def calculate_sha256(file_path):
    """
    NEW FEATURE: Cryptographic Data Integrity Guardrail.
    Generates a unique SHA-256 hash string for tracked assets.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


@shared_task
def execute_usb_filesystem_scan(device_id):
    """
    Upgraded Forensic Task for USB Storage Media.
    Blends former recursive crawling and credential harvesting with 
    live SHA-256 cryptographic tracking and MIME-type mismatch discovery.
    """
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

    # Deep recursive directory tree traversal traversal
    for root, dirs, files in os.walk(target_root):
        
        # PRESERVED: Windows OS Permission Guardrails
        if "System Volume Information" in root:
            continue
        if "$RECYCLE.BIN" in root and any(sid in os.path.basename(root) for sid in ["S-1-5-", "S-1-12-"]):
            continue

        for file in files:
            file_path = os.path.join(root, file)
            extension = os.path.splitext(file)[1].lower() # e.g., '.txt' or '.jpg'
            
            # File size sanity limit to prevent system crashes on huge files
            try:
                if os.path.getsize(file_path) > 15 * 1024 * 1024: 
                    continue
            except (PermissionError, FileNotFoundError): 
                continue

            # ====================================================
            #  🆕 FEATURE ADDITION: MIME-TYPE EVASION DETECTOR
            # ====================================================
            file_mime = "Unknown"
            evasion_alert = False
            
            try:
                # Use magic to peek at the raw binary headers (magic bytes)
                file_mime = magic.from_file(file_path, mime=True)
                
                # Check 1: Is an executable binary pretending to be a harmless text file or image?
                if "application/x-dosexec" in file_mime and extension in ['.txt', '.log', '.cfg', '.ini', '.env', '.json', '.pdf', '.jpg']:
                    evasion_alert = True
                
                # Check 2: Is a Python script masked under a non-standard extension?
                elif "text/x-python" in file_mime and extension not in ['.py', '.pyw']:
                    evasion_alert = True
            except Exception:
                pass

            # Calculate hash identifier for the artifact data ledger
            file_hash = calculate_sha256(file_path)

            if evasion_alert:
                ForensicArtifact.objects.create(
                    device=device,
                    category="Anti-Forensics Evasion",
                    title=f"MIME-Type Masquerade Flagged in '{file}'",
                    severity="CRITICAL",
                    extracted_data=f"File: {file_path} | Extension claimed: {extension} | True File Signature: {file_mime}",
                    sha256_hash=file_hash,
                    true_mime_type=file_mime,
                    is_spoofed=True
                )

            # ====================================================
            #  🔒 PRESERVED: ORIGINAL CREDENTIAL HARVESTING ENGINE
            # ====================================================
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
                                    extracted_data=f"File: {file_path} | Leaked Snippet: {matches[0]}",
                                    sha256_hash=file_hash, true_mime_type=file_mime
                                )
                except (PermissionError, FileNotFoundError): 
                    pass

            # ====================================================
            #  🛡️ PRESERVED: ORIGINAL EXECUTABLE RISK TRIAGE
            # ====================================================
            if file.endswith(('.exe', '.bat', '.ps1', '.vbs', '.scr')) and not evasion_alert:
                ForensicArtifact.objects.get_or_create(
                    device=device, category="Executable Artifact",
                    title=f"Potential Hostile Executable: {file}", severity="HIGH",
                    extracted_data=f"Path: {file_path}",
                    sha256_hash=file_hash, true_mime_type=file_mime
                )

    device.status = 'COMPLETED'
    device.last_scanned_at = timezone.now()
    device.save()
    return f"Forensic signature tracking routine complete for {device_id}."


# ====================================================
# 📱 PRESERVED: ORIGINAL ANDROID ADB INTERFACE
# ====================================================
@shared_task
def execute_android_vulnerability_scan(device_id):
    """
    Active Mobile Telemetry Ingestion via local ADB interfacing.
    完全保持 unchanged to safeguard your mobile forensics pipeline.
    """
    try:
        device = TargetDevice.objects.get(device_id=device_id)
    except TargetDevice.DoesNotExist:
        return "Error: Android device missing from local database index."

    device.status = 'SCANNING'
    device.save()

    try:
        prop_output = subprocess.check_output(["adb", "shell", "getprop", "ro.build.version.release"], text=True, stderr=subprocess.STDOUT).strip()
        model_output = subprocess.check_output(["adb", "shell", "getprop", "ro.product.model"], text=True, stderr=subprocess.STDOUT).strip()
        
        ForensicArtifact.objects.create(
            device=device, category="Mobile Profiling",
            title=f"Device Blueprint Established: {model_output}", severity="LOW",
            extracted_data=f"OS Version: Android {prop_output} | Hardware Target Verified."
        )

        package_output = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"], text=True, stderr=subprocess.STDOUT)
        packages = package_output.strip().split('\n')
        
        ForensicArtifact.objects.create(
            device=device, category="Software Inventory",
            title=f"Discovered {len(packages)} Custom Applications Installed", severity="LOW",
            extracted_data=f"Third-Party Software Inventory: {', '.join(packages[:5])}..."
        )

    except Exception as e:
        ForensicArtifact.objects.create(
            device=device, category="Interface Warning",
            title="ADB Communication Blocked or Unauthorized", severity="HIGH",
            extracted_data=f"Details: Ensure USB Debugging is turned on. Error: {str(e)}"
        )

    device.status = 'COMPLETED'
    device.last_scanned_at = timezone.now()
    device.save()
    return f"Android profiling complete for {device_id}."