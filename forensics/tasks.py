import os
import re
import hashlib
from celery import shared_task
from django.utils import timezone
from forensics.models import TargetDevice, ForensicArtifact

# High-efficiency regex matchers for common credentials and leaks
SECRET_PATTERNS = {
    "Plaintext Password": re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*()_+]{4,20})["\']?', re.IGNORECASE),
    "Generic API Key": re.compile(r'(?:api_key|apikey|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9\-_\+]{16,40})["\']?', re.IGNORECASE)
}

def calculate_sha256(file_path):
    """Generates a verifiable forensic cryptographic checksum for an ingested file."""
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
    Weaponized Forensic Task.
    Physically maps the mounted directory structure, calculates hashes, flags hidden components,
    and inspects plaintext text files for sensitive leaked credentials.
    """
    print(f"[+] Launching live hardware analysis sequence for target: {device_id}")
    
    try:
        device = TargetDevice.objects.get(device_id=device_id)
    except TargetDevice.DoesNotExist:
        return f"Error: Target device {device_id} missing from local registry."

    # Identify the target execution vector (e.g., "E:\\")
    target_root = device.mount_point
    if not os.path.exists(target_root):
        device.status = 'FAILED'
        device.save()
        return f"Execution Failure: Mount path {target_root} is inaccessible or unplugged."

    # Transition to active processing state
    device.status = 'SCANNING'
    device.save()

    discovered_logs_count = 0

    # Crawl the target drive file structure recursively
    for root, dirs, files in os.walk(target_root):
        # 1. Identify and flag dangerous/hidden operating system junctions
        if "$RECYCLE.BIN" in root or "System Volume Information" in root:
            ForensicArtifact.objects.get_or_create(
                device=device,
                category="System Volume",
                title=f"Protected Directory Monitored: {os.path.basename(root)}",
                severity="HIGH",
                extracted_data=f"Absolute System Path: {root} | Analysis: Common staging area for persistent payloads."
            )
            discovered_logs_count += 1

        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip massive locked operating system system files to save computational overhead
            if os.path.getsize(file_path) > 10 * 1024 * 1024: # 10MB limit
                continue

            # 2. File Analysis Check: Hunt for text files to inspect for data leaks
            if file.endswith(('.txt', '.log', '.cfg', '.ini', '.env', '.json')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Run pattern scanners against raw string blocks
                        for pattern_name, regex in SECRET_PATTERNS.items():
                            matches = regex.findall(content)
                            if matches:
                                ForensicArtifact.objects.get_or_create(
                                    device=device,
                                    category="Credential Leak",
                                    title=f"{pattern_name} Exposed in '{file}'",
                                    severity="CRITICAL",
                                    extracted_data=f"File: {file_path} | Leaked Snippet: {matches[0]} | SHA256: {calculate_sha256(file_path)}"
                                )
                                discovered_logs_count += 1
                except Exception as e:
                    print(f"[-] Access error while reading {file_path}: {e}")

            # 3. Extension Spoofing / Risk Triage: Flag dangerous payloads
            if file.endswith(('.exe', '.bat', '.ps1', '.vbs', '.scr')):
                ForensicArtifact.objects.get_or_create(
                    device=device,
                    category="Executable Artifact",
                    title=f"Potential Hostile Executable: {file}",
                    severity="HIGH",
                    extracted_data=f"Path: {file_path} | Forensics Hash Summary: {calculate_sha256(file_path)}"
                )
                discovered_logs_count += 1

    # Finalize state metrics
    device.status = 'COMPLETED'
    device.last_scanned_at = timezone.now()
    device.save()

    print(f"[+] Production scan complete. Registered {discovered_logs_count} live indicators.")
    return f"USB Scan complete for device {device_id}. Found {discovered_logs_count} flags."


@shared_task
def execute_android_vulnerability_scan(device_id):
    """
    Placeholder for your upcoming mobile/ADB collection scripts.
    """
    try:
        device = TargetDevice.objects.get(device_id=device_id)
        device.status = 'COMPLETED'
        device.last_scanned_at = timezone.now()
        device.save()
    except TargetDevice.DoesNotExist:
        pass
    return f"Android target complete: {device_id}"