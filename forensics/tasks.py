import os
import re
import hashlib
import subprocess
import magic
import logging
from celery import shared_task
from django.utils import timezone
from django.template.loader import render_to_string
from django.conf import settings
from forensics.models import TargetDevice, ForensicArtifact

# Setup logging to see progress in your worker terminal
logger = logging.getLogger(__name__)

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
        return None

def generate_auto_report(device):
    report_dir = os.path.join(settings.BASE_DIR, 'reports')
    if not os.path.exists(report_dir): os.makedirs(report_dir)
    report_path = os.path.join(report_dir, f"Report_{device.device_id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.html")
    context = {'device': device, 'artifacts': device.artifacts.all().order_by('-severity')}
    html_content = render_to_string('forensics/report_export.html', context)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

@shared_task
def execute_usb_filesystem_scan(device_id):
    try:
        device = TargetDevice.objects.get(device_id=device_id)
        target_root = os.path.normpath(device.mount_point)
        
        if not os.path.exists(target_root):
            logger.error(f"Path inaccessible: {target_root}")
            return "Path inaccessible."

        device.status = 'SCANNING'; device.save()
        logger.info(f"Scan started for {device_id} at {target_root}")

        for root, dirs, files in os.walk(target_root):
            # Skip hidden/system directories
            if any(part.startswith(('.', '$', 'System Volume')) for part in root.split(os.sep)):
                continue

            for file in files:
                file_path = os.path.join(root, file)
                extension = os.path.splitext(file)[1].lower()
                
                try:
                    if os.path.getsize(file_path) > 15 * 1024 * 1024: continue
                except: continue

                file_mime, evasion_alert = "Unknown", False
                try:
                    file_mime = magic.from_file(file_path, mime=True)
                    if "application/x-dosexec" in file_mime and extension in ['.txt', '.log', '.cfg', '.ini', '.env', '.json', '.pdf', '.jpg']:
                        evasion_alert = True
                except: pass

                file_hash = calculate_sha256(file_path)

                if evasion_alert:
                    ForensicArtifact.objects.create(device=device, category="Anti-Forensics Evasion", title=f"MIME Masquerade: {file}", severity="CRITICAL", extracted_data=f"Path: {file_path}", sha256_hash=file_hash, true_mime_type=file_mime, is_spoofed=True)

                if file.endswith(('.txt', '.log', '.cfg', '.ini', '.env', '.json')):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern_name, regex in SECRET_PATTERNS.items():
                                matches = regex.findall(content)
                                if matches:
                                    ForensicArtifact.objects.get_or_create(device=device, category="Credential Leak", title=f"{pattern_name} in '{file}'", severity="CRITICAL", extracted_data=f"Snippet: {matches[0]}", sha256_hash=file_hash, true_mime_type=file_mime)
                    except: pass

        device.status = 'COMPLETED'; device.last_scanned_at = timezone.now(); device.save()
        generate_auto_report(device)
        logger.info(f"Scan finished successfully for {device_id}")
        return "Scan complete."
    except Exception as e:
        logger.error(f"Task failed: {str(e)}")
        raise e

@shared_task
def execute_android_vulnerability_scan(device_id):
    # ... (Keep your existing Android logic here)
    pass