import os
import re
import hashlib
import subprocess
import magic  # High-performance file signature identification
from celery import shared_task
from django.utils import timezone
from django.template.loader import render_to_string
from django.conf import settings
from forensics.models import TargetDevice, ForensicArtifact

# --- CORE CREDENTIAL SCRAPING SIGNATURES ---
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
    """Generates a static HTML report automatically upon scan completion."""
    report_dir = os.path.join(settings.BASE_DIR, 'reports')
    if not os.path.exists(report_dir): os.makedirs(report_dir)
    
    report_path = os.path.join(report_dir, f"Report_{device.device_id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.html")
    context = {'device': device, 'artifacts': device.artifacts.all().order_by('-severity')}
    
    html_content = render_to_string('forensics/report_export.html', context)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

# --- USB FORENSIC PIPELINE ---
@shared_task
def execute_usb_filesystem_scan(device_id):
    try:
        device = TargetDevice.objects.get(device_id=device_id)
    except TargetDevice.DoesNotExist:
        return f"Error: Target device {device_id} missing."

    target_root = device.mount_point
    if not os.path.exists(target_root):
        device.status = 'FAILED'; device.save(); return "Path inaccessible."

    device.status = 'SCANNING'; device.save()

    for root, dirs, files in os.walk(target_root):
        if "System Volume Information" in root or "$RECYCLE.BIN" in root: continue

        for file in files:
            file_path = os.path.join(root, file)
            extension = os.path.splitext(file)[1].lower()
            
            try:
                if os.path.getsize(file_path) > 15 * 1024 * 1024: continue
            except: continue

            # MIME Evasion Check
            file_mime, evasion_alert = "Unknown", False
            try:
                file_mime = magic.from_file(file_path, mime=True)
                if "application/x-dosexec" in file_mime and extension in ['.txt', '.log', '.cfg', '.ini', '.env', '.json', '.pdf', '.jpg']:
                    evasion_alert = True
                elif "text/x-python" in file_mime and extension not in ['.py', '.pyw']:
                    evasion_alert = True
            except: pass

            file_hash = calculate_sha256(file_path)

            if evasion_alert:
                ForensicArtifact.objects.create(device=device, category="Anti-Forensics Evasion", title=f"MIME Masquerade: {file}", severity="CRITICAL", extracted_data=f"Path: {file_path} | Signature: {file_mime}", sha256_hash=file_hash, true_mime_type=file_mime, is_spoofed=True)

            # Credential Harvest
            if file.endswith(('.txt', '.log', '.cfg', '.ini', '.env', '.json')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_name, regex in SECRET_PATTERNS.items():
                            matches = regex.findall(content)
                            if matches:
                                ForensicArtifact.objects.get_or_create(device=device, category="Credential Leak", title=f"{pattern_name} in '{file}'", severity="CRITICAL", extracted_data=f"Path: {file_path} | Snippet: {matches[0]}", sha256_hash=file_hash, true_mime_type=file_mime)
                except: pass

            # Executable Risk
            if file.endswith(('.exe', '.bat', '.ps1', '.vbs', '.scr')) and not evasion_alert:
                ForensicArtifact.objects.get_or_create(device=device, category="Executable Artifact", title=f"Executable: {file}", severity="HIGH", extracted_data=f"Path: {file_path}", sha256_hash=file_hash, true_mime_type=file_mime)

    device.status = 'COMPLETED'; device.last_scanned_at = timezone.now(); device.save()
    generate_auto_report(device) # Automated trigger
    return f"Scan complete for {device_id}."

# --- ANDROID TELEMETRY PIPELINE ---
@shared_task
def execute_android_vulnerability_scan(device_id):
    device = TargetDevice.objects.get(device_id=device_id)
    device.status = 'SCANNING'; device.save()
    try:
        prop = subprocess.check_output(["adb", "shell", "getprop", "ro.build.version.release"], text=True).strip()
        model = subprocess.check_output(["adb", "shell", "getprop", "ro.product.model"], text=True).strip()
        ForensicArtifact.objects.create(device=device, category="Mobile Profiling", title=f"Blueprint: {model}", severity="LOW", extracted_data=f"Android {prop}")
        
        packages = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"], text=True).strip().split('\n')
        ForensicArtifact.objects.create(device=device, category="Software Inventory", title=f"{len(packages)} Apps Installed", severity="LOW", extracted_data=f"Samples: {', '.join(packages[:5])}")
    except Exception as e:
        ForensicArtifact.objects.create(device=device, category="Interface Warning", title="ADB Error", severity="HIGH", extracted_data=str(e))
    
    device.status = 'COMPLETED'; device.last_scanned_at = timezone.now(); device.save()
    generate_auto_report(device) # Automated trigger
    return f"Android audit complete for {device_id}."