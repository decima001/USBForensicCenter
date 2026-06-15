import os, re
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponse, JsonResponse
from .models import TargetDevice, ForensicArtifact
from .tasks import execute_usb_filesystem_scan, execute_android_vulnerability_scan
from .host_audit import extract_system_usb_history

# --- CORE DASHBOARD ---
def dashboard_home(request):
    devices = TargetDevice.objects.all().order_by('-detected_at')
    active_device = TargetDevice.objects.filter(device_id=request.GET.get('device_id')).first()
    artifacts = active_device.artifacts.all().order_by('-severity') if active_device else []
    return render(request, 'forensics/dashboard.html', {
        'devices': devices, 'active_device': active_device, 
        'artifacts': artifacts, 'host_history': extract_system_usb_history()
    })

# --- OPERATIONAL TOOLS ---
def trigger_forensic_scan(request, device_id):
    device = get_object_or_404(TargetDevice, device_id=device_id)
    # Ensure .delay() is being called
    if device.device_type == 'ANDROID': 
        execute_android_vulnerability_scan.delay(device.device_id)
    else: 
        execute_usb_filesystem_scan.delay(device.device_id)
    return redirect(f'/?device_id={device.device_id}')

def inspect_file_content(request, artifact_id):
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    path_match = re.search(r'(?:File|Path):\s*([A-Za-z]:\\[^\s|]+)', artifact.extracted_data)
    if path_match and os.path.exists(path_match.group(1)):
        with open(path_match.group(1), 'r', encoding='utf-8', errors='ignore') as f:
            return JsonResponse({"file": os.path.basename(path_match.group(1)), "content": f.read(2000000)})
    return JsonResponse({"error": "File unreachable."}, status=404)

def download_file(request, artifact_id):
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    path_match = re.search(r'(?:File|Path):\s*([A-Za-z]:\\[^\s|]+)', artifact.extracted_data)
    if path_match and os.path.exists(path_match.group(1)):
        with open(path_match.group(1), 'rb') as f:
            response = HttpResponse(f.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(path_match.group(1))}"'
            return response
    return Http404("File not found.")

# --- CASE MANAGEMENT ---
def update_case_metadata(request, device_id):
    device = get_object_or_404(TargetDevice, device_id=device_id)
    if request.method == "POST":
        device.case_number = request.POST.get('case_number', ''); device.investigator_name = request.POST.get('investigator_name', ''); device.case_notes = request.POST.get('case_notes', ''); device.save()
    return redirect(f'/?device_id={device.device_id}')

def export_case_report(request, device_id):
    device = get_object_or_404(TargetDevice, device_id=device_id)
    return render(request, 'forensics/report_export.html', {'device': device, 'artifacts': device.artifacts.all()})