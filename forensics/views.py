import os
import re
import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponse, JsonResponse
from django.utils import timezone
from forensics.models import TargetDevice, ForensicArtifact
from .tasks import execute_usb_filesystem_scan, execute_android_vulnerability_scan

# 🆕 IMPORT SYSTEM FOOTPRINT ENGINE (From Step 1)
from .host_audit import extract_system_usb_history


def dashboard_home(request):
    """
    Primary Incident Workspace Hub Control Engine.
    Aggregates connected target hardware nodes and runs live system registry 
    audits to surface past device footprints.
    """
    devices = TargetDevice.objects.all().order_by('-detected_at')
    active_device_id = request.GET.get('device_id')
    
    active_device = None
    artifacts = []
    
    if active_device_id:
        active_device = TargetDevice.objects.filter(device_id=active_device_id).first()
        if active_device:
            # Sort critical anti-forensics and credential alerts to the top of the timeline
            artifacts = active_device.artifacts.all().order_by('-severity', '-created_at')
            
    # 🆕 EXECUTE REGISTRY SCANDISK HISTORICAL CORRELATION
    host_history = extract_system_usb_history()

    context = {
        'devices': devices,
        'active_device': active_device,
        'artifacts': artifacts,
        'host_history': host_history,  # Exposed directly to the sidebar template layout
    }
    return render(request, 'forensics/dashboard.html', context)


def trigger_forensic_scan(request, device_id):
    """
    Dispatches targeted processing pipelines down to back-end Celery workers.
    Ensures asynchronous scanning doesn't lock the web UI request threads.
    """
    device = get_object_or_404(TargetDevice, id=device_id)
    
    if device.status != 'SCANNING':
        if device.device_type == 'ANDROID':
            execute_android_vulnerability_scan.delay(device.device_id)
        else:
            execute_usb_filesystem_scan.delay(device.device_id)
            
    return redirect(f'/?device_id={device.device_id}')


def inspect_file_content(request, artifact_id):
    """
    Directory-Safe Raw Binary/Text Inspector View.
    Bypasses standard Windows exception crashes when an analyst evaluates a targeted leak.
    """
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    
    # Simple regex parsing extraction layer to safely grab raw paths from context notes
    path_match = re.search(r'(?:File|Path):\s*([A-Za-z]:\\[^\s|]+)', artifact.extracted_data)
    if not path_match:
        return JsonResponse({"error": "No parsable target filepath pattern found inside current artifact summary data."}, status=400)
        
    target_file_path = path_match.group(1)
    
    if os.path.isdir(target_file_path):
        return JsonResponse({
            "file_name": os.path.basename(target_file_path),
            "content": f"[SYSTEM WARNING] Target reference is an active Directory Junction Node, not an extractable binary file entry.\nPath: {target_file_path}"
        })
        
    if not os.path.exists(target_file_path):
        return JsonResponse({"error": f"Target file target has vanished or was unmounted: {target_file_path}"}, status=404)

    try:
        # Enforce file inspect limits to safeguard web memory footprints (Max 2MB review buffer)
        if os.path.getsize(target_file_path) > 2 * 1024 * 1024:
            return JsonResponse({"error": "File size exceeds standard fast-triage viewing thresholds (Max 2MB limit). Use localized extraction carvers."}, status=400)

        with open(target_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_data_stream = f.read()
            
        return JsonResponse({
            "file_name": os.path.basename(target_file_path),
            "content": raw_data_stream
        })
    except PermissionError:
        return JsonResponse({"error": "OS Kernel Access Denied: Target path locked by active system handles or missing administrative environment context."}, status=403)
    except Exception as e:
        return JsonResponse({"error": f"Read routine failed completely: {str(e)}"}, status=500)


# ====================================================
# 🆕 CASE META-MANAGEMENT & EXPORT REPORT VIEWS
# ====================================================

def update_case_metadata(request, device_id):
    """
    Saves investigator case logs and reference numbers to the active device.
    Ensures structural data tags stick to the target workspace profile.
    """
    device = get_object_or_404(TargetDevice, id=device_id)
    
    if request.method == "POST":
        device.case_number = request.POST.get('case_number', device.case_number).strip()
        device.investigator_name = request.POST.get('investigator_name', device.investigator_name).strip()
        device.case_notes = request.POST.get('case_notes', device.case_notes).strip()
        device.save()
        
    return redirect(f'/?device_id={device.device_id}')


def export_case_report(request, device_id):
    """
    Generates a clean operational triage summary report document.
    Formatted explicitly for legal archiving, team distribution, or physical printing.
    """
    device = get_object_or_404(TargetDevice, id=device_id)
    # Pull artifacts ordered by critical/high priority first to headline the report document
    artifacts = device.artifacts.all().order_by('-severity', '-created_at')
    
    context = {
        'device': device,
        'artifacts': artifacts,
    }
    return render(request, 'forensics/report_export.html', context)