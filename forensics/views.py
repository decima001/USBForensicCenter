import os
import re
import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponse
from forensics.models import TargetDevice, ForensicArtifact
from forensics.detectors import monitor_and_update_devices
from forensics.tasks import execute_usb_filesystem_scan, execute_android_vulnerability_scan

def dashboard_home(request, device_id=None):
    """
    Renders the core forensic tracking engine panel workspace matrix.
    Queries active system hardware registers and pulls explicit state changes.
    """
    devices = TargetDevice.objects.all().order_by('-detected_at')
    active_device = None
    artifacts = []

    if device_id:
        active_device = get_object_or_404(TargetDevice, id=device_id)
        
        # FORCE DB REFRESH: Bypasses Django's local object instance memory cache
        # to guarantee we read the 'COMPLETED' status written by the Celery worker.
        active_device.refresh_from_db()
        
        artifacts = active_device.artifacts.all().order_by('-severity', '-created_at')

    context = {
        'devices': devices,
        'active_device': active_device,
        'artifacts': artifacts
    }
    return render(request, 'forensics/dashboard.html', context)


def trigger_hardware_scan(request):
    """
    Triggers the physical hardware mapping routing loop directly
    to discover connected USB storage units or ADB instances.
    """
    monitor_and_update_devices()
    return redirect('dashboard_home')


def trigger_forensic_scan(request, device_id):
    """
    Pipes high-density deep forensics scraping routines off to background 
    Celery layers to ensure long-running audits don't freeze the HTTP server thread.
    """
    device = get_object_or_404(TargetDevice, id=device_id)
    
    # Transition status to scanning before offloading the task payload
    device.status = 'SCANNING'
    device.save()
    
    if device.device_type == 'USB':
        execute_usb_filesystem_scan.delay(device.device_id)
    elif device.device_type == 'ANDROID':
        execute_android_vulnerability_scan.delay(device.device_id)
        
    return redirect('device_detail', device_id=device.id)


def download_artifact_file(request, artifact_id):
    """
    Resolves the exact file path parsed inside a specific ForensicArtifact 
    and pipes it directly back to the analyst browser as an attachment download.
    """
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    
    # Use regex routing to isolate the path string inside our extracted data block
    path_match = re.search(r'(?:Path|File):\s*([a-zA-Z]:\\[^\s|]+)', artifact.extracted_data)
    
    if not path_match:
        raise Http404("No absolute disk file path could be parsed from this artifact metadata payload.")
    
    resolved_file_path = path_match.group(1).strip()
    
    if os.path.exists(resolved_file_path):
        with open(resolved_file_path, 'rb') as fh:
            mime_type, _ = mimetypes.guess_type(resolved_file_path)
            response = HttpResponse(fh.read(), content_type=mime_type or "application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename={os.path.basename(resolved_file_path)}'
            return response
            
    raise Http404("The requested file no longer exists on the target media or device was detached.")