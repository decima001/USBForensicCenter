import os
import re
import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponse, JsonResponse
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
        try:
            active_device = TargetDevice.objects.get(id=device_id)
            active_device.refresh_from_db()
            artifacts = active_device.artifacts.all().order_by('-severity', '-created_at')
        except TargetDevice.DoesNotExist:
            return redirect('dashboard_home')
    elif devices.exists():
        return redirect('device_detail', device_id=devices.first().id)

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
    device.status = 'SCANNING'
    device.save()
    
    if device.device_type == 'USB':
        execute_usb_filesystem_scan.delay(device.device_id)
    elif device.device_type == 'ANDROID':
        execute_android_vulnerability_scan.delay(device.device_id)
        
    return redirect('device_detail', device_id=device.id)


def download_artifact_file(request, artifact_id):
    """
    Resolves the target file name or absolute path from a specific ForensicArtifact,
    binds it cleanly to the hardware mount point, and handles the download pipeline.
    """
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    device = artifact.device

    path_match = re.search(r'(?:Path|File):\s*([a-zA-Z]:\\[^\s|]+)', artifact.extracted_data)
    if path_match:
        resolved_file_path = path_match.group(1).strip()
    else:
        file_match = re.search(r'(?:Path|File):\s*([^\s|]+\.[a-zA-Z0-9]{2,4})', artifact.extracted_data)
        if not file_match:
            raise Http404("No valid file reference or text target could be extracted from this artifact metadata.")
        filename = file_match.group(1).strip()
        resolved_file_path = os.path.join(device.mount_point, filename)

    if os.path.exists(resolved_file_path):
        with open(resolved_file_path, 'rb') as fh:
            mime_type, _ = mimetypes.guess_type(resolved_file_path)
            response = HttpResponse(fh.read(), content_type=mime_type or "application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(resolved_file_path)}"'
            return response
            
    raise Http404(f"Target verification failed: File not found at '{resolved_file_path}'. Check if the media device was detached.")


def inspect_file_content(request, artifact_id):
    """
    NEW: Reads text file artifacts and streams raw snippets directly to the front-end interface
    as JSON for real-time visualization without downloading the file first.
    """
    artifact = get_object_or_404(ForensicArtifact, id=artifact_id)
    path_match = re.search(r'(?:Path|File):\s*([a-zA-Z]:\\[^\s|]+)', artifact.extracted_data)
    
    if not path_match:
        file_match = re.search(r'(?:Path|File):\s*([^\s|]+\.[a-zA-Z0-9]{2,4})', artifact.extracted_data)
        if not file_match:
            return JsonResponse({"error": "No parseable path"}, status=400)
        resolved_file_path = os.path.join(artifact.device.mount_point, file_match.group(1).strip())
    else:
        resolved_file_path = path_match.group(1).strip()

    if os.path.exists(resolved_file_path):
        try:
            with open(resolved_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return JsonResponse({"content": f.read(5000)})  # Limit to first 5000 chars for safety
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
            
    return JsonResponse({"error": "File not found on drive"}, status=404)