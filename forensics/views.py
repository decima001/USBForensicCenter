# ... (Keep all your existing imports and views at the top)

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
        
    return redirect('device_detail', device_id=device.id)


def export_case_report(request, device_id):
    """
    Generates a clean operational triage summary report document.
    Formatted explicitly for legal archiving, team distribution, or printing.
    """
    device = get_object_or_404(TargetDevice, id=device_id)
    # Pull artifacts ordered by critical/high priority first to headline the report
    artifacts = device.artifacts.all().order_by('-severity', '-created_at')
    
    context = {
        'device': device,
        'artifacts': artifacts,
    }
    return render(request, 'forensics/report_export.html', context)