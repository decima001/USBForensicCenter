from django.db import models
from django.utils import timezone

class TargetDevice(models.Model):
    DEVICE_TYPES = (('USB', 'USB Storage Media'), ('ANDROID', 'Android Mobile Device'))
    STATUS_CHOICES = (('IDLE', 'Idle'), ('SCANNING', 'Scanning'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed'))
    
    device_id = models.CharField(max_length=255, unique=True)
    device_type = models.CharField(max_length=50, choices=DEVICE_TYPES)
    mount_point = models.CharField(max_length=255, default="E:\\") # Migration default
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='IDLE')
    detected_at = models.DateTimeField(default=timezone.now)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    
    # Forensic Metadata
    case_number = models.CharField(max_length=100, default="CASE-2026-001")
    investigator_name = models.CharField(max_length=255, default="Lead Analyst")
    case_notes = models.TextField(blank=True, default="Standard forensic triage.")

    def __str__(self):
        return f"{self.device_type} ({self.mount_point})"

class ForensicArtifact(models.Model):
    SEVERITY_LEVELS = (('LOW', 'Low'), ('HIGH', 'High'), ('CRITICAL', 'Critical'))
    device = models.ForeignKey(TargetDevice, on_delete=models.CASCADE, related_name='artifacts')
    category = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=50, choices=SEVERITY_LEVELS, default='LOW')
    extracted_data = models.TextField()
    sha256_hash = models.CharField(max_length=64, blank=True, null=True)
    true_mime_type = models.CharField(max_length=100, blank=True, null=True)
    is_spoofed = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)