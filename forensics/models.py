from django.db import models
from django.utils import timezone

class TargetDevice(models.Model):
    DEVICE_TYPES = (
        ('USB', 'USB Storage Media'),
        ('ANDROID', 'Android Mobile Device'),
    )
    STATUS_CHOICES = (
        ('IDLE', 'Idle Registry'),
        ('SCANNING', 'Auditing Targets...'),
        ('COMPLETED', 'Analysis Complete'),
        ('FAILED', 'Execution Failure'),
    )
    
    device_id = models.CharField(max_length=255, unique=True)
    device_type = models.CharField(max_length=50, choices=DEVICE_TYPES)
    mount_point = models.CharField(max_length=255)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='IDLE')
    detected_at = models.DateTimeField(default=timezone.now)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    
    # NEW: Forensic Case Metadata Fields
    case_number = models.CharField(max_length=100, default="CASE-2026-001")
    investigator_name = models.CharField(max_length=255, default="Lead Analyst")
    case_notes = models.TextField(blank=True, default="Standard automated digital forensic acquisition triage routine.")

    def __str__(self):
        return f"{self.device_type} Target ({self.mount_point})"


class ForensicArtifact(models.Model):
    SEVERITY_LEVELS = (
        ('LOW', 'Low Operational Risk'),
        ('HIGH', 'High Security Flag'),
        ('CRITICAL', 'Critical Evasion Leak'),
    )
    
    device = models.ForeignKey(TargetDevice, on_delete=models.CASCADE, related_name='artifacts')
    category = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=50, choices=SEVERITY_LEVELS, default='LOW')
    extracted_data = models.TextField()
    
    # NEW: Deep File Integrity Fields
    sha256_hash = models.CharField(max_length=64, blank=True, null=True)
    true_mime_type = models.CharField(max_length=100, blank=True, null=True)
    is_spoofed = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"[{self.severity}] {self.category} - {self.title}"