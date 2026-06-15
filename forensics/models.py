from django.db import models

class TargetDevice(models.Model):
    DEVICE_TYPES = [
        ('USB', 'USB / External Mass Storage'),
        ('ANDROID', 'Android Device'),
    ]
    
    STATUS_CHOICES = [
        ('DETECTED', 'Detected / Idle'),
        ('SCANNING', 'Scan In Progress'),
        ('COMPLETED', 'Scan Completed'),
        ('FAILED', 'Scan Failed'),
    ]

    # FIXED: Changed help_with to help_text
    device_id = models.CharField(max_length=255, unique=True, help_text="Serial number or hardware UUID")
    device_type = models.CharField(max_length=15, choices=DEVICE_TYPES)
    label = models.CharField(max_length=255, blank=True, null=True, help_text="e.g., Samsung S23, SanDisk 64GB")
    # FIXED: Escaped the backslash using E:\\ to satisfy Python 3.14 string parsing
    mount_point = models.CharField(max_length=50, blank=True, null=True, help_text="e.g., E:\\ or ADB device ID")
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='DETECTED')
    detected_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.get_device_type_display()} - {self.label or self.device_id}"


class ForensicArtifact(models.Model):
    SEVERITY_LEVELS = [
        ('INFO', 'Information / Log'),
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk / Exposure'),
    ]

    device = models.ForeignKey(TargetDevice, on_delete=models.CASCADE, related_name='artifacts')
    title = models.CharField(max_length=255, help_text="Summary of the finding (e.g., Cached Browser Password Found)")
    category = models.CharField(max_length=100, help_text="e.g., Browser Cache, Application Log, System Settings")
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='INFO')
    
    # JSONField allows storing varying structured objects like specific system logs or packet data metadata
    extracted_data = models.JSONField(help_text="Raw or parsed structure of the forensic artifact")
    
    timestamp_observed = models.DateTimeField(blank=True, null=True, help_text="The historic log timestamp from the target device")
    created_at = models.DateTimeField(auto_now_add=True, help_text="When this tool parsed and saved the data")

    def __str__(self):
        return f"[{self.severity}] {self.category} - {self.title}"