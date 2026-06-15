from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_home, name='dashboard_home'),
    path('device/<int:device_id>/', views.dashboard_home, name='device_detail'),
    path('scan-hardware/', views.trigger_hardware_scan, name='trigger_hardware_scan'),
    path('scan-forensic/<int:device_id>/', views.trigger_forensic_scan, name='trigger_forensic_scan'),
    path('download-evidence/<int:artifact_id>/', views.download_artifact_file, name='download_evidence'),
]