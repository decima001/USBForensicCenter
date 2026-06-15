from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_home, name='dashboard_home'),
    path('scan-hardware/<str:device_id>/', views.trigger_forensic_scan, name='trigger_forensic_scan'),
    path('device/<str:device_id>/update-case/', views.update_case_metadata, name='update_case_metadata'),
    path('device/<str:device_id>/export-report/', views.export_case_report, name='export_case_report'),
    # Restored artifact tools
    path('inspect/<int:artifact_id>/', views.inspect_file_content, name='inspect_file'),
    path('download/<int:artifact_id>/', views.download_file, name='download_file'),
]