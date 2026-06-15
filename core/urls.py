from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Fixed: Removed the broken admin.site.split route entirely
    path('admin/', admin.site.urls),
    path('', include('forensics.urls')),
]