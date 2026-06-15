import os
from celery import Celery

# Set default Django settings module for 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery('core')

# Read config from Django settings, using a 'CELERY_' prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks.py modules inside all registered Django apps.
app.autodiscover_tasks()