import os
from celery import Celery

# --- PROTOCOL FIX COUPLING LAYER ---
try:
    # Explicitly force the redis client connection pool defaults to RESP2
    import redis
    redis.Connection.__init__.__defaults__ = tuple(
        2 if k == 'protocol' else v 
        for k, v in zip(redis.Connection.__init__.__code__.co_varnames[1:], redis.Connection.__init__.__defaults__)
    )
    # Double-down defense: enforce it on the Redis connection pool initialization keyword arguments
    from kombu.transport.redis import Transport
    Transport.default_connection_params.update({'protocol': 2})
except Exception:
    pass
# -----------------------------------

# Set default Django settings module for 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery('core')

# Read config from Django settings, using a 'CELERY_' prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks.py modules inside all registered Django apps.
app.autodiscover_tasks()