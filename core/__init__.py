import os

# Force the underlying redis-py client library to drop down to RESP2 protocol limits
os.environ["REDIS_PROTOCOL"] = "2"

from .celery import app as celery_app

__all__ = ('celery_app',)