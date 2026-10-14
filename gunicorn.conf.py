"""Production WSGI configuration for DeCloud.

Use one worker: authentication sessions and WebSocket state are intentionally
process-local. Scale out only after moving that state to shared storage.
"""
import os

bind = os.environ.get('GUNICORN_BIND', '127.0.0.1:8899')
workers = 1
threads = 8
timeout = 120
keepalive = 5
accesslog = '-'
errorlog = '-'
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')

# Do not preload: the application owns startup configuration and sockets.
preload_app = False
