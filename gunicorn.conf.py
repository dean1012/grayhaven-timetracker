"""Low-resource Gunicorn configuration."""

bind = "0.0.0.0:8000"
workers = 1
threads = 4
worker_class = "gthread"
timeout = 30
graceful_timeout = 30
keepalive = 5
accesslog = None
errorlog = "-"
capture_output = True
