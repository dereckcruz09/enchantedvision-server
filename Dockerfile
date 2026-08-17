# Multi-stage build for Discord OAuth2 Auth Server
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY discord_auth.py .

# Create non-root user for security
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-10000}/health || exit 1

# Expose port (default 10000 for Render compatibility)
EXPOSE ${PORT:-10000}

# Run the application with gunicorn.
# NOTE: this service runs as a Docker web service on Render, which executes
# this CMD directly and ignores render.yaml's startCommand. --workers must
# stay 1: _device_binds/_live_sessions/recent_authentications/_role_denied
# are process-local in-memory dicts with no shared cache, so >1 worker lets
# a customer's login land on one worker and their heartbeat land on
# another, which never saw the bind and denies them with "Sign in again"
# even though they have the required role.
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "--workers", "1", "--timeout", "60", "server:app"]
