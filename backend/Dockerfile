# KGuard Backend Dockerfile
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# No system packages: every dependency ships as a wheel, and the health
# check uses Python, so there is no compiler or curl in the image

# Unprivileged user the backend runs as (fixed IDs so volumes and
# group_add are predictable)
RUN groupadd -r -g 10001 app && useradd -r -u 10001 -g app -d /app -s /usr/sbin/nologin app

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base AS development

# Install development dependencies
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Change ownership to app user
RUN chown -R app:app /app

# Switch to app user
USER app

# Expose port
EXPOSE 8000

# Command for development
# Reloads on code changes because DEBUG=true
CMD ["python", "-m", "app"]

# Production stage
FROM base AS production

# Application code belongs to root and is read-only to the app user; only
# data/ and logs/ are writable
COPY . .
RUN mkdir -p /app/data /app/logs && \
    chown app:app /app/data /app/logs && \
    chmod 750 /app/data /app/logs

# Never run as root
USER 10001:10001

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health/', timeout=5)"]

# Command for production
# One process: the collector and detection state live in it (see app/__main__.py)
CMD ["python", "-m", "app"]