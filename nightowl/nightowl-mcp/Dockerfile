FROM python:3.11-slim

# Security: non-root user
RUN useradd -m -u 1000 nightowl

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Copy modules from parent directory (built by earlier tasks)
COPY --chown=nightowl:nightowl ../modules /app/modules

# Switch to non-root
USER nightowl

ENV PORT=8080
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health').raise_for_status()" || exit 1

CMD ["python", "server.py"]
