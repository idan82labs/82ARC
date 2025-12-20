# Aegis - AI Security Testing Platform
# Multi-stage build for optimized image size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir build
RUN pip wheel --no-cache-dir --wheel-dir /wheels -e ".[all]"

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user for security
RUN groupadd -r aegis && useradd -r -g aegis aegis

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Copy application code
COPY aegis ./aegis
COPY packs ./packs

# Create data directory
RUN mkdir -p /data && chown -R aegis:aegis /data

# Set environment
ENV PYTHONUNBUFFERED=1
ENV AEGIS_DATA_PATH=/data
ENV AEGIS_PACKS_PATH=/app/packs

# Switch to non-root user
USER aegis

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Default command - run API server
CMD ["python", "-m", "aegis.api.app"]
