FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# Copy application
COPY ./arc_solver ./arc_solver
COPY ./configs ./configs

# Create data directories
RUN mkdir -p /app/data /app/results

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "arc_solver.main:app", "--host", "0.0.0.0", "--port", "8000"]
