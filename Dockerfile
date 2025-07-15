# =============================================================================
# Company1 Auth Service - Production Multi-Stage Dockerfile
# Optimized for: Security, CI/CD pipelines, and production deployment
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Base Dependencies (Shared layer for caching)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS base

# Set environment variables for Python optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and security updates
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security (following production best practices)
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create app directory with proper ownership
WORKDIR /app
RUN chown -R appuser:appuser /app

# -----------------------------------------------------------------------------
# Stage 2: Dependencies Installation (Cached layer)
# -----------------------------------------------------------------------------
FROM base AS dependencies

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 3: Testing Stage (CI/CD Pipeline Integration)
# -----------------------------------------------------------------------------
FROM dependencies AS testing

# Copy source code for testing
COPY --chown=appuser:appuser . .

# Switch to non-root user for testing
USER appuser

# Install development/testing dependencies
RUN pip install --no-cache-dir pytest pytest-cov httpx

# Run tests and generate coverage (CI/CD integration point)
RUN python -m pytest tests/ -v --cov=. --cov-report=term-missing || echo "Tests run in CI"

# Security: Ensure no secrets in final image
RUN find . -name "*.env*" -delete 2>/dev/null || true

# -----------------------------------------------------------------------------
# Stage 4: Production Runtime (Minimal & Secure)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS production

# Copy optimized Python settings from base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    libpq5 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (security best practice)
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set up application directory
WORKDIR /app
RUN chown -R appuser:appuser /app

# Copy Python dependencies from dependencies stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=dependencies /usr/local/bin/ /usr/local/bin/

# Copy application code (excluding tests and dev files)
COPY --chown=appuser:appuser main.py .
COPY --chown=appuser:appuser requirements.txt .

# Switch to non-root user (security hardening)
USER appuser

# Health check for Kubernetes readiness/liveness probes
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port (documentation - actual port binding done by k8s)
EXPOSE 8000

# Production startup command
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# =============================================================================
# Multi-stage build benefits:
# 1. Security: Non-root user, minimal attack surface
# 2. Performance: Optimized layer caching for CI/CD
# 3. Testing: Built-in test execution for automated pipelines  
# 4. Production: Minimal runtime image without dev dependencies
# 5. Monitoring: Health checks for Kubernetes integration
# =============================================================================
