# =============================================================================
# Nova KMS - Dockerfile
# =============================================================================
# Single-stage build (no frontend).  Runs inside AWS Nitro Enclave.
# =============================================================================

FROM python:3.12-slim

WORKDIR /app

ENV IN_ENCLAVE=true

# Install dependencies first for Docker layer caching
COPY enclave/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY enclave/ .

EXPOSE 8000

CMD ["python", "app.py"]
