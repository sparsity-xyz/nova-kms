FROM python:3.11-slim

WORKDIR /app

# Install python dependencies
COPY enclave/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy enclave code
COPY enclave/ .

ENV IN_ENCLAVE=true
CMD ["python", "app.py"]
