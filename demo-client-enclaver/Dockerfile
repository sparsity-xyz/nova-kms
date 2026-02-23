FROM python:3.11-slim

WORKDIR /app

COPY enclave/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enclave/ .

ENV IN_ENCLAVE=true
CMD ["python", "app.py"]
