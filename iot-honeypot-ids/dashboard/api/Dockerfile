# FastAPI image — Python 3.11 slim
FROM python:3.11-slim-bookworm

# Build deps for scikit-learn / numpy / pandas wheels (mostly pre-built, but
# keep gcc in case the platform needs it for arm64 fallback)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

EXPOSE 8000

# Run via uvicorn with a single worker — fine for a lab machine.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
