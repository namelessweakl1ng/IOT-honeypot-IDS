# Camera HTTP honeypot
# Slim Python base for the Pi 4 (arm64). Pinned to a specific minor version.
FROM python:3.11-slim-bookworm

# Create non-root user for the container
RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid app --home-dir /app --shell /sbin/nologin app && \
    mkdir -p /app/logs && chown -R app:app /app

WORKDIR /app

# Install deps as app user, then drop back to root only for COPY chown
COPY --chown=app:app requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=app:app app.py /app/app.py

USER app
EXPOSE 8080

# Simple Flask dev server is sufficient for honeypot telemetry on the Pi.
# Use --workers=1 --threads=4 to stay under the 96M cap.
CMD ["python", "app.py"]
