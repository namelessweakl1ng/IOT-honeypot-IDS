# IoT service honeypot — pure-stdlib, minimal image
FROM python:3.11-slim-bookworm

RUN groupadd --gid 10002 app && \
    useradd --uid 10002 --gid app --home-dir /app --shell /sbin/nologin app && \
    mkdir -p /app/logs && chown -R app:app /app

WORKDIR /app
COPY --chown=app:app app.py /app/app.py

USER app
EXPOSE 9000

CMD ["python", "app.py"]
