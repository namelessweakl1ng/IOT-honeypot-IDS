FROM python:3.11-slim-bookworm

RUN groupadd --gid 10003 app && \
    useradd --uid 10003 --gid app --home-dir /app --shell /sbin/nologin app && \
    mkdir -p /app /data && chown -R app:app /app /data

WORKDIR /app
COPY --chown=app:app app.py /app/app.py

USER app
CMD ["python", "app.py"]
