FROM python:3.12-alpine
WORKDIR /app
COPY app.py .
COPY healthcheck.py /usr/local/bin/healthcheck.py
RUN adduser -D -u 10001 honeypot
USER honeypot
CMD ["python","app.py"]
