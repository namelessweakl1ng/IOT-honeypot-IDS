FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends --yes openssh-client \
    && command -v ssh \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd --system --uid 10001 trapsig
USER trapsig
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
