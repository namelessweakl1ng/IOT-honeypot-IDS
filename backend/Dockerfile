FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends --yes gosu openssh-client \
    && command -v ssh \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd --system --uid 10001 --home-dir /home/trapsig trapsig
COPY docker-entrypoint.sh /usr/local/bin/trapsig-entrypoint
RUN chmod 0755 /usr/local/bin/trapsig-entrypoint \
    && install -d -o trapsig -g trapsig -m 0700 /home/trapsig/.ssh \
    && install -o trapsig -g trapsig -m 0600 /dev/null /home/trapsig/.ssh/readability-check \
    && gosu trapsig test -r /home/trapsig/.ssh/readability-check \
    && rm /home/trapsig/.ssh/readability-check
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/trapsig-entrypoint"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
