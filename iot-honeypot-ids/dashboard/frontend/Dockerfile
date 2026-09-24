# Custom React dashboard
#
# Two-stage build: install deps, then build static assets.
# For the lab we use the dev server (vite) directly inside Docker Compose.

FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
# If no lockfile exists, fall back to npm install (which writes one)
RUN if [ ! -f package-lock.json ]; then npm install; else npm ci; fi

COPY . .
EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
