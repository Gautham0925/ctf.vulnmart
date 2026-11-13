FROM node:22-alpine AS build
WORKDIR /app
COPY vulnmart/frontend/package.json vulnmart/frontend/package-lock.json ./
RUN npm ci
COPY vulnmart/frontend .
RUN npx tsc --noEmit && npx vite build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl nginx && rm -rf /var/lib/apt/lists/*
COPY vulnmart/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vulnmart/backend/app ./app
COPY vulnmart/backend/migrations ./migrations
COPY vulnmart/backend/alembic.ini .
COPY --from=build /app/dist /usr/share/nginx/html
COPY deploy/render/shop.nginx.conf /etc/nginx/shop.conf.tmpl
COPY deploy/render/shop.sh /app/start.sh
RUN mkdir -p /app/keys && chmod +x /app/start.sh && useradd -r -u 10002 app && chown -R app /app/keys
USER app
CMD ["/app/start.sh"]
