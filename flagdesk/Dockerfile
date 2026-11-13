FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY flagdesk/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY flagdesk/app app
COPY flagdesk/migrations migrations
COPY flagdesk/alembic.ini flagdesk/challenges.seed.json ./
COPY scripts scripts
RUN mkdir -p data && useradd -r -u 10001 app && chown -R app /srv/data
USER app
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY:-2} --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 15"]
