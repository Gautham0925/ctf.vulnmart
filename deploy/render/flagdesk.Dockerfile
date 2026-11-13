FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY flagdesk/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY flagdesk/app app
COPY flagdesk/wordlists wordlists
COPY flagdesk/migrations migrations
COPY flagdesk/alembic.ini flagdesk/challenges.seed.json ./
COPY scripts scripts
COPY deploy/render/flagdesk.sh /srv/start.sh
RUN mkdir -p data && chmod +x /srv/start.sh && useradd -r -u 10001 app && chown -R app /srv/data
USER app
CMD ["/srv/start.sh"]
