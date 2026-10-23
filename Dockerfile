FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_FILE=/var/log/honeypot/events.jsonl \
    BIND_HOST=0.0.0.0 \
    SSH_SANDBOX=simulate

WORKDIR /app

#dépendances d'abord : meilleur cache de build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

#utilisateur non-root (uid 1000) + dossier de logs qui lui appartient
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /var/log/honeypot \
    && chown -R honeypot:honeypot /var/log/honeypot /app
USER honeypot

VOLUME ["/var/log/honeypot"]

#ports internes (tous > 1024, pas besoin de privilèges) : le mapping vers 21, 22, 80... se fait dans docker-compose.yml
EXPOSE 8080 2222 2121 6379 3306 2323 2525 1110 3890 3389 5432 9000

CMD ["python", "-m", "src.main"]
