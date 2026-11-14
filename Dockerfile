# Digital Footprint Self-Audit — Render / any Docker host.
# python:3.12-slim, ~512 MB free-tier friendly (Maigret limited to --top-sites 200,
# username tools never overlap, scan concurrency 2).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    DATABASE_PATH=/var/data/footprint.db \
    MAIGRET_TOP_SITES=200 \
    MAIGRET_MAX_CONNECTIONS=20 \
    SCAN_CONCURRENCY=2 \
    SECURE_COOKIES=1

# whois CLI is small and more complete than python-whois alone.
# DejaVu fonts are used by the PDF exporter.
RUN apt-get update && apt-get install -y --no-install-recommends \
        whois \
        fonts-dejavu-core \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY app /app/app
COPY static /app/static
COPY data/demo_result.json /app/data/demo_result.json

RUN mkdir -p /var/data \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app /var/data

USER appuser

EXPOSE 8000

# Honour $PORT from Render. Single worker: SQLite + 512 MB RAM.
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
