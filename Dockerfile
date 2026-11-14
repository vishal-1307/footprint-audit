# Digital Footprint Self-Audit — Render / any Docker host.
# python:3.12-slim, ~512 MB free-tier friendly (Maigret limited to --top-sites 200,
# heavy CLIs never overlap, scan concurrency 2).
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
    SECURE_COOKIES=1 \
    SUBFINDER_VERSION=2.17.0

# whois CLI is small and more complete than python-whois alone.
# DejaVu fonts are used by the PDF exporter. curl/unzip/git for extra tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
        whois \
        fonts-dejavu-core \
        ca-certificates \
        curl \
        unzip \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# dnsrecon: PyPI 0.10.1 keeps the classic -d/-t/-j flags and avoids pulling a
# newer FastAPI pin that would conflict with the app. theHarvester is installed
# from the 4.6.0 tag (Python 3.12, same -d/-b/-l/-f flags) *without* its pinned
# FastAPI/Playwright extras — we only need the CLI plus free-source deps.
RUN pip install "dnsrecon==0.10.1" netaddr \
    && pip install --no-deps "git+https://github.com/laramies/theHarvester.git@4.6.0" \
    && pip install aiodns aiofiles aiomultiprocess aiosqlite ujson retrying

# Official subfinder linux amd64 release (pinned).
RUN curl -sSL -o /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/subfinder.zip -d /tmp/subfinder \
    && install -m 0755 /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder /tmp/subfinder.zip \
    && subfinder -version -duc

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
