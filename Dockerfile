# --- Build stage: install Python dependencies into a venv ---
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# psycopg2 is built from source: needs a compiler and the libpq headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN uv venv /opt/venv \
    && uv pip install --python /opt/venv/bin/python --no-cache -r requirements.txt


# --- Runtime stage ---
FROM python:3.12-slim

# Code lives in /app, runtime files (settings.json, jwk_key.json, admin.crt,
# admin.key) are read/written relative to the working directory /data
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    GUNICORN_CMD_ARGS="--bind 0.0.0.0:5000 --workers 1 --threads 4 --access-logfile -"

# libpq runtime library for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
    && mkdir /data \
    && chown app:app /data

COPY --from=builder /opt/venv /opt/venv
COPY config.py /app/
COPY app /app/app

WORKDIR /data
USER app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/auth/login', timeout=4)"]

CMD ["gunicorn", "app:create_app()"]
