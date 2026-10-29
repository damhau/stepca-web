# Installs dependencies with uv. Dockerfile.pip builds the same image with plain pip.

# --- Build stage: install Python dependencies into a venv ---
FROM python:3.12-slim AS builder

# uv from PyPI, so the build only needs Docker Hub and PyPI
RUN pip install --no-cache-dir uv==0.9.5

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

# Exact versions from uv.lock; all dependencies ship prebuilt wheels, so no compiler is needed
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-cache


# --- Runtime stage ---
FROM python:3.12-slim

# Code lives in /app; runtime files (settings.json, jwk_key.json, admin.crt, admin.key, ca_root.crt,
# stepca-web.db, local_users.json) in the data directory /data
ENV PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    GUNICORN_CMD_ARGS="--bind 0.0.0.0:5000 --workers 1 --threads 4 --access-logfile -"

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
    && mkdir /data \
    && chown app:app /data

COPY --from=builder /opt/venv /opt/venv
COPY app /app/app

WORKDIR /data
USER app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/auth/login', timeout=4)"]

CMD ["gunicorn", "app:create_app()"]
