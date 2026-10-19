# NetSentinel AI - API image (base dependencies only; no torch, no dashboard).
# Build:  docker build -t netsentinel:dev .
# Run:    docker compose up   (see docker-compose.yml; models are mounted read-only)
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# uv from the official image, pinned to the version that wrote uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv
# LightGBM wheels need the OpenMP runtime.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Dependency layer first (cache-friendly): only the lockfile and project metadata.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY configs ./configs
RUN uv sync --frozen --no-dev

RUN useradd --create-home --uid 10001 netsentinel \
    && mkdir -p /app/artifacts /models \
    && chown -R netsentinel:netsentinel /app/artifacts
USER netsentinel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# Inside the container the API must listen on 0.0.0.0; publish it on the host's localhost only
# (docker-compose.yml maps 127.0.0.1:8000:8000).
ENTRYPOINT ["netsentinel"]
CMD ["serve", "--bundle", "/models/bundle", "--host", "0.0.0.0", "--port", "8000", \
     "--events-db", "/app/artifacts/events.sqlite"]
