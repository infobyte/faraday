FROM python:3.11-slim-bookworm

# Set DEV_ENV=1 to build with development dependencies and editable install
# Comment for prod
ARG DEV_ENV

WORKDIR /src

# Copy dependency files first for better layer caching
COPY pyproject.toml uv.lock ./
COPY ./docker/entrypoint.sh /entrypoint.sh
COPY ./docker/server.ini /docker_server.ini

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates python3-dev build-essential libgdk-pixbuf2.0-0 \
    libpq-dev libsasl2-dev libldap2-dev libssl-dev libmagic1 redis-tools netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* \
    && chmod +x /entrypoint.sh

# Install uv (pinned version)
COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /usr/local/bin/uv

# Install dependencies only (cached unless pyproject.toml/uv.lock change)
RUN if [ ! -z "$DEV_ENV" ]; then \
    echo "Building dev environment ..." && \
    uv sync --frozen --no-cache --no-install-project; \
    else \
    uv sync --frozen --no-dev --no-cache --no-editable --no-install-project; \
    fi

# Copy source code (changes here won't invalidate dependency cache)
COPY . /src

# Install the project itself (deps already cached, this just adds the package)
RUN if [ ! -z "$DEV_ENV" ]; then \
    uv sync --frozen --no-cache; \
    else \
    uv sync --frozen --no-dev --no-cache --no-editable; \
    fi

# Add venv to PATH
ENV PATH="/src/.venv/bin:$PATH"

WORKDIR /home/faraday

RUN mkdir -p /home/faraday/.faraday/{config,logs,session,storage}

ENV PYTHONUNBUFFERED=1
ENV FARADAY_HOME=/home/faraday

EXPOSE 5985

ENTRYPOINT ["/entrypoint.sh"]
