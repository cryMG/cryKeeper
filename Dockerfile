###################
# Build stage for static assets
###################
FROM python:3.14-slim AS asset-builder

WORKDIR /build

COPY requirements.txt requirements-dev.txt /tmp/
RUN pip install -r /tmp/requirements-dev.txt

COPY app/static ./app/static
COPY scripts ./scripts

RUN python /build/scripts/build_static_assets.py /build/app/static /build/static-dist

###################
# Final image
###################
FROM python:3.14-slim

ARG VERSION=dev
ARG VCS_REF=
ARG BUILD_DATE=

LABEL org.opencontainers.image.title="cryKeeper" \
    org.opencontainers.image.description="The open-source human verification service for nginx making bots cry" \
    org.opencontainers.image.url="https://github.com/cryMG/cryKeeper" \
    org.opencontainers.image.documentation="https://github.com/cryMG/cryKeeper/blob/main/README.md" \
    org.opencontainers.image.source="https://github.com/cryMG/cryKeeper" \
    org.opencontainers.image.vendor="cryeffect Media Group" \
    org.opencontainers.image.authors="Peter Müller <peter@crycode.de>" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.base.name="docker.io/library/python:3.14-slim" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CRYKEEPER_CONFIG_FILE=/app/config.toml \
    CRYKEEPER_PROMETHEUS_MULTIPROC_DIR=/tmp/crykeeper-prometheus \
    CRYKEEPER_GUNICORN_WORKERS=2 \
    CRYKEEPER_GUNICORN_THREADS=4

RUN groupadd --system crykeeper \
    && useradd --system --gid crykeeper --create-home --home-dir /home/crykeeper crykeeper \
    && mkdir -p /app \
    && chown crykeeper:crykeeper /app

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
COPY app ./app
COPY entrypoint.sh gunicorn.conf.py wsgi.py ./
COPY --from=asset-builder /build/static-dist/ ./app/static/

RUN pip install -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && chmod 755 /app/entrypoint.sh

USER crykeeper

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/_crykeeper/healthz')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
