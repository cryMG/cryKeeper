FROM python:3.13-slim

ARG VERSION=dev
ARG VCS_REF=
ARG BUILD_DATE=

LABEL org.opencontainers.image.title="Gatekeeper" \
    org.opencontainers.image.description="Protect websites from bots and automated abuse with a simple human check." \
    org.opencontainers.image.url="https://github.com/cryMG/gatekeeper" \
    org.opencontainers.image.documentation="https://github.com/cryMG/gatekeeper/blob/main/README.md" \
    org.opencontainers.image.source="https://github.com/cryMG/gatekeeper" \
    org.opencontainers.image.vendor="cryeffect Media Group" \
    org.opencontainers.image.authors="Peter Müller <peter@crycode.de>" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.base.name="docker.io/library/python:3.13-slim" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GATEKEEPER_CONFIG_FILE=/app/config.toml \
    GATEKEEPER_GUNICORN_WORKERS=2 \
    GATEKEEPER_GUNICORN_THREADS=4

RUN groupadd --system gatekeeper \
    && useradd --system --gid gatekeeper --create-home --home-dir /home/gatekeeper gatekeeper \
    && mkdir -p /app \
    && chown gatekeeper:gatekeeper /app

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY app ./app
COPY wsgi.py ./

USER gatekeeper

EXPOSE 5000

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:5000 --workers \"${GATEKEEPER_GUNICORN_WORKERS:-2}\" --threads \"${GATEKEEPER_GUNICORN_THREADS:-4}\" --access-logfile - --error-logfile - wsgi:app"]
