FROM python:3.14-slim

ARG VERSION=dev
ARG VCS_REF=
ARG BUILD_DATE=

LABEL org.opencontainers.image.title="cryKeeper" \
    org.opencontainers.image.description="The open-source human verification service for Nginx making bots cry" \
    org.opencontainers.image.url="https://github.com/cryMG/cryKeeper" \
    org.opencontainers.image.documentation="https://github.com/cryMG/cryKeeper/blob/main/README.md" \
    org.opencontainers.image.source="https://github.com/cryMG/cryKeeper" \
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
    CRYKEEPER_CONFIG_FILE=/app/config.toml \
    CRYKEEPER_GUNICORN_WORKERS=2 \
    CRYKEEPER_GUNICORN_THREADS=4

RUN groupadd --system crykeeper \
    && useradd --system --gid crykeeper --create-home --home-dir /home/crykeeper crykeeper \
    && mkdir -p /app \
    && chown crykeeper:crykeeper /app

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY app ./app
COPY wsgi.py ./

USER crykeeper

EXPOSE 5000

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:5000 --workers \"${CRYKEEPER_GUNICORN_WORKERS:-2}\" --threads \"${CRYKEEPER_GUNICORN_THREADS:-4}\" --access-logfile - --error-logfile - wsgi:app"]
