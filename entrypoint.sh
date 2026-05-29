#!/bin/sh
# Entrypoint script for the cryKeeper container.
# It prepares the Prometheus multiprocess state directory and then execs
# Gunicorn with the appropriate configuration.
set -eu

# Prepare Prometheus multiprocess state before handing control to Gunicorn.
prom_dir="${CRYKEEPER_PROMETHEUS_MULTIPROC_DIR:-/tmp/crykeeper-prometheus}"

if [ -z "$prom_dir" ] || [ "$prom_dir" = "/" ]; then
  echo "CRYKEEPER_PROMETHEUS_MULTIPROC_DIR must not be empty or '/'." >&2
  exit 1
fi

mkdir -p "$prom_dir"
rm -rf "${prom_dir:?}"/* "${prom_dir:?}"/.[!.]* "${prom_dir:?}"/..?*
export PROMETHEUS_MULTIPROC_DIR="$prom_dir"

if [ "$#" -eq 0 ]; then
  set -- \
    gunicorn \
    --config gunicorn.conf.py \
    --bind 0.0.0.0:5000 \
    --workers "${CRYKEEPER_GUNICORN_WORKERS:-2}" \
    --threads "${CRYKEEPER_GUNICORN_THREADS:-4}" \
    --access-logfile - \
    --error-logfile - \
    wsgi:app
fi

exec "$@"