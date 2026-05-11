#!/bin/bash
# Drop-in wrapper: translates the original update-blacklist.sh calling convention
# to the Python implementation.  Existing cron jobs keep working unchanged:
#   /usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
#
# The Python script is the real implementation; this just maps the positional
# conf-file argument to --conf.

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PY_SCRIPT="${SCRIPT_DIR}/update_blacklist.py"

if [ ! -x "$PY_SCRIPT" ]; then
    echo "Error: $PY_SCRIPT not found or not executable" >&2
    exit 1
fi

CONF="${1:-}"
shift || true

if [ -z "$CONF" ]; then
    echo "Usage: $(basename "$0") <conf-file> [extra-args...]" >&2
    exit 1
fi

exec "$PY_SCRIPT" --conf "$CONF" --apply --ipv4-only --force --quiet "$@"
