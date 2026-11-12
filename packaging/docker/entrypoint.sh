#!/bin/sh
# Runs actp as the "node" user, renumbered to PUID/PGID so files in mounted
# folders keep their owner. PUID=0 runs as root.
set -e
PUID=${PUID:-1000}
PGID=${PGID:-1000}
if [ "$(id -u)" = "0" ] && [ "$PUID" != "0" ]; then
  [ "$(id -g node)" = "$PGID" ] || groupmod -o -g "$PGID" node
  [ "$(id -u node)" = "$PUID" ] || usermod -o -u "$PUID" node
  mkdir -p /data
  [ "$(stat -c %u /data)" = "$PUID" ] || chown -R node:node /data
  exec gosu node "$@"
fi
exec "$@"
