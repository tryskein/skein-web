#!/usr/bin/env bash
# Turn a running redis:7-alpine container into the Sentinel stand of the integration
# tests and wait until it is ready. The container runs a primary on 6379, a Sentinel
# on 26379 that monitors it as the service "skein", and a replica on 6380 that the
# Sentinel has seen and that is then stopped: the Sentinel still lists it, so a
# client that connects through the Sentinel knows a server that never connects.
# The tests reach it with TEST_REDIS_SENTINEL_URL=<host>:26379,serviceName=skein,abortConnect=false.
# The container needs a writable /tmp and must keep running on its own
# (for example `sh -c 'while :; do sleep 3600; done'`).
# Usage: sentinel-stand.sh <container>
set -euo pipefail

container="${1:?usage: sentinel-stand.sh <container>}"

docker exec -i "$container" sh -c 'cat > /tmp/sentinel-stand.sh' <<'STAND'
set -eu
redis-server --save "" --appendonly no --dir /tmp &
until redis-cli ping >/dev/null 2>&1; do sleep 0.1; done
ip=$(hostname -i | cut -d" " -f1)
redis-server --port 6380 --replicaof "$ip" 6379 --replica-announce-ip "$ip" --save "" --appendonly no --dir /tmp &
# The Sentinel learns the replicas from the primary: start it once the primary shows one.
until redis-cli info replication | grep -q "^slave0:.*state=online"; do sleep 0.1; done
printf "port 26379\ndir /tmp\nsentinel monitor skein %s 6379 1\n" "$ip" > /tmp/sentinel.conf
redis-sentinel /tmp/sentinel.conf &
until redis-cli -p 26379 sentinel replicas skein | grep -q 6380; do sleep 0.2; done
redis-cli -p 6380 shutdown nosave || true
touch /tmp/sentinel-stand.ready
wait
STAND
docker exec -d "$container" sh /tmp/sentinel-stand.sh

for ((attempt = 0; attempt < 300; attempt++)); do
    if docker exec "$container" sh -c \
        'test -e /tmp/sentinel-stand.ready && redis-cli -p 26379 sentinel replicas skein | grep -q 6380 && ! redis-cli -p 6380 ping >/dev/null 2>&1'; then
        exit 0
    fi
    sleep 0.2
done
echo "sentinel stand in $container did not become ready" >&2
exit 1
