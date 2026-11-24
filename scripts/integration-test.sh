#!/usr/bin/env bash
# Run the BFF's NATS/Redis integration tests in an isolated container stack.
set -euo pipefail

usage() {
    printf '%s\n' "Usage: $0 ['FullyQualifiedName~ClassOrMethod']"
}
if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi
if (($# > 1)) || [[ ${1:-} == -* ]]; then
    usage >&2
    exit 2
fi
for dependency in docker python3; do
    command -v "$dependency" >/dev/null || {
        printf 'Missing required command: %s\n' "$dependency" >&2
        exit 1
    }
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_name="skein-web-it-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
mkdir -p "$repo_root/TestResults"
result_dir=$(mktemp -d "$repo_root/TestResults/integration-XXXXXX")
runner_image=${SKEIN_TEST_RUNNER_IMAGE:-mcr.microsoft.com/dotnet/sdk:10.0}
runner_cpus=${SKEIN_TEST_CPUS:-2}
runner_memory=${SKEIN_TEST_MEMORY:-2g}
test_filter=Category=Integration
if (($#)); then
    test_filter+="&($1)"
    shift
fi

cleanup() {
    local result=$?
    docker rm -f "$run_name-runner" "$run_name-nats" "$run_name-redis" "$run_name-sentinel" >/dev/null 2>&1 || true
    docker network rm "$run_name" >/dev/null 2>&1 || true
    if ((result == 0)); then
        rm -rf "$result_dir"
    else
        printf 'Integration results retained in %s\n' "$result_dir" >&2
    fi
}
trap cleanup EXIT

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 50; attempt++)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    printf 'Dependency did not become ready: %s\n' "$*" >&2
    return 1
}

# Every container: no capabilities, no privilege gain through setuid binaries,
# and a process limit, so a runaway test cannot exhaust the host's process
# table. NATS and Redis keep no state here and get a read-only root.
hardening=(--cap-drop ALL --security-opt no-new-privileges)

docker network create "$run_name" >/dev/null
docker run -d --name "$run_name-nats" --network "$run_name" --network-alias nats \
    --user "$(id -u):$(id -g)" --cpus 0.5 --memory 128m \
    "${hardening[@]}" --pids-limit 128 --read-only \
    nats:2.10-alpine -m 8222 >/dev/null
docker run -d --name "$run_name-redis" --network "$run_name" --network-alias redis \
    --user "$(id -u):$(id -g)" --cpus 0.5 --memory 128m \
    "${hardening[@]}" --pids-limit 128 --read-only \
    redis:7-alpine redis-server --save '' --appendonly no >/dev/null
# Its own primary, a Sentinel that names it (service "skein") and a replica the
# Sentinel still lists after it went down: the start of the application with
# REDIS_URL pointing at Sentinel.
docker run -d --name "$run_name-sentinel" --network "$run_name" --network-alias sentinel \
    --user "$(id -u):$(id -g)" --cpus 0.5 --memory 128m \
    "${hardening[@]}" --pids-limit 128 --read-only --tmpfs /tmp \
    redis:7-alpine sh -c 'redis-server --save "" --appendonly no --dir /tmp & until redis-cli ping >/dev/null 2>&1; do sleep 0.1; done; ip=$(hostname -i | cut -d" " -f1); redis-server --port 6380 --replicaof "$ip" 6379 --replica-announce-ip "$ip" --save "" --appendonly no --dir /tmp & printf "port 26379\ndir /tmp\nsentinel monitor skein %s 6379 1\n" "$ip" > /tmp/sentinel.conf; redis-sentinel /tmp/sentinel.conf & until redis-cli -p 26379 sentinel replicas skein | grep -q 6380; do sleep 0.2; done; redis-cli -p 6380 shutdown nosave; wait' >/dev/null
wait_for docker exec "$run_name-redis" redis-cli ping
wait_for docker exec "$run_name-sentinel" sh -c 'redis-cli -p 26379 sentinel replicas skein | grep -q 6380 && ! redis-cli -p 6380 ping >/dev/null 2>&1'
wait_for docker exec "$run_name-nats" wget -q -O /dev/null http://127.0.0.1:8222/healthz

docker run --rm --name "$run_name-runner" --network "$run_name" \
    --user "$(id -u):$(id -g)" --cpus "$runner_cpus" --memory "$runner_memory" \
    "${hardening[@]}" --pids-limit 2048 \
    -e HOME=/tmp -e DOTNET_CLI_HOME=/tmp -e NUGET_PACKAGES=/tmp/nuget \
    -e TEST_NATS_URL=nats://nats:4222 -e TEST_NATS_MONITOR_URL=http://nats:8222/ \
    -e TEST_REDIS_URL=redis:6379 -e TEST_REDIS_SENTINEL_URL=sentinel:26379,serviceName=skein,abortConnect=false \
    -v "$repo_root:/work:ro" -v "$result_dir:/results" -w /work "$runner_image" \
    dotnet test src/Tests/SkeinWeb.Tests.csproj --nologo \
    --filter "$test_filter" --logger 'trx;LogFileName=integration.trx' \
    --artifacts-path /tmp/artifacts --results-directory /results

python3 - "$result_dir/integration.trx" <<'PY'
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

report = Path(sys.argv[1])
if not report.is_file():
    raise SystemExit('Integration runner did not produce a TRX report')
root = ET.parse(report).getroot()
ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
counters = root.find('t:ResultSummary/t:Counters', ns)
if counters is None or int(counters.get('executed', '0')) == 0:
    raise SystemExit('No integration tests executed')
print(f"Integration tests executed: {counters.get('executed')}; total: {counters.get('total')}; skipped: {counters.get('notExecuted')}")
PY
