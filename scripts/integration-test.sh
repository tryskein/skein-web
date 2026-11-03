#!/usr/bin/env bash
# Run the BFF's NATS/Redis integration tests in an isolated container stack.
# Usage: ./scripts/integration-test.sh ['FullyQualifiedName~ClassOrMethod'] [dotnet test options]
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_name="skein-web-it-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
result_dir=$(mktemp -d "$repo_root/.integration-results-XXXXXX")
runner_image=${SKEIN_TEST_RUNNER_IMAGE:-mcr.microsoft.com/dotnet/sdk:10.0}
runner_cpus=${SKEIN_TEST_CPUS:-2}
runner_memory=${SKEIN_TEST_MEMORY:-2g}
test_filter=Category=Integration
if (($#)); then
    test_filter+="&($1)"
    shift
fi

cleanup() {
    docker rm -f "$run_name-runner" "$run_name-nats" "$run_name-redis" >/dev/null 2>&1 || true
    docker network rm "$run_name" >/dev/null 2>&1 || true
    rm -rf "$result_dir"
}
trap cleanup EXIT

docker network create "$run_name" >/dev/null
docker run -d --name "$run_name-nats" --network "$run_name" --network-alias nats \
    --user "$(id -u):$(id -g)" --cpus 0.5 --memory 128m \
    nats:2.10-alpine -m 8222 >/dev/null
docker run -d --name "$run_name-redis" --network "$run_name" --network-alias redis \
    --user "$(id -u):$(id -g)" --cpus 0.5 --memory 128m \
    redis:7-alpine redis-server --save '' --appendonly no >/dev/null

docker run --rm --name "$run_name-runner" --network "$run_name" \
    --user "$(id -u):$(id -g)" --cpus "$runner_cpus" --memory "$runner_memory" \
    -e DOTNET_CLI_HOME=/tmp/dotnet -e NUGET_PACKAGES=/tmp/nuget \
    -e TEST_NATS_URL=nats://nats:4222 -e TEST_NATS_MONITOR_URL=http://nats:8222/ \
    -e TEST_REDIS_URL=redis:6379 \
    -v "$repo_root:/work" -w /work "$runner_image" \
    dotnet test src/Tests/SkeinWeb.Tests.csproj --nologo \
    --filter "$test_filter" --logger 'trx;LogFileName=integration.trx' \
    --results-directory "/work/$(basename "$result_dir")" "$@"

python3 - "$result_dir/integration.trx" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
counters = root.find('t:ResultSummary/t:Counters', ns)
if counters is None or int(counters.get('executed', '0')) == 0:
    raise SystemExit('No integration tests executed')
print(f"Integration tests executed: {counters.get('executed')}")
PY
