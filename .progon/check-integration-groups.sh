#!/usr/bin/env bash
# Reads the TRX report of the integration run made before the mutation run and fails the step (so Stryker
# does not start) when the run cannot be trusted as a baseline:
#   - the report has no results at all;
#   - a required group did not run (no result), or fell out of the selection (the class is absent):
#     both are an error, and are told apart in the message;
#   - the selected set has skipped tests (outcome NotExecuted).
# Usage: check-integration-groups.sh <report.trx>
set -euo pipefail

report="${1:?usage: check-integration-groups.sh <report.trx>}"
[ -s "$report" ] || { echo "check: report $report is missing or empty" >&2; exit 1; }

# Test classes that own integration rows of the test plan (the "Where" column of tests.md). A file that has
# both levels is counted by its integration methods only, because the run selects Category=Integration.
required=(
  SessionHandlerCharacterizationTest
  InsecureHttpStartupTest
  SessionStoreFailureMiddlewareTest
  SwaggerEarlyFailureDocumentationTest
  StandardStartupIntegrationTest
  SessionPipelineIntegrationTest
  RedisTicketStoreTest
  UserChangedSubscriberIntegrationTests
  SessionIssuerTest
  SessionStoreMigrationTest
  SessionRevocationAcrossReplicasIntegrationTest
  SessionLogRedactionTest
  EdgePipelineTest
  AccountRoutesPipelineTest
  SessionSurfacesTest
  PasswordResetSessionTest
  OidcCallbackSessionIntegrationTest
  SsoSessionIntegrationTest
)

# One line per result: "<outcome> <fully qualified test name>".
results="$(grep -o '<UnitTestResult [^>]*>' "$report" \
  | sed -n 's/.*testName="\([^"]*\)".*outcome="\([^"]*\)".*/\2 \1/p' || true)"

total="$(printf '%s' "$results" | grep -c . || true)"
if [ "$total" -eq 0 ]; then
  echo "check: the report holds no test result" >&2
  exit 1
fi

status=0

skipped="$(printf '%s\n' "$results" | grep '^NotExecuted ' || true)"
if [ -n "$skipped" ]; then
  echo "check: skipped tests in the selected set:" >&2
  printf '%s\n' "$skipped" | sed 's/^NotExecuted /  /' | head -50 >&2
  status=1
fi

for group in "${required[@]}"; do
  executed="$(printf '%s\n' "$results" | grep -v '^NotExecuted ' | grep -c "\.${group}\." || true)"
  if [ "$executed" -gt 0 ]; then
    continue
  fi
  if printf '%s\n' "$results" | grep -q "\.${group}\."; then
    echo "check: group $group is in the report but nothing of it ran (all skipped)" >&2
  else
    echo "check: group $group is absent from the report (fell out of the selection)" >&2
  fi
  status=1
done

if [ "$status" -ne 0 ]; then
  exit 1
fi
echo "check: ${total} results, all ${#required[@]} required groups ran, no skipped tests"
