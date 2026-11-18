#!/usr/bin/env bash
# Reads the TRX report of the integration run made before the mutation run and fails the step (so Stryker
# does not start) when the run cannot be trusted as a baseline:
#   - the report is incomplete (no closing </TestRun>, no completed summary) or its Counters disagree with
#     the results it lists;
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

# The report is a single XML document in the TRX namespace; work on it as one line of text so a tag is one
# match whatever the line breaks and the order of its attributes are.
xml="$(tr '\n\r' '  ' < "$report")"

case "$xml" in
  *'</TestRun>'*) ;;
  *) echo "check: the report is truncated (no closing </TestRun>)" >&2; exit 1 ;;
esac

summary="$(printf '%s' "$xml" | grep -o '<ResultSummary [^>]*>' | head -1 || true)"
if [ -z "$summary" ]; then
  echo "check: the report has no result summary" >&2
  exit 1
fi
counters="$(printf '%s' "$xml" | grep -o '<Counters [^>]*>' | head -1 || true)"
if [ -z "$counters" ]; then
  echo "check: the report has no counters" >&2
  exit 1
fi
counter() { printf '%s' "$counters" | sed -n "s/.* $1=\"\([0-9]*\)\".*/\1/p"; }

# One line per result record, from the record's own attributes: "<outcome> <fully qualified test name>".
results=""
while IFS= read -r tag; do
  name="$(printf '%s' "$tag" | sed -n 's/.* testName="\([^"]*\)".*/\1/p')"
  outcome="$(printf '%s' "$tag" | sed -n 's/.* outcome="\([^"]*\)".*/\1/p')"
  if [ -z "$name" ] || [ -z "$outcome" ]; then
    echo "check: a result record has no test name or outcome: ${tag:0:200}" >&2
    exit 1
  fi
  results+="${outcome} ${name}"$'\n'
done < <(printf '%s' "$xml" | grep -o '<UnitTestResult [^>]*>' || true)

total="$(printf '%s' "$results" | grep -c . || true)"
if [ "$total" -eq 0 ]; then
  echo "check: the report holds no test result" >&2
  exit 1
fi

count_outcome() { printf '%s' "$results" | grep -c "^$1 " || true; }
skipped_count="$(count_outcome NotExecuted)"
passed_count="$(count_outcome Passed)"
failed_count="$(count_outcome Failed)"

status=0
if [ "$(counter total)" != "$total" ] \
  || [ "$(counter notExecuted)" != "$skipped_count" ] \
  || [ "$(counter passed)" != "$passed_count" ] \
  || [ "$(counter failed)" != "$failed_count" ]; then
  echo "check: the counters disagree with the records: counters total=$(counter total) passed=$(counter passed)" \
    "failed=$(counter failed) notExecuted=$(counter notExecuted); records total=$total passed=$passed_count" \
    "failed=$failed_count notExecuted=$skipped_count" >&2
  status=1
fi

if [ "$failed_count" -ne 0 ]; then
  echo "check: failed tests in the baseline run: $failed_count" >&2
  status=1
fi

if [ "$skipped_count" -ne 0 ]; then
  echo "check: skipped tests in the selected set:" >&2
  printf '%s' "$results" | grep '^NotExecuted ' | sed 's/^NotExecuted /  /' | head -50 >&2
  status=1
fi

for group in "${required[@]}"; do
  executed="$(printf '%s' "$results" | grep -v '^NotExecuted ' | grep -c "\.${group}\." || true)"
  if [ "$executed" -gt 0 ]; then
    continue
  fi
  if printf '%s' "$results" | grep -q "\.${group}\."; then
    echo "check: group $group is in the report but nothing of it ran (all skipped)" >&2
  else
    echo "check: group $group is absent from the report (fell out of the selection)" >&2
  fi
  status=1
done

if [ "$status" -ne 0 ]; then
  exit 1
fi
echo "check: ${total} results, counters agree, all ${#required[@]} required groups ran, no skipped tests"
