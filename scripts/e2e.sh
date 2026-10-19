#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required"; exit 2; }

BASE="${BASE:-http://127.0.0.1:8080}"
LAB="${LAB:-http://127.0.0.1:3000}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
FAILED=0
CODE=""

call() { # call <method> <path> [json]
  local args=(-s -o "$TMP" -w '%{http_code}' -X "$1" "$BASE$2")
  if [[ -n "${3:-}" ]]; then args+=(-H 'Content-Type: application/json' -d "$3"); fi
  CODE="$(curl "${args[@]}")"
}
check() { # check <want-status> <label>
  if [[ "$CODE" == "$1" ]]; then echo "PASS $2"; else echo "FAIL $2: got $CODE want $1: $(cat "$TMP")"; FAILED=1; fi
}
expect() { # expect <label> <jq-boolean-expression> (against $RUN_JSON)
  if jq -e "$2" <<<"$RUN_JSON" >/dev/null; then echo "PASS $1"; else echo "FAIL $1: $RUN_JSON"; FAILED=1; fi
}
wait_terminal() { # wait_terminal <run-id>
  STATUS=""
  for _ in $(seq 1 90); do
    call GET "/api/v1/runs/$1"
    STATUS="$(jq -r .status "$TMP")"
    case "$STATUS" in completed|failed|timed_out|stopped|cancelled) return 0 ;; esac
    sleep 2
  done
}

echo "== health & docs =="
call GET /healthz; check 200 "healthz"
call GET /swagger/index.html; check 200 "swagger ui"
call GET /swagger/doc.json; check 200 "swagger json"

echo "== scope =="
call POST /api/v1/scope '{"kind":"ip","value":"127.0.0.1"}'
if [[ "$CODE" == "201" ]]; then SCOPE_ID="$(jq -r .id "$TMP")"; SCOPE_CREATED=1; echo "PASS create scope"; else
  call GET /api/v1/scope; SCOPE_ID="$(jq -r '.[] | select(.value=="127.0.0.1") | .id' "$TMP")"; SCOPE_CREATED=0; echo "PASS reuse scope"
fi
call POST /api/v1/scope '{"kind":"ip","value":"127.0.0.1"}'; check 409 "duplicate scope rejected"
call POST /api/v1/scope '{"kind":"bogus","value":"x"}'; check 400 "invalid scope kind"
call GET /api/v1/scope; check 200 "list scope"

echo "== targets =="
SUFFIX="e2e-$RANDOM"
call POST /api/v1/targets "{\"name\":\"e2e-$SUFFIX\",\"hosts\":[\"$LAB\"]}"; check 201 "create target"
TARGET_ID="$(jq -r .id "$TMP")"
call POST /api/v1/targets "{\"name\":\"e2e-bad-$SUFFIX\",\"hosts\":[\"https://evil.invalid\"]}"; check 422 "reject target outside scope"
call POST /api/v1/targets "{\"name\":\"\",\"hosts\":[\"$LAB\"]}"; check 400 "reject empty name"
call POST /api/v1/targets '{"name":"x","hosts":[]}'; check 400 "reject empty hosts"
call GET "/api/v1/targets/$TARGET_ID"; check 200 "get target"
call GET /api/v1/targets; check 200 "list targets"
call GET /api/v1/targets/999999; check 404 "get unknown target"

echo "== profiles =="
call GET /api/v1/profiles; check 200 "list profiles"
PROFILE_ID="$(jq -r '.[] | select(.name=="quick") | .id' "$TMP")"
[[ -n "$PROFILE_ID" ]] || { echo "FAIL quick profile not seeded"; FAILED=1; }
call POST /api/v1/profiles "{\"name\":\"e2e-$SUFFIX\",\"custom_set\":\"smoke\",\"rate_limit\":20}"; check 201 "create profile"
CUSTOM_PROFILE_ID="$(jq -r .id "$TMP")"
call DELETE "/api/v1/profiles/$PROFILE_ID"; check 409 "builtin profile cannot be deleted"
call GET "/api/v1/profiles/$PROFILE_ID"; check 200 "get profile"

echo "== tasks =="
call POST /api/v1/tasks "{\"name\":\"e2e-$SUFFIX\",\"target_id\":$TARGET_ID,\"profile_id\":$CUSTOM_PROFILE_ID,\"min_severity\":\"info\"}"; check 201 "create task"
TASK_ID="$(jq -r .id "$TMP")"
call POST /api/v1/tasks "{\"name\":\"e2e-bad-$SUFFIX\",\"target_id\":999999,\"profile_id\":$CUSTOM_PROFILE_ID}"; check 400 "reject unknown target_id"
call POST /api/v1/tasks "{\"name\":\"e2e-bad2-$SUFFIX\",\"target_id\":$TARGET_ID,\"profile_id\":999999}"; check 400 "reject unknown profile_id"
call GET "/api/v1/tasks/$TASK_ID"; check 200 "get task"
call PUT "/api/v1/tasks/$TASK_ID" "{\"name\":\"e2e-$SUFFIX-upd\",\"target_id\":$TARGET_ID,\"profile_id\":$CUSTOM_PROFILE_ID,\"min_severity\":\"info\"}"; check 200 "update task"
call GET /api/v1/tasks; check 200 "list tasks"
call DELETE "/api/v1/targets/$TARGET_ID"; check 409 "target in use cannot be deleted"

echo "== runs =="
call POST "/api/v1/tasks/$TASK_ID/run"; check 202 "start run"
RUN_ID="$(jq -r .id "$TMP")"
call POST "/api/v1/tasks/$TASK_ID/run"; check 409 "second run while active rejected"
wait_terminal "$RUN_ID"
call GET "/api/v1/runs/$RUN_ID"; RUN_JSON="$(cat "$TMP")"
expect "run completed"          '.status == "completed"'
expect "exit code 0"            '.exit_code == 0'
expect "finding counted"        '.results_total >= 1 and .findings_medium >= 1'
expect "nuclei version stored"  '.nuclei_version != ""'
expect "command line stored"    '(.command_line | contains("-jsonl"))'
expect "no parse errors"        '.parse_errors == 0'
call GET "/api/v1/runs/$RUN_ID/output"; check 200 "download output"
grep -q sm-smoke-homepage "$TMP" && echo "PASS output contains smoke result" || { echo "FAIL output lacks smoke result"; FAILED=1; }
call GET "/api/v1/runs/$RUN_ID/log"; check 200 "read log"
call GET "/api/v1/runs?task_id=$TASK_ID"; check 200 "list runs by task"
call GET "/api/v1/runs?status=completed"; check 200 "list runs by status"
call GET "/api/v1/runs?limit=5"; check 200 "list runs limit"

echo "== stop =="
call POST "/api/v1/tasks/$TASK_ID/run"; check 202 "start second run"
RUN2="$(jq -r .id "$TMP")"
call POST "/api/v1/runs/$RUN2/stop"
case "$CODE" in 200|202) echo "PASS stop request ($CODE)" ;; *) echo "FAIL stop returned $CODE: $(cat "$TMP")"; FAILED=1 ;; esac
wait_terminal "$RUN2"
case "$STATUS" in cancelled|stopped|completed) echo "PASS second run ended as $STATUS" ;; *) echo "FAIL second run ended as $STATUS"; FAILED=1 ;; esac

echo "== scope re-check =="
if [[ "$SCOPE_CREATED" == "1" ]]; then
  call DELETE "/api/v1/scope/$SCOPE_ID"; check 204 "delete scope"
  call POST "/api/v1/tasks/$TASK_ID/run"; check 422 "run rejected when target left scope"
else
  echo "SKIP scope re-check"
fi

echo "== cleanup =="
call DELETE "/api/v1/tasks/$TASK_ID"; check 204 "delete task"
call DELETE "/api/v1/profiles/$CUSTOM_PROFILE_ID"; check 204 "delete custom profile"
call DELETE "/api/v1/targets/$TARGET_ID"; check 204 "delete target"
if [[ "$SCOPE_CREATED" == "1" ]]; then
  call POST /api/v1/scope '{"kind":"ip","value":"127.0.0.1"}'; check 201 "recreate scope"
  SCOPE_ID="$(jq -r .id "$TMP")"
  call DELETE "/api/v1/scope/$SCOPE_ID"; check 204 "delete scope"
fi

echo "== error cases =="
call GET /api/v1/runs/999999; check 404 "unknown run"
call POST /api/v1/runs/999999/stop; check 404 "stop unknown run"
call GET /api/v1/tasks/999999; check 404 "unknown task"
call DELETE /api/v1/tasks/999999; check 404 "delete unknown task"

exit "$FAILED"
