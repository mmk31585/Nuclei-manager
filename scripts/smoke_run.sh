#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required"; exit 2; }

BASE="${BASE:-http://127.0.0.1:8080}"
# LAB target: use Juice Shop container IP
if [[ "${LAB:-}" == "" ]]; then
  if [[ "$BASE" == http://127.0.0.1* ]] || [[ "$BASE" == http://localhost* ]]; then
    # Get Juice Shop container IP from docker network
    LAB="http://$(docker inspect scanner-juiceshop-1 --format '{{.NetworkSettings.Networks.scanner_scanner-network.IPAddress}}' 2>/dev/null || echo "172.20.0.3"):3000"
  else
    LAB="http://127.0.0.1:3000"
  fi
fi
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
expect() { # expect <label> <jq-boolean-expression>   (runs against $RUN_JSON)
  if jq -e "$2" <<<"$RUN_JSON" >/dev/null; then echo "PASS $1"; else echo "FAIL $1: $RUN_JSON"; FAILED=1; fi
}
wait_terminal() { # wait_terminal <run-id>  -> sets STATUS
  STATUS=""
  for _ in $(seq 1 90); do
    call GET "/api/v1/runs/$1"
    STATUS="$(jq -r .status "$TMP")"
    case "$STATUS" in completed|failed|timed_out|stopped|cancelled) return 0 ;; esac
    sleep 2
  done
}

# Check reachability using 127.0.0.1:3000 (host port mapping)
LAB_CHECK="${LAB_CHECK:-http://127.0.0.1:3000}"
for _ in $(seq 1 30); do curl -sf -o /dev/null "$LAB_CHECK" && break; sleep 1; done
curl -sf -o /dev/null "$LAB_CHECK" || { echo "lab target $LAB_CHECK is not reachable (run: make lab-up)"; exit 2; }

SUFFIX="$$-$RANDOM"

# scope: 127.0.0.1 and Juice Shop container IP
SCOPE_CREATED=0
call POST /api/v1/scope '{"kind":"ip","value":"127.0.0.1"}'
if [[ "$CODE" == "201" ]]; then
  SCOPE_ID="$(jq -r .id "$TMP")"; SCOPE_CREATED=1; echo "PASS create scope 127.0.0.1"
else
  call GET /api/v1/scope
  SCOPE_ID="$(jq -r '.[] | select(.value=="127.0.0.1") | .id' "$TMP")"
fi
# Add Juice Shop container IP to scope
JUICESHOP_IP=$(docker inspect scanner-juiceshop-1 --format '{{.NetworkSettings.Networks.scanner_scanner-network.IPAddress}}' 2>/dev/null || echo "172.20.0.3")
call POST /api/v1/scope "{\"kind\":\"ip\",\"value\":\"$JUICESHOP_IP\"}"
if [[ "$CODE" == "201" ]]; then
  echo "PASS create scope $JUICESHOP_IP"
else
  echo "PASS scope $JUICESHOP_IP already exists"
fi

call POST /api/v1/targets "{\"name\":\"smoke-run-$SUFFIX\",\"hosts\":[\"$LAB\"]}";  check 201 "create target"
TARGET_ID="$(jq -r .id "$TMP")"
call POST /api/v1/profiles "{\"name\":\"smoke-run-$SUFFIX\",\"custom_set\":\"smoke\",\"rate_limit\":20,\"max_duration_min\":5}"; check 201 "create profile"
PROFILE_ID="$(jq -r .id "$TMP")"
call POST /api/v1/tasks "{\"name\":\"smoke-run-$SUFFIX\",\"target_id\":$TARGET_ID,\"profile_id\":$PROFILE_ID,\"min_severity\":\"info\"}"; check 201 "create task"
TASK_ID="$(jq -r .id "$TMP")"

call POST "/api/v1/tasks/$TASK_ID/run";  check 202 "start run"
RUN_ID="$(jq -r .id "$TMP")"
call POST "/api/v1/tasks/$TASK_ID/run";  check 409 "second run while active is rejected"

wait_terminal "$RUN_ID"
call GET "/api/v1/runs/$RUN_ID"; RUN_JSON="$(cat "$TMP")"
if [[ "$STATUS" != "completed" ]]; then
  echo "run ended as '$STATUS'; log:"; call GET "/api/v1/runs/$RUN_ID/log"; jq -r .data "$TMP"
fi
expect "run completed"          '.status == "completed"'
expect "exit code 0"            '.exit_code == 0'
expect "smoke finding counted"  '.results_total >= 1 and .findings_medium >= 1'
expect "nuclei version stored"  '.nuclei_version != ""'
expect "command line stored"    '(.command_line | contains("-jsonl"))'
expect "no parse errors"        '.parse_errors == 0'

call GET "/api/v1/runs/$RUN_ID/output"; check 200 "download output"
grep -q sm-smoke-homepage "$TMP" && echo "PASS output contains the smoke result" || { echo "FAIL output lacks the smoke result"; FAILED=1; }
call GET "/api/v1/runs/$RUN_ID/log";    check 200 "read log"
call GET "/api/v1/runs?task_id=$TASK_ID"; check 200 "list runs"

# stop: accept any valid outcome (the run may already be finished), then it must reach a terminal state
call POST "/api/v1/tasks/$TASK_ID/run";  check 202 "start second run"
RUN2="$(jq -r .id "$TMP")"
call POST "/api/v1/runs/$RUN2/stop"
case "$CODE" in 200|202|409) echo "PASS stop request answered ($CODE)" ;; *) echo "FAIL stop returned $CODE: $(cat "$TMP")"; FAILED=1 ;; esac
wait_terminal "$RUN2"
case "$STATUS" in cancelled|stopped|completed) echo "PASS second run ended as $STATUS" ;; *) echo "FAIL second run ended as $STATUS"; FAILED=1 ;; esac

# scope re-check at run creation (only when this script created the scope entry)
if [[ "$SCOPE_CREATED" == "1" ]]; then
  call DELETE "/api/v1/scope/$SCOPE_ID"; check 204 "delete scope"
  call POST "/api/v1/tasks/$TASK_ID/run"; check 422 "run rejected when target left the scope"
else
  echo "SKIP scope re-check (scope entry existed before this script)"
fi

call DELETE "/api/v1/tasks/$TASK_ID";      check 204 "delete task"
call DELETE "/api/v1/profiles/$PROFILE_ID"; check 204 "delete profile"
call DELETE "/api/v1/targets/$TARGET_ID";  check 204 "delete target"
exit "$FAILED"