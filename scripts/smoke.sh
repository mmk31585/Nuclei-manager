#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required"; exit 2; }

BASE="${BASE:-http://127.0.0.1:8080}"
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

SUFFIX="$$-$RANDOM"
DOMAIN="smoke-$SUFFIX.example.test"

call GET /healthz;                                                    check 200 "healthz"
call POST /api/v1/scope "{\"kind\":\"domain\",\"value\":\"$DOMAIN\"}"; check 201 "create scope"
SCOPE_ID="$(jq -r .id "$TMP")"

call POST /api/v1/targets "{\"name\":\"smoke-$SUFFIX\",\"hosts\":[\"https://app.$DOMAIN\"]}"; check 201 "create target in scope"
TARGET_ID="$(jq -r .id "$TMP")"
call POST /api/v1/targets "{\"name\":\"smoke-bad-$SUFFIX\",\"hosts\":[\"https://evil.invalid\"]}"; check 422 "reject target outside scope"
call POST /api/v1/targets "{\"name\":\"\",\"hosts\":[\"https://app.$DOMAIN\"]}";                  check 400 "reject empty name"
call GET /api/v1/targets;                                             check 200 "list targets"

call GET /api/v1/profiles;                                            check 200 "list profiles"
PROFILE_ID="$(jq -r '.[] | select(.name=="quick") | .id' "$TMP")"
[[ -n "$PROFILE_ID" ]] || { echo "FAIL quick profile not seeded"; exit 1; }

call POST /api/v1/tasks "{\"name\":\"smoke-task-$SUFFIX\",\"target_id\":$TARGET_ID,\"profile_id\":$PROFILE_ID}"; check 201 "create task"
TASK_ID="$(jq -r .id "$TMP")"
call POST /api/v1/tasks "{\"name\":\"smoke-task-bad-$SUFFIX\",\"target_id\":999999,\"profile_id\":$PROFILE_ID}"; check 400 "reject unknown target_id"
call DELETE "/api/v1/targets/$TARGET_ID";                             check 409 "target in use cannot be deleted"
call DELETE "/api/v1/profiles/$PROFILE_ID";                           check 409 "builtin profile cannot be deleted"

call DELETE "/api/v1/tasks/$TASK_ID";                                 check 204 "delete task"
call DELETE "/api/v1/targets/$TARGET_ID";                             check 204 "delete target"
call DELETE "/api/v1/scope/$SCOPE_ID";                                check 204 "delete scope"

exit "$FAILED"
