#!/usr/bin/env bash
case "${FAKE_MODE:-ok}" in
  ok)
    echo '{"template-id":"sm-a","info":{"name":"A","severity":"critical","tags":"cve,test","classification":{"cve-id":["CVE-2021-0001"]}},"host":"http://x","matched-at":"http://x/a","timestamp":"2026-01-01T00:00:00Z"}'
    echo '{"template-id":"sm-b","info":{"name":"B","severity":"medium","tags":["x"],"classification":{"cve-id":"CVE-2021-0002"}},"host":"http://x","matched-at":"http://x/b"}'
    echo '{"template-id":"sm-c","info":{"name":"C","severity":"weird"},"host":"http://x","matched-at":"http://x/c"}'
    echo 'this is not json'
    echo '{"broken":'
    echo '[INF] some log line' >&2
    exit 0 ;;
  exit3)
    echo '{"template-id":"sm-a","info":{"name":"A","severity":"low"},"host":"h","matched-at":"h"}'
    exit 3 ;;
  big)
    head -c 3000000 /dev/zero | tr '\0' 'x'; echo
    echo '{"template-id":"sm-after","info":{"name":"After","severity":"high"},"host":"h","matched-at":"h"}'
    exit 0 ;;
  hang)
    trap '' TERM            # ignore SIGTERM: forces the forced-kill path
    echo $$ > "${FAKE_PIDFILE:?}.main"
    sleep 300 &
    echo $! > "${FAKE_PIDFILE:?}"
    echo '{"template-id":"sm-h","info":{"name":"H","severity":"low"},"host":"h","matched-at":"h"}'
    wait ;;
esac