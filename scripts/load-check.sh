#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-http://127.0.0.1:8080/}"
REQUESTS="${FYKE_LOAD_REQUESTS:-1000}"
CONCURRENCY="${FYKE_LOAD_CONCURRENCY:-25}"

if [[ ! "$REQUESTS" =~ ^[0-9]+$ || "$REQUESTS" -lt 1 || "$REQUESTS" -gt 10000 ]]; then
  echo "FYKE_LOAD_REQUESTS must be between 1 and 10000." >&2
  exit 1
fi
if [[ ! "$CONCURRENCY" =~ ^[0-9]+$ || "$CONCURRENCY" -lt 1 || "$CONCURRENCY" -gt 100 ]]; then
  echo "FYKE_LOAD_CONCURRENCY must be between 1 and 100." >&2
  exit 1
fi
case "$TARGET" in
  http://127.0.0.1:*|http://localhost:*|https://127.0.0.1:*|https://localhost:*) ;;
  *)
    if [[ "${FYKE_ALLOW_REMOTE_LOAD:-0}" != 1 ]]; then
      echo "Refusing a non-loopback load target. Set FYKE_ALLOW_REMOTE_LOAD=1 only for a host you own." >&2
      exit 1
    fi
    ;;
esac
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }

RESULTS="$(mktemp)"
trap 'rm -f "$RESULTS"' EXIT
START="$(date +%s)"
export TARGET RESULTS
seq 1 "$REQUESTS" | xargs -P "$CONCURRENCY" -n 1 sh -c '
  curl --insecure --silent --show-error --output /dev/null \
    --max-time 10 --write-out "%{http_code} %{time_total}\n" "$TARGET" >>"$RESULTS"
' sh
END="$(date +%s)"

awk -v elapsed="$((END-START))" '
  {codes[$1]++; total+=$2; if($2>max)max=$2; count++}
  END {
    printf "Requests: %d\nElapsed: %ds\nMean latency: %.3fs\nMax latency: %.3fs\n",count,elapsed,total/count,max
    for(code in codes) printf "HTTP %s: %d\n",code,codes[code]
  }
' "$RESULTS"
