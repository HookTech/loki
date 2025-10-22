#!/usr/bin/env bash

set -euo pipefail

# Loki health check script using curl
# - Checks readiness, metrics, labels, build info, series and a sample query
# - Supports optional Bearer token and X-Scope-OrgID for multi-tenant Loki

DEFAULT_URL="https://loki.aicoding.sh"
URL="${LOKI_URL:-$DEFAULT_URL}"
TOKEN="${LOKI_TOKEN:-}"
ORG_ID="${LOKI_ORG_ID:-${TENANT_ID:-}}"
INSECURE=0
VERBOSE=0
TIME_RANGE_MINUTES=${TIME_RANGE_MINUTES:-5}
# Retry strategy
RETRIES=${RETRIES:-3}
RETRY_DELAY=${RETRY_DELAY:-2}
DOCKER_JOB_LABEL=${DOCKER_JOB_LABEL:-docker}

usage() {
  cat <<EOF
Loki health checker

Usage: $(basename "$0") [options]

Options:
  -u, --url URL           Loki base URL (default: $DEFAULT_URL or env LOKI_URL)
  -t, --token TOKEN       Bearer token for Authorization (or env LOKI_TOKEN)
  -o, --org-id ID         X-Scope-OrgID / tenant ID (or env LOKI_ORG_ID)
  -k, --insecure          Allow insecure TLS (curl -k)
  -v, --verbose           Print brief body on failures
  -r, --retries N         Retry failed requests N times (default: ${RETRIES})
  -d, --retry-delay SEC   Initial retry delay seconds (default: ${RETRY_DELAY})
  -J, --docker-job NAME   Expected docker job label value (default: ${DOCKER_JOB_LABEL})
  -h, --help              Show this help

Environment:
  LOKI_URL, LOKI_TOKEN, LOKI_ORG_ID (or TENANT_ID), TIME_RANGE_MINUTES

Exit code:
  0 if all critical checks pass; non-zero otherwise.
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) URL="$2"; shift 2;;
    -t|--token) TOKEN="$2"; shift 2;;
    -o|--org-id|--tenant|--org) ORG_ID="$2"; shift 2;;
    -k|--insecure) INSECURE=1; shift;;
    -v|--verbose) VERBOSE=1; shift;;
    -r|--retries) RETRIES="$2"; shift 2;;
    -d|--retry-delay) RETRY_DELAY="$2"; shift 2;;
    -J|--docker-job) DOCKER_JOB_LABEL="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

if [[ -z "$URL" ]]; then
  URL="$DEFAULT_URL"
fi

# Build curl base options
CURL_OPTS=(--silent --show-error --location --max-redirs 3 --connect-timeout 10 --max-time 30)
if [[ "$INSECURE" -eq 1 ]]; then
  CURL_OPTS+=(--insecure)
fi

:

trim() { sed -E 's/^\s+|\s+$//g'; }

http_get() {
  # args: path accept tmpfile
  local path="$1"; shift
  local accept="$1"; shift
  local tmp="$1"; shift

  local full_url
  # ensure single slash join
  full_url="${URL%/}${path}"

  local attempt=1
  local delay="$RETRY_DELAY"
  local m code

  while :; do
    m=$(curl "${CURL_OPTS[@]}" \
      -H "Accept: ${accept}" \
      ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
      ${ORG_ID:+-H "X-Scope-OrgID: $ORG_ID"} \
      -w $'http_code=%{http_code}\nnamelookup=%{time_namelookup}\nconnect=%{time_connect}\nappconnect=%{time_appconnect}\nstarttransfer=%{time_starttransfer}\ntotal=%{time_total}\nsize=%{size_download}\ncontent_type=%{content_type}\n' \
      -o "$tmp" \
      "$full_url" 2>&1)

    # curl mixes stderr in m; extract http_code line last occurrence
    code=$(echo "$m" | awk -F= '/^http_code=/{c=$2} END{print c}')
    [[ -z "$code" ]] && code="000"

    # Success or non-retriable codes (<500 and not 000) break
    if [[ "$code" != "000" && ! "$code" =~ ^5 ]]; then
      echo "$m"
      return 0
    fi

    if (( attempt >= RETRIES )); then
      echo "$m"
      return 0
    fi

    sleep "$delay"
    attempt=$((attempt+1))
    # exponential backoff, cap at 30s
    delay=$(( delay < 30 ? delay * 2 : 30 ))
  done
}

print_metric_line() {
  # args: metrics_string
  local m="$1"
  local code total connect appconnect starttransfer namelookup size ctype
  code=$(echo "$m" | awk -F= '/^http_code=/{print $2}')
  total=$(echo "$m" | awk -F= '/^total=/{print $2}')
  connect=$(echo "$m" | awk -F= '/^connect=/{print $2}')
  appconnect=$(echo "$m" | awk -F= '/^appconnect=/{print $2}')
  starttransfer=$(echo "$m" | awk -F= '/^starttransfer=/{print $2}')
  namelookup=$(echo "$m" | awk -F= '/^namelookup=/{print $2}')
  size=$(echo "$m" | awk -F= '/^size=/{print $2}')
  ctype=$(echo "$m" | awk -F= '/^content_type=/{print $2}')
  printf "code=%s time=%.3fs (dns=%.3f conn=%.3f tls=%.3f ttfb=%.3f) size=%s type=%s" \
    "$code" "${total:-0}" "${namelookup:-0}" "${connect:-0}" "${appconnect:-0}" "${starttransfer:-0}" "$size" "${ctype:-}"
}

checks_total=0
crit_fail=0
warn_fail=0

report_line() {
  # args: level name ok metrics note [bodyfile]
  local level="$1"; shift
  local name="$1"; shift
  local ok="$1"; shift
  local metrics="$1"; shift
  local note="${1:-}"; shift || true
  local bodyfile="${1:-}"; shift || true

  checks_total=$((checks_total+1))
  if [[ "$level" == "crit" && "$ok" != "ok" ]]; then
    crit_fail=$((crit_fail+1))
  elif [[ "$level" == "warn" && "$ok" != "ok" ]]; then
    warn_fail=$((warn_fail+1))
  fi

  printf "[%s] %-24s : %s | " "$level" "$name" "$ok"
  print_metric_line "$metrics"
  if [[ -n "$note" ]]; then
    printf " | %s" "$note"
  fi
  echo

  if [[ "$VERBOSE" -eq 1 && "$ok" != "ok" && -f "$bodyfile" ]]; then
    echo "--- response snippet ---"
    head -c 600 "$bodyfile"
    echo -e "\n-------------------------"
  fi
}

tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t loki-health)
trap 'rm -rf "$tmpdir"' EXIT

echo "Checking Loki at: $URL"
if [[ -n "$ORG_ID" ]]; then echo "Tenant: $ORG_ID"; fi

now_ns=$(date +%s%N)
range_ns=$((TIME_RANGE_MINUTES * 60 * 1000000000))
start_ns=$((now_ns - range_ns))
end_ns=$now_ns

# 1) Ready
body="$tmpdir/ready"
metrics=$(http_get "/ready" "text/plain" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -qi "ready" "$body"; then
  report_line crit "ready" ok "$metrics" "expect 200 + body contains 'ready'" "$body"
else
  note="unexpected status/body"; [[ "$code" != 200 ]] && note="http $code"
  report_line crit "ready" fail "$metrics" "$note" "$body"
fi

# 2) Metrics
body="$tmpdir/metrics"
metrics=$(http_get "/metrics" "*/*" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && (grep -qE "(^|_)loki_build_info\{|^go_info\{|^process_start_time_seconds" "$body" || true); then
  report_line warn "metrics" ok "$metrics" "found build/go metrics" "$body"
else
  report_line warn "metrics" fail "$metrics" "missing metrics or http $code" "$body"
fi

# 3) Labels
body="$tmpdir/labels"
metrics=$(http_get "/loki/api/v1/labels" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"status"\s*:\s*"success"' "$body"; then
  report_line crit "labels" ok "$metrics" "status=success" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "labels" fail "$metrics" "auth required (http $code)" "$body"
  else
    note="http $code"; grep -q '"status"' "$body" || note+="; no status field"
    report_line crit "labels" fail "$metrics" "$note" "$body"
  fi
fi

# 4) Build Info (optional; warn on failure)
body="$tmpdir/buildinfo"
metrics=$(http_get "/loki/api/v1/status/buildinfo" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -qE '"version"\s*:\s*"|"revision"\s*:\s*"' "$body"; then
  ver=$(grep -oE '"version"\s*:\s*"[^"]+"' "$body" | head -1 | cut -d '"' -f4 || true)
  report_line warn "buildinfo" ok "$metrics" "version=${ver:-unknown}" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "buildinfo" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line warn "buildinfo" fail "$metrics" "http $code" "$body"
  fi
fi

# 5) Series (exists query)
body="$tmpdir/series"
qs="match[]=%7Bjob%3D~%22.%2B%22%7D&start=$start_ns&end=$end_ns&limit=1"
metrics=$(http_get "/loki/api/v1/series?${qs}" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"status"\s*:\s*"success"' "$body"; then
  report_line warn "series" ok "$metrics" "queried recent series (may be empty)" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "series" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line warn "series" fail "$metrics" "http $code" "$body"
  fi
fi

# 6) Query range (logs)
body="$tmpdir/query_range"
q=$(printf '{job=~".+"}')
qs="query=$(printf %s "$q" | jq -sRr @uri 2>/dev/null || python -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.stdin.read()))' <<< "$q" 2>/dev/null || echo '%7Bjob%3D~%22.%2B%22%7D')&start=$start_ns&end=$end_ns&limit=10&direction=backward"
metrics=$(http_get "/loki/api/v1/query_range?${qs}" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"status"\s*:\s*"success"' "$body"; then
  report_line warn "query_range" ok "$metrics" "status=success (may be empty)" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "query_range" fail "$metrics" "auth required (http $code)" "$body"
  else
    # 400 can happen if parser errors; mark as fail warn
    report_line warn "query_range" fail "$metrics" "http $code" "$body"
  fi
fi

# 7) Log volume (point-in-time)
body="$tmpdir/index_volume"
q=$(printf '{job=~".+"}')
qs="query=$(printf %s "$q" | jq -sRr @uri 2>/dev/null || echo '%7Bjob%3D~%22.%2B%22%7D')&start=$start_ns&end=$end_ns&limit=100"
metrics=$(http_get "/loki/api/v1/index/volume?${qs}" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"status"\s*:\s*"success"' "$body"; then
  report_line warn "index.volume" ok "$metrics" "status=success (may be empty)" "$body"
else
  if [[ "$code" == "404" ]]; then
    report_line warn "index.volume" fail "$metrics" "endpoint missing (http 404)" "$body"
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "index.volume" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line warn "index.volume" fail "$metrics" "http $code" "$body"
  fi
fi

# 8) Log volume (range)
body="$tmpdir/index_volume_range"
q=$(printf '{job=~".+"}')
qs="query=$(printf %s "$q" | jq -sRr @uri 2>/dev/null || echo '%7Bjob%3D~%22.%2B%22%7D')&start=$start_ns&end=$end_ns&step=60s&limit=100"
metrics=$(http_get "/loki/api/v1/index/volume_range?${qs}" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"status"\s*:\s*"success"' "$body"; then
  report_line warn "index.volume_range" ok "$metrics" "status=success (may be empty)" "$body"
else
  if [[ "$code" == "404" ]]; then
    report_line warn "index.volume_range" fail "$metrics" "endpoint missing (http 404)" "$body"
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line warn "index.volume_range" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line warn "index.volume_range" fail "$metrics" "http $code" "$body"
  fi
fi

# 9) Verify docker job label exists
body="$tmpdir/job_values"
metrics=$(http_get "/loki/api/v1/label/job/values?start=$start_ns&end=$end_ns" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -q '"'"$DOCKER_JOB_LABEL"'"' "$body"; then
  report_line crit "docker.job.label" ok "$metrics" "found job=$DOCKER_JOB_LABEL" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line crit "docker.job.label" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line crit "docker.job.label" fail "$metrics" "missing job=$DOCKER_JOB_LABEL or http $code" "$body"
  fi
fi

# 10) Query recent logs for docker job
body="$tmpdir/docker_logs"
q=$(printf '{job="%s"}' "$DOCKER_JOB_LABEL")
enc_q=$(printf %s "$q" | jq -sRr @uri 2>/dev/null || python - <<'PY' 2>/dev/null
import sys, urllib.parse
print(urllib.parse.quote(sys.stdin.read()))
PY
)
if [[ -z "$enc_q" ]]; then enc_q="%7Bjob%3D%22${DOCKER_JOB_LABEL//\"/%22}%22%7D"; fi
qs="query=$enc_q&start=$start_ns&end=$end_ns&limit=20&direction=backward"
metrics=$(http_get "/loki/api/v1/query_range?${qs}" "application/json" "$body") || true
code=$(echo "$metrics" | awk -F= '/^http_code=/{print $2}')
if [[ "$code" == "200" ]] && grep -Eq '"values"\s*:\s*\[\s*\[' "$body"; then
  report_line crit "docker.logs.present" ok "$metrics" "found recent entries for job=$DOCKER_JOB_LABEL" "$body"
else
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    report_line crit "docker.logs.present" fail "$metrics" "auth required (http $code)" "$body"
  else
    report_line crit "docker.logs.present" fail "$metrics" "no recent entries or http $code" "$body"
  fi
fi

echo
echo "Summary: total checks=$checks_total, critical failures=$crit_fail, warnings=$warn_fail"
if [[ $crit_fail -gt 0 ]]; then
  exit 1
fi
exit 0
