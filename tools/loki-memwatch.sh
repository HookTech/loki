#!/usr/bin/env bash

set -euo pipefail

# Loki memory watcher
# - 支持两种采集方式：
#   1) SSH 到远端主机执行 docker stats / ps 汇总 Loki 内存
#   2) 通过 HTTP 抓取 /metrics 的 process_resident_memory_bytes 估算
# - 可选建立 SSH 本地端口映射（隧道）后本地 curl 采集
# - 根据宿主机总内存占比给出 OK/WARN/CRIT 级别
#
# 依赖：bash, awk, grep, sed, curl（metrics 模式）, docker（远端 docker 方式）

WARN_PCT=${WARN_PCT:-50}
CRIT_PCT=${CRIT_PCT:-70}
HI_CONTAINER_PCT=${HI_CONTAINER_PCT:-90}
# CPU 阈值（按“占宿主机总核的百分比”计算，0-100）
CPU_WARN_PCT=${CPU_WARN_PCT:-70}
CPU_CRIT_PCT=${CPU_CRIT_PCT:-90}
HI_CPU_CONTAINER_PCT=${HI_CPU_CONTAINER_PCT:-200}   # 单容器 CPU%（docker stats 原值），默认 2 核相当于 200%
WATCH_INTERVAL=${WATCH_INTERVAL:-10}
WATCH=${WATCH:-0}
MODE=${MODE:-auto}            # auto|docker|metrics
CONTAINER_MATCH=${CONTAINER_MATCH:-"(^|-)loki($|-)|(^|-)loki-(read|write|backend)($|-)"}

# SSH 相关
SSH_HOST=""
SSH_ID=""
SSH_OPTS=()
USE_SUDO=1

# Metrics 相关
URLS=()
TOKEN=""
ORG_ID=""
INSECURE=0

# 告警相关（企业微信机器人）
WECOM_WEBHOOK_URL=${WECOM_WEBHOOK_URL:-""}
ALWAYS_SEND=${ALWAYS_SEND:-0}   # 1=即使 OK 也推送汇总

# 隧道相关（示例：-T 13100:127.0.0.1:3100 可在本地 http://127.0.0.1:13100/metrics 抓取）
TUNNEL_SPEC=""   # 形如 LPORT:RHOST:RPORT
TUNNEL_PID=""

usage() {
  cat <<EOF
Loki memory watcher

用法: $(basename "$0") [选项]

核心选项：
  -m, --mode MODE         采集模式: auto|docker|metrics (默认: auto)
  -w, --warn PCT          WARN 阈值，占宿主机内存百分比 (默认: ${WARN_PCT}%)
  -c, --crit PCT          CRIT 阈值，占宿主机内存百分比 (默认: ${CRIT_PCT}%)
  -p, --hi-container PCT  单容器接近内存上限阈值 (默认: ${HI_CONTAINER_PCT}%)
  --cpu-warn PCT          CPU WARN 阈值，占宿主机总核百分比 (默认: ${CPU_WARN_PCT}%)
  --cpu-crit PCT          CPU CRIT 阈值，占宿主机总核百分比 (默认: ${CPU_CRIT_PCT}%)
  --hi-cpu-container PCT  单容器 CPU% 高阈值（docker stats 原值）(默认: ${HI_CPU_CONTAINER_PCT}%)
  --watch [SEC]           循环监控，间隔秒 (默认: ${WATCH_INTERVAL}s)

SSH 远程：
  -s, --ssh HOST          远端主机 (如 user@host)
  -i, --identity KEY      SSH 私钥路径
  -o, --ssh-opts OPTS     额外 SSH 选项（可多次）
  --no-sudo               远端执行命令时不使用 sudo（默认尝试 sudo）
  -T, --tunnel SPEC       建立本地隧道 SPEC=LOCAL:RHOST:RPORT（需配合 --ssh）

Metrics 模式：
  -U, --url URL           目标 /metrics 的完整 URL（可多次）
  -t, --token TOKEN       Bearer Token（可选）
  -o, --org-id ID         X-Scope-OrgID / 租户（可选）
  -k, --insecure          允许不安全 TLS（curl -k）

告警推送：
  -W, --wecom URL         企业微信机器人 webhook 完整 URL
  --report-ok             即使 OK 也发送汇总报告

示例：
  # 1) SSH 到远端统计 docker 中 Loki 内存占用
  $0 --ssh user@10.0.0.2 --mode docker --watch 5

  # 2) 通过 ssh 隧道映射远端 3100 到本地 13100，再用 /metrics 采集
  $0 --ssh user@10.0.0.2 -T 13100:127.0.0.1:3100 \\
     --mode metrics -U http://127.0.0.1:13100/metrics --watch 10

  # 3) 直接本地采集多个 /metrics 端点
  $0 --mode metrics -U http://localhost:3100/metrics -U http://localhost:3101/metrics

环境变量支持：WARN_PCT, CRIT_PCT, HI_CONTAINER_PCT, CPU_WARN_PCT, CPU_CRIT_PCT, HI_CPU_CONTAINER_PCT,
            WATCH_INTERVAL, MODE, CONTAINER_MATCH, WECOM_WEBHOOK_URL, ALWAYS_SEND
EOF
}

log() { printf "%s\n" "$*"; }

die() { echo "ERROR: $*" >&2; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

to_bytes() {
  # 将人类可读容量转为字节（支持 B,kB,KB,KiB,MB,MiB,GB,GiB 等）
  # 入参形如："68.84MiB"、"1GiB"、"512kB"
  local v="$1"
  v=$(echo "$v" | tr -d ' ')
  local num unit
  num=$(echo "$v" | sed -E 's/^([0-9]+(\.[0-9]+)?).*/\1/')
  unit=$(echo "$v" | sed -E 's/^[0-9]+(\.[0-9]+)?\s*//')
  case "$unit" in
    ""|B|bytes|byte) awk -v n="$num" 'BEGIN{printf "%.0f", n}' ;;
    kB|KB)        awk -v n="$num" 'BEGIN{printf "%.0f", n*1000}' ;;
    KiB|K|Ki)     awk -v n="$num" 'BEGIN{printf "%.0f", n*1024}' ;;
    MB)           awk -v n="$num" 'BEGIN{printf "%.0f", n*1000*1000}' ;;
    MiB|M|Mi)     awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024}' ;;
    GB)           awk -v n="$num" 'BEGIN{printf "%.0f", n*1000*1000*1000}' ;;
    GiB|G|Gi)     awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024*1024}' ;;
    TB)           awk -v n="$num" 'BEGIN{printf "%.0f", n*1000*1000*1000*1000}' ;;
    TiB|T|Ti)     awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024*1024*1024}' ;;
    *)            awk -v n="$num" 'BEGIN{printf "%.0f", n}' ;;
  esac
}

fmt_bytes() {
  # 以友好单位输出字节数
  local b="$1"
  awk -v b="$b" 'function f(v,u){printf "%.2f%s", v,u; exit}
    BEGIN{
      if (b>=1024^4) f(b/1024^4, "TiB");
      else if (b>=1024^3) f(b/1024^3, "GiB");
      else if (b>=1024^2) f(b/1024^2, "MiB");
      else if (b>=1024)   f(b/1024,   "KiB");
      else                 f(b,        "B");
    }'
}

percent_of() {
  local part="$1" whole="$2"
  awk -v p="$part" -v w="$whole" 'BEGIN{ if(w==0){print 0}else{printf "%.2f", (p*100.0)/w} }'
}

host_cpu_cores() {
  # 获取宿主机 CPU 逻辑核数量
  local n
  if ! n=$(rsh "nproc" 2>/dev/null); then
    n=$(rsh "grep -c ^processor /proc/cpuinfo" 2>/dev/null || echo 1)
  fi
  [[ -z "$n" || "$n" -lt 1 ]] && n=1
  echo "$n"
}

rsh() {
  # 在本地或远端执行命令
  local cmd="$1"
  if [[ -z "$SSH_HOST" ]]; then
    bash -lc "$cmd"
  else
    local ssh_args=("-o" "BatchMode=yes" "-o" "StrictHostKeyChecking=no")
    [[ ${#SSH_OPTS[@]} -gt 0 ]] && ssh_args+=("${SSH_OPTS[@]}")
    [[ -n "$SSH_ID" ]] && ssh_args+=("-i" "$SSH_ID")
    ssh "${ssh_args[@]}" "$SSH_HOST" "bash -lc $(printf %q "$cmd")"
  fi
}

start_tunnel() {
  # 需要 --ssh，SPEC 形如: LPORT:RHOST:RPORT
  local spec="$TUNNEL_SPEC"
  [[ -z "$spec" ]] && return 0
  [[ -z "$SSH_HOST" ]] && die "--tunnel 需配合 --ssh 使用"
  local lport rhost rport
  IFS=: read -r lport rhost rport <<<"$spec"
  [[ -z "$lport" || -z "$rhost" || -z "$rport" ]] && die "非法 --tunnel SPEC: $spec"
  local args=("-N" "-L" "${lport}:${rhost}:${rport}" "-o" "ExitOnForwardFailure=yes" "-o" "BatchMode=yes" "-o" "StrictHostKeyChecking=no")
  [[ ${#SSH_OPTS[@]} -gt 0 ]] && args+=("${SSH_OPTS[@]}")
  [[ -n "$SSH_ID" ]] && args+=("-i" "$SSH_ID")
  ssh "${args[@]}" "$SSH_HOST" &
  TUNNEL_PID=$!
  # 等待隧道起来
  sleep 0.3
}

stop_tunnel() {
  [[ -n "$TUNNEL_PID" ]] && kill "$TUNNEL_PID" >/dev/null 2>&1 || true
}

host_mem_info() {
  # 输出: mem_total_bytes mem_available_bytes swap_total_bytes swap_free_bytes
  rsh "awk -F: '/^MemTotal|^MemAvailable|^SwapTotal|^SwapFree/ {gsub(/ /, "", \$2); print \$1, \$2}' /proc/meminfo | sed -E 's/kB//g'" \
    | awk 'BEGIN{mt=ma=st=sf=0} \
           $1=="MemTotal"{mt=$2*1024} \
           $1=="MemAvailable"{ma=$2*1024} \
           $1=="SwapTotal"{st=$2*1024} \
           $1=="SwapFree"{sf=$2*1024} \
           END{print mt, ma, st, sf}'
}

collect_docker_stats() {
  # 采集 docker stats，输出多行：name;used_bytes;limit_bytes;mem_percent;cpu_percent
  local sudo=""
  if [[ $USE_SUDO -eq 1 ]]; then sudo="sudo -n "; fi

  # 容器列表
  local list_cmd="${sudo}docker ps --format '{{.Names}};{{.Image}}'"
  local lines
  if ! lines=$(rsh "$list_cmd" 2>/dev/null); then
    # 无权限时尝试不带 sudo
    lines=$(rsh "docker ps --format '{{.Names}};{{.Image}}'" 2>/dev/null || true)
  fi

  local containers=()
  while IFS= read -r ln; do
    [[ -z "$ln" ]] && continue
    local name image
    name="${ln%%;*}"; image="${ln#*;}"
    if echo "$name" | grep -Eq "$CONTAINER_MATCH" || echo "$image" | grep -qi 'grafana/loki'; then
      containers+=("$name")
    fi
  done <<<"$lines"

  if [[ ${#containers[@]} -eq 0 ]]; then
    return 0
  fi

  local stats_cmd
  stats_cmd="${sudo}docker stats --no-stream --format '{{.Name}};{{.MemUsage}};{{.MemPerc}};{{.CPUPerc}}' ${containers[*]}"
  local out
  if ! out=$(rsh "$stats_cmd" 2>/dev/null); then
    out=$(rsh "docker stats --no-stream --format '{{.Name}};{{.MemUsage}};{{.MemPerc}};{{.CPUPerc}}' ${containers[*]}" 2>/dev/null || true)
  fi

  while IFS= read -r ln; do
    [[ -z "$ln" ]] && continue
    # 形如：name;68.84MiB / 1GiB;6.78%;12.34%
    local name usage mem_pct cpu_pct used limit
    name=${ln%%;*}
    usage=${ln#*;}; usage=${usage%%;*}
    # 拆分 mem_pct 与 cpu_pct
    mem_pct=${ln#*;}; mem_pct=${mem_pct#*;}; mem_pct=${mem_pct%%;*}; mem_pct=${mem_pct%%%}
    cpu_pct=${ln##*;}; cpu_pct=${cpu_pct%%%}
    used=$(echo "$usage" | awk -F'/' '{gsub(/ /,""); print $1}')
    limit=$(echo "$usage" | awk -F'/' '{gsub(/ /,""); print $2}')
    local used_b limit_b
    used_b=$(to_bytes "$used")
    limit_b=$(to_bytes "$limit")
    printf "%s;%s;%s;%.2f;%.2f\n" "$name" "$used_b" "$limit_b" "$mem_pct" "$cpu_pct"
  done <<<"$out"
}

collect_metrics_mem() {
  # 从 /metrics 提取 process_resident_memory_bytes；输出多行：url;used_bytes
  local curl_opts=(--silent --show-error --location --connect-timeout 5 --max-time 10)
  [[ "$INSECURE" -eq 1 ]] && curl_opts+=(--insecure)

  for u in "${URLS[@]:-}"; do
    [[ -z "$u" ]] && continue
    local hdrs=()
    [[ -n "$TOKEN" ]] && hdrs+=("-H" "Authorization: Bearer $TOKEN")
    [[ -n "$ORG_ID" ]] && hdrs+=("-H" "X-Scope-OrgID: $ORG_ID")
    local body
    if ! body=$(curl "${curl_opts[@]}" "${hdrs[@]}" "$u" 2>/dev/null); then
      continue
    fi
    local v
    v=$(echo "$body" | awk '/^process_resident_memory_bytes\s/{print $2; exit}')
    if [[ -n "$v" ]]; then
      # 值可能是科学计数
      local bytes
      bytes=$(awk -v x="$v" 'BEGIN{printf "%.0f", x+0}')
      printf "%s;%s\n" "$u" "$bytes"
    fi
  done
}

eval_level() {
  local pct="$1"
  if awk -v p="$pct" -v c="$CRIT_PCT" 'BEGIN{exit !(p>=c)}'; then echo CRIT
  elif awk -v p="$pct" -v w="$WARN_PCT" 'BEGIN{exit !(p>=w)}'; then echo WARN
  else echo OK; fi
}

eval_cpu_level() {
  local pct="$1"
  if awk -v p="$pct" -v c="$CPU_CRIT_PCT" 'BEGIN{exit !(p>=c)}'; then echo CRIT
  elif awk -v p="$pct" -v w="$CPU_WARN_PCT" 'BEGIN{exit !(p>=w)}'; then echo WARN
  else echo OK; fi
}

print_header() {
  local mt="$1" ma="$2" st="$3" sf="$4"
  local mu=$(( mt - ma ))
  printf "Host Mem: total=%s, used=%s, avail=%s | Swap: total=%s, free=%s\n" \
    "$(fmt_bytes "$mt")" "$(fmt_bytes "$mu")" "$(fmt_bytes "$ma")" \
    "$(fmt_bytes "$st")" "$(fmt_bytes "$sf")"
  if [[ "$st" -eq 0 ]]; then
    echo "[WARN] 无 Swap（SwapTotal=0）— 内存耗尽时风险较高"
  fi
}

maybe_send_wecom() {
  local level="$1"
  local details="$2"
  if [[ -z "$WECOM_WEBHOOK_URL" ]]; then
    return 0
  fi
  if [[ "$level" == "OK" && "$ALWAYS_SEND" -ne 1 ]]; then
    return 0
  fi

  local host ts
  host=$(rsh 'hostname' 2>/dev/null || hostname)
  ts=$(date '+%F %T')

  local title
  if [[ "$level" == "OK" ]]; then
    title="Loki 资源监控 OK"
  else
    title="Loki 资源告警 ${level}"
  fi

  # 组织 Markdown 文本
  local content
  if [[ -n "$details" ]]; then
    content="**${title}**\n> 主机: ${host}\n> 时间: ${ts}\n> 详情: ${details}"
  else
    content="**${title}**\n> 主机: ${host}\n> 时间: ${ts}"
  fi

  # 发送到企业微信机器人
  # JSON 转义
  local content_json
  content_json=$(printf "%s" "$content" | sed -e 's/\\/\\\\/g' -e 's/\"/\\\"/g' -e ':a;N;$!ba;s/\n/\\n/g')
  local payload
  payload="{\"msgtype\":\"markdown\",\"markdown\":{\"content\":\"${content_json}\"}}"

  curl --silent --show-error --location --connect-timeout 5 --max-time 10 \
    -H 'Content-Type: application/json' \
    -X POST "$WECOM_WEBHOOK_URL" \
    -d "$payload" \
    >/dev/null 2>&1 || true
}

run_once() {
  local mt ma st sf
  read -r mt ma st sf < <(host_mem_info)
  print_header "$mt" "$ma" "$st" "$sf"

  local found=0
  local total_used=0
  local total_cpu_pct_sum=0   # docker stats CPU% 之和
  local lines
  local overall_level="OK"
  local alerts=()

  if [[ "$MODE" == "auto" || "$MODE" == "docker" ]]; then
    lines=$(collect_docker_stats || true)
    if [[ -n "$lines" ]]; then
      found=1
      echo "-- Docker containers (Loki) --"
      printf "%-24s %12s %12s %8s %8s\n" "NAME" "USED" "LIMIT" "MEM%" "CPU%"
      local hi=0
      local hi_cpu=0
      while IFS= read -r ln; do
        [[ -z "$ln" ]] && continue
        IFS=';' read -r name used_b limit_b mem_pct cpu_pct <<<"$ln"
        total_used=$(( total_used + used_b ))
        total_cpu_pct_sum=$(awk -v a="$total_cpu_pct_sum" -v b="$cpu_pct" 'BEGIN{printf "%.2f", a+b}')
        printf "%-24s %12s %12s %7.2f%% %7.2f%%\n" "$name" "$(fmt_bytes "$used_b")" "$(fmt_bytes "$limit_b")" "$mem_pct" "$cpu_pct"
        if awk -v p="$mem_pct" -v h="$HI_CONTAINER_PCT" 'BEGIN{exit !(p>=h)}'; then hi=1; fi
        if awk -v p="$cpu_pct" -v h="$HI_CPU_CONTAINER_PCT" 'BEGIN{exit !(p>=h)}'; then hi_cpu=1; fi
      done <<<"$lines"
      local share
      share=$(percent_of "$total_used" "$mt")
      local lvl
      lvl=$(eval_level "$share")
      printf "TOTAL (Docker Loki): %s (%.2f%% of host)\n" "$(fmt_bytes "$total_used")" "$share"
      if [[ "$hi" -eq 1 ]]; then
        echo "[WARN] 存在容器接近各自内存上限（>= ${HI_CONTAINER_PCT}%）"
      fi
      # CPU 聚合，换算为“占宿主机总核的百分比”
      local cores
      cores=$(host_cpu_cores)
      local cpu_host_pct
      cpu_host_pct=$(awk -v s="$total_cpu_pct_sum" -v c="$cores" 'BEGIN{if(c<=0)c=1; printf "%.2f", s/c}')
      local cpu_lvl
      cpu_lvl=$(eval_cpu_level "$cpu_host_pct")
      printf "TOTAL CPU (Docker Loki): sum=%.2f%%, cores=%d -> host=%.2f%%\n" "$total_cpu_pct_sum" "$cores" "$cpu_host_pct"
      if [[ "$hi_cpu" -eq 1 ]]; then
        echo "[WARN] 存在容器 CPU% 过高（>= ${HI_CPU_CONTAINER_PCT}%）"
      fi
      echo "LEVEL: $lvl"
      echo "CPU LEVEL: $cpu_lvl"

      # 汇总告警级别
      if [[ "$lvl" == "CRIT" || "$cpu_lvl" == "CRIT" ]]; then overall_level="CRIT"; fi
      if [[ "$overall_level" == "OK" && ( "$lvl" == "WARN" || "$cpu_lvl" == "WARN" ) ]]; then overall_level="WARN"; fi

      # 告警文本片段
      if [[ "$lvl" == "CRIT" || "$lvl" == "WARN" ]]; then
        alerts+=("内存占用: ${share}% (${lvl})，总计 $(fmt_bytes "$total_used"); 宿主机 $(fmt_bytes "$mt")")
      fi
      if [[ "$cpu_lvl" == "CRIT" || "$cpu_lvl" == "WARN" ]]; then
        alerts+=("CPU 使用: ${cpu_host_pct}% (${cpu_lvl})，容器汇总 ${total_cpu_pct_sum}% / ${cores} 核")
      fi
    fi
  fi

  if [[ "$MODE" == "metrics" || ( "$MODE" == "auto" && "$found" -eq 0 ) ]]; then
    if [[ ${#URLS[@]} -gt 0 ]]; then
      local mlines
      mlines=$(collect_metrics_mem || true)
      if [[ -n "$mlines" ]]; then
        found=1
        echo "-- Metrics process_resident_memory_bytes --"
        printf "%-40s %12s\n" "URL" "RSS"
        local total_rss=0
        while IFS= read -r ln; do
          [[ -z "$ln" ]] && continue
          IFS=';' read -r u bytes <<<"$ln"
          total_rss=$(( total_rss + bytes ))
          printf "%-40s %12s\n" "$u" "$(fmt_bytes "$bytes")"
        done <<<"$mlines"
        local share
        share=$(percent_of "$total_rss" "$mt")
        local lvl
        lvl=$(eval_level "$share")
        printf "TOTAL (metrics sum): %s (%.2f%% of host)\n" "$(fmt_bytes "$total_rss")" "$share"
        echo "LEVEL: $lvl"
        if [[ "$lvl" == "CRIT" || "$lvl" == "WARN" ]]; then
          alerts+=("内存占用: ${share}% (${lvl})，总计 $(fmt_bytes "$total_rss"); 宿主机 $(fmt_bytes "$mt")")
          [[ "$overall_level" == "OK" ]] && overall_level="$lvl" || true
          [[ "$lvl" == "CRIT" ]] && overall_level="CRIT" || true
        fi
      fi
    fi
  fi

  if [[ "$found" -eq 0 ]]; then
    echo "未采集到 Loki 内存数据（请检查 --mode、SSH 权限或 URL）"
    return 1
  fi

  # 企业微信推送
  maybe_send_wecom "$overall_level" "${alerts[*]:-}"
}

# 解析参数
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode) MODE="$2"; shift 2;;
    -w|--warn) WARN_PCT="$2"; shift 2;;
    -c|--crit) CRIT_PCT="$2"; shift 2;;
    -p|--hi-container) HI_CONTAINER_PCT="$2"; shift 2;;
    --cpu-warn) CPU_WARN_PCT="$2"; shift 2;;
    --cpu-crit) CPU_CRIT_PCT="$2"; shift 2;;
    --hi-cpu-container) HI_CPU_CONTAINER_PCT="$2"; shift 2;;
    --watch) WATCH=1; WATCH_INTERVAL="${2:-$WATCH_INTERVAL}"; [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]] && shift 2 || shift 1;;
    -s|--ssh) SSH_HOST="$2"; shift 2;;
    -i|--identity) SSH_ID="$2"; shift 2;;
    -o|--ssh-opts) SSH_OPTS+=("$2"); shift 2;;
    --no-sudo) USE_SUDO=0; shift;;
    -T|--tunnel) TUNNEL_SPEC="$2"; shift 2;;
    -U|--url) URLS+=("$2"); shift 2;;
    -t|--token) TOKEN="$2"; shift 2;;
    -O|--org-id|-o) ORG_ID="$2"; shift 2;;
    -k|--insecure) INSECURE=1; shift;;
    -W|--wecom) WECOM_WEBHOOK_URL="$2"; shift 2;;
    --report-ok) ALWAYS_SEND=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "未知参数: $1" >&2; usage; exit 2;;
  esac
done

trap 'stop_tunnel' EXIT

start_tunnel

if [[ "$WATCH" -eq 1 ]]; then
  while :; do
    date '+%F %T'
    if ! run_once; then
      echo "-- 采集失败 --"
    fi
    echo "----------------------------------------"
    sleep "$WATCH_INTERVAL"
  done
else
  run_once
fi
