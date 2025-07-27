#!/bin/bash
#perf-metrics.sh
EVENTS="cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-loads,dTLB-load-misses"

LOG_FILE="perf_log.csv"

run_perf_and_parse() {
  local ts="$1"
  awk -F, -v ts="$ts" -v log_mode="$2" -v log_file="$LOG_FILE" '
  /cycles/ {c=$1}
  /instructions/ {i=$1}
  /cache-references/ {cr=$1}
  /cache-misses/ {cm=$1}
  /L1-dcache-loads/ {l1=$1}
  /L1-dcache-load-misses/ {l1m=$1}
  /LLC-loads/ {llc=$1}
  /LLC-load-misses/ {llcm=$1}
  /dTLB-loads/ {tlb=$1}
  /dTLB-load-misses/ {tlbm=$1}
  END {
    ipc = (c>0)? i/c : 0
    cache_hit = (cr>0)? (1 - cm/cr)*100 : 0
    l1_hit = (l1>0)? (1 - l1m/l1)*100 : 0
    llc_hit = (llc>0)? (1 - llcm/llc)*100 : 0
    tlb_hit = (tlb>0)? (1 - tlbm/tlb)*100 : 0

    # 实时打印
    printf "结果:\n"
    printf "  IPC: %.2f\n  Cache命中率: %.2f%%\n  L1命中率: %.2f%%\n  LLC命中率: %.2f%%\n  TLB命中率: %.2f%%\n", ipc, cache_hit, l1_hit, llc_hit, tlb_hit

    # 如果是 log_mode，就写 CSV
    if (log_mode=="log") {
      # 先检查文件是否存在，不存在就写 header
      cmd = "test -f " log_file
      if (system(cmd) != 0) {
        print "timestamp,IPC,CacheHit,L1Hit,LLCHit,TLBHit" >> log_file
      }
      printf "%s,%.2f,%.2f,%.2f,%.2f,%.2f\n", ts, ipc, cache_hit, l1_hit, llc_hit, tlb_hit >> log_file
    }
  }'
}

if [[ "$1" == "--system" ]]; then
  SECONDS=${2:-10}
  echo ">> 全系统采样 ${SECONDS} 秒..."
  sudo perf stat -a -x, -e $EVENTS sleep $SECONDS 2>&1 | run_perf_and_parse "$(date '+%Y-%m-%d %H:%M:%S')"

elif [[ "$1" == "--program" ]]; then
  shift
  echo ">> 采样单个程序: $@"
  sudo perf stat -x, -e $EVENTS "$@" 2>&1 | run_perf_and_parse "$(date '+%Y-%m-%d %H:%M:%S')"

elif [[ "$1" == "--loop" ]]; then
  INTERVAL=${2:-5}
  DURATION=${3:-3}
  LOG_MODE=$4  # 传 log 就启用日志
  echo ">> 循环采样: 每隔 ${INTERVAL}s 采样全系统 ${DURATION}s (Ctrl+C 停止)"
  if [[ "$LOG_MODE" == "log" ]]; then
    echo ">> 日志模式开启，结果将写入 $LOG_FILE"
  fi
  while true; do
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    echo "===== $TS ====="
    sudo perf stat -a -x, -e $EVENTS sleep $DURATION 2>&1 | run_perf_and_parse "$TS" "$LOG_MODE"
    echo ""
    sleep $INTERVAL
  done

else
  echo "用法:"
  echo "  $0 --system [秒数]                  # 全系统采样 N 秒 (默认 10s)"
  echo "  $0 --program ./程序 参数            # 针对单个程序采样"
  echo "  $0 --loop [间隔秒] [采样秒] [log]   # 循环采样, 默认每隔5s采样3s, 传 log 开启CSV记录"
  echo ""
  echo "示例:"
  echo "  $0 --loop 5 3           # 每隔5秒采样3秒"
  echo "  $0 --loop 10 5 log      # 每隔10秒采样5秒并写入 perf_log.csv"
  exit 1
fi
