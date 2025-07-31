#!/bin/bash
set -e

# 编译优化版本
echo "🔨 Compiling enhanced cache performance demo..."
gcc -O2 -pthread -D_GNU_SOURCE -o cache_test cache_pingpong_perf.c

# 检查CPU信息
echo "💻 System Information:"
echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
echo "Cores: $(nproc)"
echo "Cache line size: $(getconf LEVEL1_DCACHE_LINESIZE 2>/dev/null || echo "64 (assumed)")"
echo

# 运行基础测试
echo "=== Basic Performance Test ==="
./cache_test
echo

# 使用 perf 收集详细的缓存行为数据
echo "=== Detailed Performance Analysis with perf ==="
if command -v perf >/dev/null 2>&1; then
    echo "📊 Cache behavior analysis:"
    sudo perf stat -e cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,cycles,instructions ./cache_test 2>&1 | grep -E "(cache-misses|cache-references|L1-dcache|Performance counter stats|seconds time elapsed)"
    echo
    
    echo "🔍 Hardware counters (if available):"
    sudo perf stat -e cache-misses,cache-references,LLC-load-misses,LLC-loads ./cache_test 2>&1 | grep -E "(LLC|cache)" || echo "LLC counters not available on this system"
else
    echo "⚠️  perf not available, skipping detailed analysis"
fi

echo
echo "🎯 Analysis Summary:"
echo "   - False Sharing: Adjacent variables cause cache line bouncing"
echo "   - Cache Ping-Pong: Same variable accessed alternately causes severe bouncing"
echo "   - Cache-Line Padded: Separate cache lines minimize interference"
echo "   - Performance difference should be significant in cache-miss rates"
