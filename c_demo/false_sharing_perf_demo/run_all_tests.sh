#!/bin/bash
set -e

echo "🚀 Comprehensive Cache Performance Analysis"
echo "=========================================="

# 编译所有测试
echo "🔨 Compiling tests..."
gcc -O2 -pthread -D_GNU_SOURCE -o cache_test cache_pingpong_perf.c
gcc -O2 -pthread -D_GNU_SOURCE -o extreme_test extreme_cache_test.c

# 系统信息
echo "💻 System Information:"
echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
echo "Cores: $(nproc)"
echo "Cache sizes:"
lscpu | grep -E "L1d|L1i|L2|L3" | sed 's/^/  /'
echo

# 运行基础测试
echo "=== Test Suite 1: Basic Cache Effects ==="
./cache_test
echo

# 运行极端测试
echo "=== Test Suite 2: Extreme Cache Effects ==="
./extreme_test
echo

# Perf分析
if command -v perf >/dev/null 2>&1; then
    echo "=== Detailed Cache Analysis ==="
    
    echo "📊 Cache miss analysis for basic test:"
    sudo perf stat -e cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads \
        ./cache_test 2>&1 | grep -E "(cache-misses|cache-references|L1-dcache)" | head -4
    echo
    
    echo "📊 Cache miss analysis for extreme test:"  
    sudo perf stat -e cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads \
        ./extreme_test 2>&1 | grep -E "(cache-misses|cache-references|L1-dcache)" | head -4
    echo
    
    echo "🔍 Branch prediction and pipeline effects:"
    sudo perf stat -e branch-misses,branches,context-switches,cpu-migrations \
        ./extreme_test 2>&1 | grep -E "(branch|context|cpu-migrations)" || echo "Some counters not available"
else
    echo "⚠️  perf not available - install linux-perf for detailed analysis"
fi

echo
echo "🎯 Summary & Recommendations:"
echo "================================"
echo "1. False Sharing Impact:"
echo "   - Occurs when threads modify adjacent variables in same cache line"
echo "   - Causes unnecessary cache line invalidations between cores"
echo "   - Solution: Add padding to separate variables into different cache lines"
echo
echo "2. Cache Ping-Pong Effect:"
echo "   - Worst case: threads alternately access the same memory location"
echo "   - Causes cache line to bounce between cores constantly"
echo "   - Solution: Redesign algorithm to minimize shared state"
echo
echo "3. Performance Optimization:"
echo "   - Use __attribute__((aligned(64))) for critical data structures"
echo "   - Consider thread-local storage for frequently accessed data"
echo "   - Profile with 'perf c2c' for detailed cache-to-cache analysis"
echo
echo "4. Verification Commands:"
echo "   - Check cache line size: getconf LEVEL1_DCACHE_LINESIZE"
echo "   - Monitor cache behavior: perf stat -e cache-misses,cache-references <program>"
echo "   - Detailed analysis: perf c2c record <program> && perf c2c report"