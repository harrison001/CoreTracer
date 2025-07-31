#!/bin/bash

echo "=== Comprehensive TLB Performance Analysis ==="

gcc -O2 tlb_miss_demo.c -o tlb_miss_demo

echo "1. Testing 4KB pages with comprehensive perf counters"
sudo perf stat -e dTLB-loads,dTLB-load-misses,dTLB-stores,dTLB-store-misses,iTLB-loads,iTLB-load-misses,cache-misses,cache-references,instructions,cycles \
    ./tlb_miss_demo 4k 2>&1 | tee perf_4k.log

echo -e "\n2. Testing 2MB huge pages with comprehensive perf counters"  
sudo perf stat -e dTLB-loads,dTLB-load-misses,dTLB-stores,dTLB-store-misses,iTLB-loads,iTLB-load-misses,cache-misses,cache-references,instructions,cycles \
    ./tlb_miss_demo 2m 2>&1 | tee perf_2m.log

echo -e "\n=== Performance Analysis ==="

# Extract data using Python for reliable calculations
python3 -c "
import re
import sys

def extract_number(file, pattern):
    try:
        with open(file, 'r') as f:
            content = f.read()
        match = re.search(pattern, content)
        if match:
            return int(match.group(1).replace(',', ''))
        return 0
    except:
        return 0

def extract_float(file, pattern):
    try:
        with open(file, 'r') as f:
            content = f.read()
        match = re.search(pattern, content)
        if match:
            return float(match.group(1))
        return 0.0
    except:
        return 0.0

# Extract 4KB data
d_loads_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+dTLB-loads')
d_misses_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+dTLB-load-misses')
i_misses_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+iTLB-load-misses')
cache_miss_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+cache-misses')
cache_ref_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+cache-references')
cycles_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+cycles')
instr_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+instructions')
time_4k = extract_float('perf_4k.log', r'(\d+\.\d+)\s+seconds time elapsed')

# Extract 2MB data
d_loads_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+dTLB-loads')
d_misses_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+dTLB-load-misses')
i_misses_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+iTLB-load-misses')
cache_miss_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+cache-misses')
cache_ref_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+cache-references')
cycles_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+cycles')
instr_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+instructions')
time_2m = extract_float('perf_2m.log', r'(\d+\.\d+)\s+seconds time elapsed')

# Calculate improvements
print('Metric                    | 4KB Pages      | 2MB Pages      | Improvement    | Miss Rate 4K   | Miss Rate 2M')
print('--------------------------|----------------|----------------|----------------|----------------|----------------')

# Data TLB Loads
if d_loads_4k > 0 and d_loads_2m > 0:
    ratio = d_loads_4k / d_loads_2m
    print(f'Data TLB Loads           | {d_loads_4k:14,} | {d_loads_2m:14,} | {ratio:11.2f}x |                |                ')

# Data TLB Load Misses
if d_misses_4k > 0 and d_misses_2m > 0 and d_loads_4k > 0 and d_loads_2m > 0:
    improvement = d_misses_4k / d_misses_2m
    # Corrected miss rate calculation
    total_dtlb_4k = d_loads_4k + d_misses_4k
    total_dtlb_2m = d_loads_2m + d_misses_2m
    miss_rate_4k = (d_misses_4k / total_dtlb_4k) * 100
    miss_rate_2m = (d_misses_2m / total_dtlb_2m) * 100
    print(f'Data TLB Load Misses     | {d_misses_4k:14,} | {d_misses_2m:14,} | {improvement:8.0f}x fewer | {miss_rate_4k:12.2f}% | {miss_rate_2m:12.4f}%')

# Instruction TLB Misses
if i_misses_4k > 0 and i_misses_2m > 0:
    improvement = i_misses_4k / i_misses_2m
    # Extract iTLB loads for corrected miss rate
    i_loads_4k = extract_number('perf_4k.log', r'(\d+(?:,\d+)*)\s+iTLB-loads')
    i_loads_2m = extract_number('perf_2m.log', r'(\d+(?:,\d+)*)\s+iTLB-loads')
    if i_loads_4k > 0 and i_loads_2m > 0:
        total_itlb_4k = i_loads_4k + i_misses_4k
        total_itlb_2m = i_loads_2m + i_misses_2m
        i_miss_rate_4k = (i_misses_4k / total_itlb_4k) * 100
        i_miss_rate_2m = (i_misses_2m / total_itlb_2m) * 100
        print(f'Instruction TLB Misses   | {i_misses_4k:14,} | {i_misses_2m:14,} | {improvement:8.0f}x fewer | {i_miss_rate_4k:12.1f}% | {i_miss_rate_2m:12.1f}%')
    else:
        print(f'Instruction TLB Misses   | {i_misses_4k:14,} | {i_misses_2m:14,} | {improvement:8.0f}x fewer |                |                ')

# Cache Misses
if cache_miss_4k > 0 and cache_miss_2m > 0 and cache_ref_4k > 0 and cache_ref_2m > 0:
    improvement = cache_miss_4k / cache_miss_2m
    cache_rate_4k = (cache_miss_4k / cache_ref_4k) * 100
    cache_rate_2m = (cache_miss_2m / cache_ref_2m) * 100
    print(f'Cache Misses             | {cache_miss_4k:14,} | {cache_miss_2m:14,} | {improvement:11.1f}x | {cache_rate_4k:12.2f}% | {cache_rate_2m:12.2f}%')

# CPU Cycles
if cycles_4k > 0 and cycles_2m > 0:
    reduction = ((cycles_4k - cycles_2m) / cycles_4k) * 100
    print(f'CPU Cycles               | {cycles_4k:14,} | {cycles_2m:14,} | {reduction:10.1f}% less |                |                ')

# Instructions & IPC
if instr_4k > 0 and instr_2m > 0 and cycles_4k > 0 and cycles_2m > 0:
    ipc_4k = instr_4k / cycles_4k
    ipc_2m = instr_2m / cycles_2m
    ipc_improvement = ((ipc_2m - ipc_4k) / ipc_4k) * 100
    print(f'Instructions             | {instr_4k:14,} | {instr_2m:14,} | {ipc_improvement:10.1f}% better | {ipc_4k:12.3f} | {ipc_2m:12.3f}')
    print(f'                         |                |                | (IPC efficiency)| (IPC 4K)       | (IPC 2M)       ')

# Execution Time
if time_4k > 0 and time_2m > 0:
    speedup = time_4k / time_2m
    print(f'Execution Time (seconds) | {time_4k:14.3f} | {time_2m:14.3f} | {speedup:10.2f}x faster |                |                ')

print()
print('=== 🎯 PERFORMANCE HIGHLIGHTS ===')

if d_misses_4k > 0 and d_misses_2m > 0:
    tlb_improvement = d_misses_4k / d_misses_2m
    print(f'🚀 TLB Miss Reduction:    {tlb_improvement:.0f}x improvement (from {d_misses_4k:,} to {d_misses_2m:,})')

if time_4k > 0 and time_2m > 0:
    speedup = time_4k / time_2m
    time_saving = ((time_4k - time_2m) / time_4k) * 100
    print(f'⚡ Performance Speedup:   {speedup:.2f}x faster ({time_saving:.1f}% time reduction)')

if cycles_4k > 0 and cycles_2m > 0:
    cycle_reduction = ((cycles_4k - cycles_2m) / cycles_4k) * 100
    print(f'💪 CPU Efficiency:       {cycle_reduction:.1f}% fewer cycles needed')

if cache_miss_4k > 0 and cache_miss_2m > 0:
    cache_improvement = cache_miss_4k / cache_miss_2m
    print(f'🎯 Cache Performance:    {cache_improvement:.1f}x fewer cache misses')
"

echo -e "\n=== Key Insights ==="
echo "• TLB miss reduction demonstrates HugePage efficiency"
echo "• Cache performance improvement shows memory locality benefits"  
echo "• IPC improvement indicates better CPU utilization"
echo "• Overall performance gain validates HugePage adoption"

echo -e "\n[INFO] Raw perf logs: perf_4k.log, perf_2m.log"
