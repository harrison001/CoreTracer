# CoreTracer

High-performance kernel & assembly debugging toolkit for CPU affinity, NUMA, lock-free data structures, cacheline effects, and memory bank conflicts.

**Components:**
- Kernel drivers with /proc interfaces for interactive testing
- Cross-architecture assembly (x86-64 Intel + ARM64) 
- Rust performance benchmarks
- Build system supporting multiple architectures

**Tech Stack:** C, Rust, Linux kernel modules, x86-64/ARM64 assembly

---

## Features

### Core Multi-Threading
- CPU Affinity & NUMA topology testing
- Lock-free data structures (ring buffers, stacks, queues)
- Cache line false sharing demonstration
- Memory bank conflict patterns

### Advanced Memory Analysis
- HugePage/THP allocation across NUMA nodes
- TLB shootdown performance impact
- Memory barriers and fence instructions
- Cache prefetch behavior analysis

### Hardware-Level Testing
- Out-of-order execution effects
- Speculative execution side-effects
- Memory consistency models

### Kernel Synchronization
- Deadlock/livelock/priority inversion scenarios
- Kernel preemption analysis
- Per-CPU vs global variable performance
- Interrupt handling load testing

---

## Project Structure

```
CoreTracer/
├── drivers/                    # Kernel modules with /proc interfaces
│   ├── affinity_numa_demo.c    # CPU binding & NUMA effects
│   ├── lockfree_ring_demo.c    # Lock-free ring buffer races  
│   ├── cacheline_false_demo.c  # False sharing demonstration
│   ├── bank_conflict_demo.c    # Memory bank serialization
│   ├── hugepage_numa_demo.c    # Large page NUMA allocation
│   ├── memory_barrier_demo.c   # Fence/barrier consistency  
│   ├── tlb_demo.c              # TLB shootdown effects
│   ├── deadlock_demo.c         # Deadlock scenarios
│   ├── preemption_demo.c       # Kernel preemption analysis
│   └── percpu_demo.c           # Per-CPU vs global variables
│
├── asm/                        # Hand-optimized assembly
│   ├── lockfree_asm.S          # x86-64 Intel syntax lock-free  
│   ├── lockfree_asm_arm.S      # ARM64 lock-free primitives
│   ├── cacheline_asm.S         # x86-64 cache line manipulation
│   ├── cacheline_asm_arm.S     # ARM64 cache operations
│   ├── tlb_shootdown.S         # TLB manipulation assembly
│   ├── prefetch_pollution.S    # Cache prefetch experiments
│   ├── ooo_execution.S         # Out-of-order instruction demos
│   └── speculative_demo.S      # Speculative execution tests
│
├── rust_demo/                  # Rust performance benchmarks
├── scripts/                    # Automated analysis tools  
├── docs/                       # Deep-dive case studies
└── Makefile                    # Cross-architecture build system
```

---

## Quick Start

```bash
# Build everything (drivers + assembly + Rust)
make build

# Load kernel modules and run basic tests  
make demo

# Advanced profiling and analysis
make profile

# Set up debugging environment
make debug

# Cross-architecture assembly compilation
make asm
```

---

## License

MIT License
