//! CoreTracer Rust Demo Library
//! 
//! High-performance Rust implementations demonstrating kernel-level debugging
//! and profiling concepts including CPU affinity, NUMA, lock-free data structures,
//! cache effects, and memory bank conflicts.

pub mod affinity;
pub mod lockfree;
pub mod cache;
pub mod memory;
pub mod perf;

use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};

/// High-precision timing utilities
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            start: Instant::now(),
        }
    }
    
    pub fn elapsed_nanos(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }
    
    pub fn elapsed_cycles(&self) -> u64 {
        // Rough approximation - would need CPU frequency for accuracy
        self.elapsed_nanos() * 3  // Assume ~3GHz CPU
    }
}

/// CPU cycle counter using assembly
pub fn get_cpu_cycles() -> u64 {
    unsafe {
        let mut low: u32;
        let mut high: u32;
        std::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
        );
        ((high as u64) << 32) | (low as u64)
    }
}

/// CPU pause hint for spin loops
pub fn cpu_pause() {
    unsafe {
        std::arch::asm!("pause");
    }
}

/// Memory barrier
pub fn memory_barrier() {
    std::sync::atomic::fence(Ordering::SeqCst);
}

/// Cache line size detection
pub fn cache_line_size() -> usize {
    // Most modern x86_64 systems use 64-byte cache lines
    64
}

/// Global performance counters
pub static OPERATIONS_COMPLETED: AtomicU64 = AtomicU64::new(0);
pub static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
pub static LOCK_CONTENTIONS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timer() {
        let timer = Timer::new();
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(timer.elapsed_nanos() > 1_000_000);
    }
    
    #[test]
    fn test_cpu_cycles() {
        let start = get_cpu_cycles();
        for _ in 0..1000 {
            cpu_pause();
        }
        let end = get_cpu_cycles();
        assert!(end > start);
    }
}