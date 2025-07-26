/*
 * Cache Line Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains ARM64 assembly routines to demonstrate cache line effects,
 * false sharing, cache coherency protocols, and memory access patterns
 * that affect cache performance.
 */

.section .text
.global cache_false_sharing_test_asm
.global cache_sequential_access_asm
.global cache_random_access_asm
.global cache_stride_access_asm
.global cache_flush_range_asm
.global cache_prefetch_range_asm
.global memory_latency_test_asm
.global cache_miss_benchmark_asm

/*
 * Cache false sharing test - multiple threads hitting same cache line
 * Parameters: x0 = base address
 *             x1 = thread_id (0-3)
 *             x2 = iteration count
 * Returns: number of cycles elapsed
 */
.type cache_false_sharing_test_asm, @function
cache_false_sharing_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    // Calculate offset for this thread (8 bytes apart in same cache line)
    lsl x3, x1, #3          // thread_id * 8 bytes
    add x19, x0, x3         // base + offset
    mov x20, x2             // Store iteration count
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
    // Main loop - read-modify-write operations causing false sharing
    mov x3, x20             // Load iteration count
false_sharing_loop:
    // Load current value
    ldr x4, [x19]
    
    // Modify (simple increment with some computation)
    add x4, x4, #1
    eor x4, x4, #0x5555555555555555
    
    // Store back (this will invalidate cache lines on other cores)
    str x4, [x19]
    
    // Add some work to make cache effects more visible
    ldr x5, [x19]           // Load again (may hit modified cache line)
    add x5, x5, #17         // Simple computation
    str x5, [x19]           // Store again
    
    subs x3, x3, #1
    b.ne false_sharing_loop
    
    // End timing
    mrs x22, cntvct_el0     // Read virtual counter
    sub x0, x22, x21        // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Sequential memory access pattern - cache-friendly
 * Parameters: x0 = array base address
 *             x1 = array size in elements (8-byte each)
 * Returns: cycles elapsed
 */
.type cache_sequential_access_asm, @function
cache_sequential_access_asm:
    stp x19, x20, [sp, #-16]!
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store size
    
    // Start timing
    mrs x2, cntvct_el0      // Read virtual counter
    
    // Sequential access loop
    mov x3, x19             // Current pointer
    mov x4, x20             // Counter
sequential_loop:
    // Load and modify
    ldr x5, [x3]
    add x5, x5, #1
    str x5, [x3]
    
    add x3, x3, #8          // Move to next element
    subs x4, x4, #1
    b.ne sequential_loop
    
    // End timing
    mrs x6, cntvct_el0      // Read virtual counter
    sub x0, x6, x2          // Calculate elapsed cycles
    
    ldp x19, x20, [sp], #16
    ret

/*
 * Random memory access pattern - cache-unfriendly
 * Parameters: x0 = array base address
 *             x1 = array size in elements
 *             x2 = seed for random number generation
 * Returns: cycles elapsed
 */
.type cache_random_access_asm, @function
cache_random_access_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store size
    mov x21, x2             // Store seed
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Random access loop
    mov x3, x20             // Counter
random_loop:
    // Simple LCG for pseudo-random numbers
    mov x4, #1103515245
    mul x21, x21, x4        // seed * 1103515245
    add x21, x21, #12345    // seed += 12345
    
    // Modulo operation to get array index
    udiv x5, x21, x20       // x5 = seed / size
    msub x6, x5, x20, x21   // x6 = seed % size (seed - (seed/size)*size)
    lsl x6, x6, #3          // Convert to byte offset
    
    // Access memory at random location
    ldr x7, [x19, x6]
    add x7, x7, #1
    str x7, [x19, x6]
    
    subs x3, x3, #1
    b.ne random_loop
    
    // End timing
    mrs x8, cntvct_el0      // Read virtual counter
    sub x0, x8, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Strided memory access - configurable stride for cache line testing
 * Parameters: x0 = array base address
 *             x1 = number of accesses
 *             x2 = stride in elements (8-byte each)
 * Returns: cycles elapsed
 */
.type cache_stride_access_asm, @function
cache_stride_access_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store access count
    lsl x21, x2, #3         // Convert stride to bytes
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Strided access loop
    mov x3, #0              // Current offset
    mov x4, x20             // Counter
stride_loop:
    // Access memory at current offset
    ldr x5, [x19, x3]
    add x5, x5, #1
    str x5, [x19, x3]
    
    add x3, x3, x21         // Add stride to offset
    subs x4, x4, #1
    b.ne stride_loop
    
    // End timing
    mrs x6, cntvct_el0      // Read virtual counter
    sub x0, x6, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Flush a range of cache lines
 * Parameters: x0 = start address
 *             x1 = size in bytes
 */
.type cache_flush_range_asm, @function
cache_flush_range_asm:
    add x1, x0, x1          // End address
    
flush_loop:
    dc civac, x0            // Clean and invalidate by VA to PoC
    add x0, x0, #64         // Move to next cache line (assuming 64-byte lines)
    cmp x0, x1
    b.lt flush_loop
    
    dsb sy                  // Ensure all flushes complete
    ret

/*
 * Prefetch a range of memory
 * Parameters: x0 = start address
 *             x1 = size in bytes
 */
.type cache_prefetch_range_asm, @function
cache_prefetch_range_asm:
    add x1, x0, x1          // End address
    
prefetch_loop:
    prfm pldl1keep, [x0]    // Prefetch for load to L1 cache
    add x0, x0, #64         // Move to next cache line
    cmp x0, x1
    b.lt prefetch_loop
    
    ret

/*
 * Memory latency test - measures latency of memory access
 * Parameters: x0 = memory address
 *             x1 = number of iterations
 * Returns: average latency in cycles
 */
.type memory_latency_test_asm, @function
memory_latency_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store address
    mov x20, x1             // Store iterations
    mov x21, #0             // Total cycles
    
latency_loop:
    // Flush the cache line to ensure we measure memory latency
    dc civac, x19           // Clean and invalidate by VA to PoC
    dsb sy                  // Data synchronization barrier
    
    // Start timing
    mrs x2, cntvct_el0      // Read virtual counter
    
    // Access memory
    ldr x3, [x19]           // This should go to main memory
    
    // End timing
    mrs x4, cntvct_el0      // Read virtual counter
    sub x5, x4, x2          // Calculate elapsed cycles
    add x21, x21, x5        // Accumulate total
    
    subs x20, x20, #1
    b.ne latency_loop
    
    // Calculate average
    udiv x0, x21, x1        // x0 = total / iterations
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Cache miss benchmark - compares cache hits vs misses
 * Parameters: x0 = array address
 *             x1 = array size (elements)
 *             x2 = test type (0=hits, 1=misses)
 * Returns: cycles elapsed
 */
.type cache_miss_benchmark_asm, @function
cache_miss_benchmark_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store array address
    mov x20, x1             // Store array size
    mov x21, x2             // Store test type
    
    // Test preparation
    cmp x21, #0
    b.eq cache_hits_test
    
    // Cache misses test - flush entire array first
    mov x0, x19
    lsl x1, x20, #3         // Convert elements to bytes
    bl cache_flush_range_asm
    b benchmark_start
    
cache_hits_test:
    // Cache hits test - warm up the cache first
    mov x3, x19             // Start address
    mov x4, x20             // Counter
warmup_loop:
    ldr x5, [x3]            // Load to warm cache
    add x3, x3, #8
    subs x4, x4, #1
    b.ne warmup_loop
    
benchmark_start:
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Main benchmark loop
    mov x3, x19             // Current address
    mov x4, x20             // Counter
benchmark_loop:
    ldr x5, [x3]            // Load from memory
    add x5, x5, #1          // Modify
    str x5, [x3]            // Store back
    
    add x3, x3, #8          // Next element
    subs x4, x4, #1
    b.ne benchmark_loop
    
    // End timing
    mrs x6, cntvct_el0      // Read virtual counter
    sub x0, x6, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

.section .note.GNU-stack,"",@progbits