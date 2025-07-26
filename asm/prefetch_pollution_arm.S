/*
 * Cache Prefetch and Pollution Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains ARM64 assembly routines to demonstrate hardware prefetcher
 * behavior, manual prefetch instructions, cache pollution effects, and their
 * impact on memory performance.
 */

.section .text
.global manual_prefetch_test_asm
.global hardware_prefetch_test_asm
.global cache_pollution_test_asm
.global prefetch_distance_test_asm
.global stream_prefetch_asm
.global random_prefetch_asm
.global cache_bypass_test_asm

/*
 * Manual prefetch effectiveness test
 * Parameters: x0 = array base address
 *             x1 = array size (elements)
 *             x2 = prefetch distance (elements ahead)
 * Returns: cycles elapsed in x0
 */
.type manual_prefetch_test_asm, @function
manual_prefetch_test_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store array size
    mov x21, x2             // Store prefetch distance
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Manual prefetch loop
    mov x3, #0              // Current index
    mov x4, x20             // Element count
    
prefetch_loop:
    // Calculate prefetch address (current + distance)
    add x5, x3, x21         // Add prefetch distance
    cmp x5, x20             // Check bounds
    b.ge skip_prefetch      // Skip if beyond array
    
    // Prefetch future data
    lsl x6, x5, #3          // Convert to byte offset
    add x6, x19, x6         // Address = base + offset
    prfm pldl1keep, [x6]    // Prefetch to L1 cache
    
skip_prefetch:
    // Access current element
    lsl x6, x3, #3          // Convert index to byte offset
    ldr x7, [x19, x6]       // Load current element
    add x7, x7, #1          // Simple computation
    str x7, [x19, x6]       // Store back
    
    add x3, x3, #1          // Next element
    subs x4, x4, #1
    b.ne prefetch_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

/*
 * Hardware prefetcher test - linear access to trigger HW prefetcher
 * Parameters: x0 = array base address
 *             x1 = array size (elements)
 * Returns: cycles elapsed in x0
 */
.type hardware_prefetch_test_asm, @function
hardware_prefetch_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store array size
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
    // Linear access to trigger hardware prefetcher
    mov x2, #0              // Current index
    mov x3, x20             // Element count
    
hw_prefetch_loop:
    // Sequential access (hardware prefetcher friendly)
    lsl x4, x2, #3          // Convert to byte offset
    ldr x5, [x19, x4]       // Load element
    add x5, x5, #1          // Modify
    str x5, [x19, x4]       // Store back
    
    add x2, x2, #1          // Next element
    subs x3, x3, #1
    b.ne hw_prefetch_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Cache pollution test
 * Parameters: x0 = main array address
 *             x1 = main array size
 *             x2 = pollution array address
 *             x3 = pollution array size
 * Returns: cycles elapsed for main array access in x0
 */
.type cache_pollution_test_asm, @function
cache_pollution_test_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Main array
    mov x20, x1             // Main array size
    mov x21, x2             // Pollution array
    mov x22, x3             // Pollution array size
    
    // First, warm up the cache with main array
    mov x4, #0              // Index
warmup_loop:
    lsl x5, x4, #3          // Convert to byte offset
    ldr x6, [x19, x5]       // Load element
    add x4, x4, #1          // Next index
    cmp x4, x20
    b.lt warmup_loop
    
    // Start timing
    mrs x23, cntvct_el0     // Read virtual counter
    
    // Access main array
    mov x4, #0              // Current index
main_access_loop:
    lsl x5, x4, #3          // Convert to byte offset
    ldr x6, [x19, x5]       // Load element
    add x6, x6, #1          // Modify
    str x6, [x19, x5]       // Store back
    
    // Interleave with pollution accesses every 4 elements
    and x7, x4, #3          // Check if index % 4 == 0
    cbnz x7, skip_pollution
    
    // Pollute cache with random access to pollution array
    and x7, x4, #0xFF       // Use low 8 bits for pollution index
    cmp x7, x22
    b.ge skip_pollution
    lsl x8, x7, #3          // Convert to byte offset
    ldr x9, [x21, x8]       // Pollution access
    
skip_pollution:
    add x4, x4, #1          // Next element
    cmp x4, x20
    b.lt main_access_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x23         // Calculate elapsed cycles
    
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

/*
 * Prefetch distance optimization test
 * Parameters: x0 = array base address
 *             x1 = array size
 *             x2 = maximum prefetch distance to test
 * Returns: optimal distance in x0
 */
.type prefetch_distance_test_asm, @function
prefetch_distance_test_asm:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store array size
    mov x21, x2             // Store max prefetch distance
    mov x22, #0             // Best time so far
    mov x23, #1             // Best distance (start with 1)
    
distance_test_loop:
    mov x24, x23            // Current distance to test
    
    // Start timing for this distance
    mrs x25, cntvct_el0     // Read virtual counter
    
    // Run prefetch test with current distance
    mov x3, #0              // Array index
    mov x4, x20             // Element count
    
distance_access_loop:
    // Calculate prefetch address
    add x5, x3, x24         // Add current distance
    cmp x5, x20
    b.ge skip_distance_prefetch
    
    // Prefetch
    lsl x6, x5, #3          // Convert to byte offset
    add x6, x19, x6         // Calculate address
    prfm pldl1keep, [x6]    // Prefetch
    
skip_distance_prefetch:
    // Access current element
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load
    add x7, x7, #1          // Modify
    str x7, [x19, x6]       // Store
    
    add x3, x3, #1          // Next element
    subs x4, x4, #1
    b.ne distance_access_loop
    
    // End timing for this distance
    mrs x26, cntvct_el0     // Read virtual counter
    sub x26, x26, x25       // Calculate elapsed time
    
    // Check if this is the best time so far
    cbz x22, set_new_best   // First measurement?
    cmp x26, x22            // Compare with best time
    b.ge not_better
    
set_new_best:
    mov x22, x26            // Update best time
    mov x23, x24            // Update best distance
    
not_better:
    add x24, x24, #1        // Next distance
    cmp x24, x21            // Check against max
    b.le distance_test_loop
    
    mov x0, x23             // Return best distance
    
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

/*
 * Streaming prefetch test - optimized for memory bandwidth
 * Parameters: x0 = source array
 *             x1 = destination array
 *             x2 = size (elements)
 * Returns: cycles elapsed in x0
 */
.type stream_prefetch_asm, @function
stream_prefetch_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Source array
    mov x20, x1             // Destination array
    mov x21, x2             // Size
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Streaming copy with aggressive prefetch
    mov x3, #0              // Current index
    mov x4, x21             // Element count
    
stream_loop:
    // Prefetch multiple cache lines ahead
    add x5, x3, #8          // Prefetch 8 elements ahead
    cmp x5, x21
    b.ge skip_stream_prefetch1
    lsl x6, x5, #3          // Convert to byte offset
    add x7, x19, x6         // Source prefetch address
    add x8, x20, x6         // Destination prefetch address
    prfm pldl1keep, [x7]    // Prefetch source
    prfm pstl1keep, [x8]    // Prefetch destination for store
    
skip_stream_prefetch1:
    add x5, x3, #16         // Also prefetch 16 ahead
    cmp x5, x21
    b.ge skip_stream_prefetch2
    lsl x6, x5, #3
    add x7, x19, x6
    add x8, x20, x6
    prfm pldl1keep, [x7]
    prfm pstl1keep, [x8]
    
skip_stream_prefetch2:
    // Perform the actual copy
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load from source
    str x7, [x20, x6]       // Store to destination
    
    add x3, x3, #1          // Next element
    subs x4, x4, #1
    b.ne stream_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Random access with prefetch hints
 * Parameters: x0 = array base
 *             x1 = array size
 *             x2 = random seed
 * Returns: cycles elapsed in x0
 */
.type random_prefetch_asm, @function
random_prefetch_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Array base
    mov x20, x1             // Array size
    mov x21, x2             // Random seed
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Random access loop
    mov x3, x20             // Access count
    
random_loop:
    // Generate pseudo-random index
    mov x4, #1103515245
    mul x5, x21, x4         // x5 = seed * 1103515245
    add x21, x5, #12345     // seed += 12345
    
    // Get array index
    udiv x6, x21, x20       // x6 = seed / size
    msub x7, x6, x20, x21   // x7 = seed % size
    
    // Try to predict next access and prefetch
    mov x4, #1103515245
    mul x5, x21, x4
    add x5, x5, #12345
    udiv x6, x5, x20
    msub x8, x6, x20, x5    // Next predicted index
    
    cmp x8, x20
    b.ge skip_random_prefetch
    lsl x9, x8, #3          // Convert to byte offset
    add x9, x19, x9         // Calculate address
    prfm pldl1keep, [x9]    // Prefetch next predicted access
    
skip_random_prefetch:
    // Access current element
    lsl x8, x7, #3          // Convert to byte offset
    ldr x9, [x19, x8]       // Load
    add x9, x9, #1          // Modify
    str x9, [x19, x8]       // Store
    
    subs x3, x3, #1
    b.ne random_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Cache bypass test using non-temporal stores
 * Note: ARM64 doesn't have direct equivalent to x86 non-temporal stores,
 * but we can use cache maintenance instructions to achieve similar effects
 * Parameters: x0 = array base
 *             x1 = array size
 * Returns: cycles elapsed in x0
 */
.type cache_bypass_test_asm, @function
cache_bypass_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Array base
    mov x20, x1             // Array size
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
    // Store with cache bypass simulation
    mov x2, #0              // Current index
    mov x3, x20             // Element count
    
bypass_loop:
    lsl x4, x2, #3          // Convert to byte offset
    add x5, x19, x4         // Calculate address
    
    // Store data
    str x2, [x5]            // Store index as data
    
    // Clean from cache to simulate bypass
    dc civac, x5            // Clean and invalidate by VA to PoC
    
    add x2, x2, #1          // Next element
    subs x3, x3, #1
    b.ne bypass_loop
    
    // Ensure all operations complete
    dsb sy                  // Data synchronization barrier
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

.section .note.GNU-stack,"",@progbits