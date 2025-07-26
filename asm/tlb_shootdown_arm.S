/*
 * TLB Shootdown Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains ARM64 assembly routines to demonstrate TLB operations,
 * shootdown effects, and their performance impact on multi-core systems.
 */

.section .text
.global tlb_flush_single_asm
.global tlb_flush_all_asm
.global tlb_shootdown_benchmark_asm
.global page_walk_timing_asm
.global tlb_miss_generator_asm
.global tlb_interference_test_asm
.global tlb_capacity_test_asm

/*
 * Flush a single page from TLB
 * Parameters: x0 = virtual address to flush
 */
.type tlb_flush_single_asm, @function
tlb_flush_single_asm:
    tlbi vaae1, x0          // TLB invalidate by VA, all ASID, EL1
    dsb sy                  // Data synchronization barrier
    isb                     // Instruction synchronization barrier
    ret

/*
 * Flush entire TLB
 */
.type tlb_flush_all_asm, @function
tlb_flush_all_asm:
    tlbi vmalle1            // TLB invalidate all, EL1
    dsb sy                  // Data synchronization barrier
    isb                     // Instruction synchronization barrier
    ret

/*
 * TLB shootdown benchmark - measures cost of TLB invalidation
 * Parameters: x0 = array of virtual addresses
 *             x1 = number of addresses
 *             x2 = iterations
 * Returns: cycles elapsed in x0
 */
.type tlb_shootdown_benchmark_asm, @function
tlb_shootdown_benchmark_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store address array
    mov x20, x1             // Store count
    mov x21, x2             // Store iterations
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Benchmark loop
    mov x3, x21             // Load iteration count
benchmark_loop:
    mov x4, x20             // Load address count
    mov x5, x19             // Load address array
    
invalidate_loop:
    ldr x6, [x5]            // Load virtual address
    lsr x6, x6, #12         // Convert to page number
    lsl x6, x6, #12         // Align to page boundary
    tlbi vaae1, x6          // Invalidate TLB entry
    add x5, x5, #8          // Next address
    subs x4, x4, #1
    b.ne invalidate_loop
    
    dsb sy                  // Ensure all invalidations complete
    
    subs x3, x3, #1
    b.ne benchmark_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Page walk timing test - measures page table walk latency
 * Parameters: x0 = virtual address to access
 *             x1 = access count
 * Returns: average cycles per access in x0
 */
.type page_walk_timing_asm, @function
page_walk_timing_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store address
    mov x20, x1             // Store access count
    mov x21, #0             // Total cycles
    
    // Ensure TLB is cold for this address
    lsr x2, x19, #12
    lsl x2, x2, #12         // Align to page
    tlbi vaae1, x2
    dsb sy
    isb
    
timing_loop:
    // Start timing
    mrs x2, cntvct_el0      // Read virtual counter
    
    // Access memory (forces page table walk if TLB miss)
    ldr x3, [x19]
    
    // End timing
    mrs x4, cntvct_el0      // Read virtual counter
    sub x4, x4, x2          // Calculate elapsed cycles
    add x21, x21, x4        // Accumulate total
    
    // Flush TLB again for next iteration
    lsr x2, x19, #12
    lsl x2, x2, #12
    tlbi vaae1, x2
    dsb sy
    isb
    
    subs x20, x20, #1
    b.ne timing_loop
    
    // Calculate average
    udiv x0, x21, x1        // x0 = total / count
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * TLB miss generator - creates predictable TLB misses
 * Parameters: x0 = base address
 *             x1 = stride (bytes)
 *             x2 = access count
 * Returns: cycles elapsed in x0
 */
.type tlb_miss_generator_asm, @function
tlb_miss_generator_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store stride
    mov x21, x2             // Store access count
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    mov x3, x21             // Load access count
    mov x4, x19             // Start address
    
miss_loop:
    // Access memory location
    ldr x5, [x4]
    
    // Move to next location with stride
    add x4, x4, x20
    
    // Invalidate current page to force TLB miss on next access
    sub x6, x4, x20         // Previous address
    lsr x6, x6, #12
    lsl x6, x6, #12         // Align to page
    tlbi vaae1, x6
    
    subs x3, x3, #1
    b.ne miss_loop
    
    dsb sy                  // Ensure all invalidations complete
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Multi-core TLB interference test
 * Parameters: x0 = shared memory region
 *             x1 = region size
 *             x2 = core ID
 * Returns: cycles elapsed in x0
 */
.type tlb_interference_test_asm, @function
tlb_interference_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store region size
    mov x21, x2             // Store core ID
    
    // Calculate starting offset for this core
    lsl x3, x21, #12        // Core ID * 4KB (page size)
    add x19, x19, x3        // Offset into shared region
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Access pattern that causes TLB conflicts
    mov x3, #1000           // Number of iterations
    mov x4, x19             // Start address
    
interference_loop:
    // Access multiple pages in sequence
    mov x5, #16             // Number of pages to touch
page_touch_loop:
    ldr x6, [x4]            // Touch page
    add x4, x4, #4096       // Next page (4KB)
    subs x5, x5, #1
    b.ne page_touch_loop
    
    // Reset to start
    mov x4, x19
    
    // Introduce some TLB invalidations
    lsr x5, x4, #12
    lsl x5, x5, #12
    tlbi vaae1, x5
    
    add x4, x4, #4096
    lsr x5, x4, #12
    lsl x5, x5, #12
    tlbi vaae1, x5
    
    add x4, x4, #4096
    lsr x5, x4, #12
    lsl x5, x5, #12
    tlbi vaae1, x5
    
    dsb sy                  // Ensure invalidations complete
    
    // Reset for next iteration
    mov x4, x19
    
    subs x3, x3, #1
    b.ne interference_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * TLB entry count estimation
 * Parameters: x0 = base address
 *             x1 = max pages to test
 * Returns: estimated TLB entries in x0
 */
.type tlb_capacity_test_asm, @function
tlb_capacity_test_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Store base address
    mov x20, x1             // Store max pages
    mov x21, #0             // Current page count
    mov x22, #0             // Baseline latency
    
capacity_test_loop:
    // Access pages sequentially to warm TLB
    mov x3, x21             // Current page count
    mov x4, x19             // Base address
    
warmup_loop:
    ldr x5, [x4]            // Touch page
    add x4, x4, #4096       // Next page
    subs x3, x3, #1
    b.ne warmup_loop
    
    // Measure access latency for first page
    mrs x23, cntvct_el0     // Start time
    ldr x5, [x19]           // Access first page
    mrs x24, cntvct_el0     // End time
    sub x24, x24, x23       // Latency
    
    // Check if latency increased significantly (TLB overflow)
    cbz x22, set_baseline   // First measurement?
    
    // Compare with baseline
    lsl x3, x22, #1         // 2x baseline
    cmp x24, x3
    b.gt tlb_overflow       // Latency > 2x baseline = TLB overflow
    
    b continue_test
    
set_baseline:
    mov x22, x24            // Set baseline latency
    
continue_test:
    add x21, x21, #1        // Next page count
    cmp x21, x20            // Check limit
    b.lt capacity_test_loop
    
    // Return max pages if no overflow detected
    mov x0, x20
    b capacity_done
    
tlb_overflow:
    mov x0, x21             // Return page count where overflow occurred
    
capacity_done:
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

.section .note.GNU-stack,"",@progbits