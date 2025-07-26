/*
 * Speculative Execution Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains ARM64 assembly routines to demonstrate speculative
 * execution effects, branch prediction, and speculative memory access
 * patterns on ARM processors.
 */

.section .text
.global speculative_branch_test_asm
.global speculative_memory_access_asm
.global indirect_branch_test_asm
.global speculative_cache_timing_asm
.global branch_target_buffer_test_asm
.global return_stack_buffer_test_asm
.global speculative_store_bypass_asm

/*
 * Branch prediction speculation test
 * Parameters: x0 = array base address
 *             x1 = array size
 *             x2 = pattern type (0=predictable, 1=random, 2=mixed)
 * Returns: cycles elapsed in x0
 */
.type speculative_branch_test_asm, @function
speculative_branch_test_asm:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    
    mov x19, x0             // Store array address
    mov x20, x1             // Store array size
    mov x21, x2             // Store pattern type
    mov x22, #12345         // Random seed
    mov x23, #0             // Sum accumulator
    
    // Start timing
    mrs x24, cntvct_el0     // Read virtual counter
    
    mov x3, #0              // Index
    
speculation_loop:
    // Generate branch condition based on pattern
    cmp x21, #0
    b.eq predictable_branch
    cmp x21, #1
    b.eq random_branch
    
mixed_branch:
    // Mixed pattern - alternates between predictable and random
    tbnz x3, #8, predictable_branch    // Every 256 iterations
    b random_branch
    
predictable_branch:
    // Predictable pattern - alternating
    tbnz x3, #0, spec_branch_taken
    b spec_branch_not_taken
    
random_branch:
    // Generate pseudo-random condition
    mov x4, #1103515245
    mul x5, x22, x4
    add x22, x5, #12345     // Update seed
    tbnz x22, #7, spec_branch_taken
    
spec_branch_not_taken:
    // Branch not taken path
    lsl x5, x3, #3          // Convert to byte offset
    ldr x6, [x19, x5]       // Load element
    add x23, x23, x6        // Accumulate
    b spec_continue
    
spec_branch_taken:
    // Branch taken path - simulate expensive operation
    lsl x5, x3, #3          // Convert to byte offset
    ldr x6, [x19, x5]       // Load element
    mov x7, #3
    mul x6, x6, x7          // Expensive multiply
    add x6, x6, #1000       // Additional work
    add x23, x23, x6        // Accumulate
    
spec_continue:
    add x3, x3, #1          // Next index
    cmp x3, x20
    b.lt speculation_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x24         // Calculate elapsed cycles
    
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

/*
 * Speculative memory access test
 * Parameters: x0 = primary array
 *             x1 = secondary array (for speculation)
 *             x2 = size
 *             x3 = speculation depth
 * Returns: cycles elapsed in x0
 */
.type speculative_memory_access_asm, @function
speculative_memory_access_asm:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    
    mov x19, x0             // Primary array
    mov x20, x1             // Secondary array
    mov x21, x2             // Size
    mov x22, x3             // Speculation depth
    mov x23, #12345         // Random seed
    
    // Start timing
    mrs x24, cntvct_el0     // Read virtual counter
    
    mov x3, #0              // Index
    
spec_memory_loop:
    // Generate condition for speculation
    mov x4, #1103515245
    mul x5, x23, x4
    add x23, x5, #12345     // Update seed
    
    // Check if we should speculate
    and x6, x23, #0x3F      // Check low 6 bits
    cbnz x6, no_speculation
    
    // Speculative path - access secondary array
    add x4, x3, x22         // Add speculation depth
    cmp x4, x21
    b.ge no_speculation     // Bounds check
    
    // Speculative memory accesses
    lsl x5, x4, #3          // Convert to byte offset
    ldr x6, [x20, x5]       // Speculative load 1
    add x4, x4, #1
    cmp x4, x21
    b.ge spec_memory_continue
    lsl x5, x4, #3
    ldr x7, [x20, x5]       // Speculative load 2
    add x6, x6, x7          // Use speculative data
    
spec_memory_continue:
    b normal_access
    
no_speculation:
    mov x6, #0              // No speculative value
    
normal_access:
    // Normal memory access
    lsl x5, x3, #3          // Convert to byte offset
    ldr x7, [x19, x5]       // Load element
    add x7, x7, x6          // Combine with speculative result
    str x7, [x19, x5]       // Store back
    
    add x3, x3, #1          // Next index
    cmp x3, x21
    b.lt spec_memory_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x24         // Calculate elapsed cycles
    
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

/*
 * Indirect branch speculation test
 * Parameters: x0 = function pointer array
 *             x1 = array size
 *             x2 = call pattern (0=sequential, 1=random)
 * Returns: cycles elapsed in x0
 */
.type indirect_branch_test_asm, @function
indirect_branch_test_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Function pointer array
    mov x20, x1             // Array size
    mov x21, x2             // Call pattern
    mov x22, #12345         // Random seed
    
    // Start timing
    mrs x23, cntvct_el0     // Read virtual counter
    
    mov x3, #0              // Index
    mov x24, #1000          // Iteration count
    
indirect_loop:
    // Determine which function to call
    cmp x21, #0
    b.eq sequential_calls
    
random_calls:
    // Random function selection
    mov x4, #1103515245
    mul x5, x22, x4
    add x22, x5, #12345     // Update seed
    udiv x6, x22, x20       // x6 = seed / size
    msub x2, x6, x20, x22   // x2 = seed % size
    b call_function
    
sequential_calls:
    udiv x4, x3, x20        // x4 = index / size
    msub x2, x4, x20, x3    // x2 = index % size
    
call_function:
    // Load function pointer and simulate indirect call
    lsl x4, x2, #3          // Convert to byte offset
    ldr x5, [x19, x4]       // Load function pointer
    cbz x5, skip_call       // Check for null pointer
    
    // Simulate indirect call without actually calling
    ldr x6, [x5]            // Dereference as if calling
    
skip_call:
    add x3, x3, #1          // Next index
    subs x24, x24, #1
    b.ne indirect_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x23         // Calculate elapsed cycles
    
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

/*
 * Speculative cache timing attack simulation
 * Parameters: x0 = secret data address
 *             x1 = probe array address
 *             x2 = probe array size
 * Returns: inferred data in x0
 */
.type speculative_cache_timing_asm, @function
speculative_cache_timing_asm:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    
    mov x19, x0             // Secret data address
    mov x20, x1             // Probe array address
    mov x21, x2             // Probe array size
    
    // Flush probe array from cache
    mov x3, #0
flush_loop:
    add x4, x20, x3         // Calculate address
    dc civac, x4            // Clean and invalidate by VA to PoC
    add x3, x3, #64         // Next cache line (64-byte lines)
    cmp x3, x21
    b.lt flush_loop
    
    dsb sy                  // Ensure flushes complete
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
    // Speculative access pattern
    ldrb w0, [x19]          // Load secret byte
    and x0, x0, #0xFF       // Mask to byte value
    
    // Use secret as index into probe array (speculative)
    lsl x0, x0, #6          // Scale by cache line size (64 bytes)
    ldr x4, [x20, x0]       // Access probe array (brings into cache)
    
    dsb sy                  // Ensure speculation completes
    
    // Timing-based inference
    mov x23, #0             // Best candidate
    mov x3, #0              // Current index
    mov x24, #0xFFFFFFFF    // Best time (start with max)
    
timing_loop:
    // Time access to each probe array location
    mrs x5, cntvct_el0      // Start timing
    
    lsl x4, x3, #6          // Scale by cache line size
    ldr x6, [x20, x4]       // Access probe location
    
    mrs x7, cntvct_el0      // End timing
    sub x7, x7, x5          // Calculate access time
    
    // Check if this is the fastest access (likely cached)
    cmp x7, x24
    b.ge not_fastest
    mov x24, x7             // Update best time
    mov x23, x3             // Update best candidate
    
not_fastest:
    add x3, x3, #1          // Next index
    cmp x3, #256            // Check all possible byte values
    b.lt timing_loop
    
    mov x0, x23             // Return inferred secret value
    
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

/*
 * Branch Target Buffer (BTB) test
 * Parameters: x0 = target array
 *             x1 = array size
 * Returns: cycles elapsed in x0
 */
.type branch_target_buffer_test_asm, @function
branch_target_buffer_test_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Target array
    mov x20, x1             // Array size
    mov x21, #1000          // Iteration count
    
    // Start timing
    mrs x22, cntvct_el0     // Read virtual counter
    
btb_loop:
    mov x3, #0              // Index
    
btb_inner_loop:
    // Calculate jump target based on index
    and x4, x3, #7          // Modulo 8 for target selection
    adr x5, btb_target_table
    ldr x6, [x5, x4, lsl #3] // Load target address
    br x6                   // Indirect branch
    
btb_target_0:
    lsl x7, x3, #3          // Convert to byte offset
    ldr x8, [x19, x7]       // Load element
    add x8, x8, #1          // Increment
    str x8, [x19, x7]       // Store back
    b btb_continue
    
btb_target_1:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #2
    str x8, [x19, x7]
    b btb_continue
    
btb_target_2:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #3
    str x8, [x19, x7]
    b btb_continue
    
btb_target_3:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #4
    str x8, [x19, x7]
    b btb_continue
    
btb_target_4:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #5
    str x8, [x19, x7]
    b btb_continue
    
btb_target_5:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #6
    str x8, [x19, x7]
    b btb_continue
    
btb_target_6:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #7
    str x8, [x19, x7]
    b btb_continue
    
btb_target_7:
    lsl x7, x3, #3
    ldr x8, [x19, x7]
    add x8, x8, #8
    str x8, [x19, x7]
    
btb_continue:
    add x3, x3, #1          // Next index
    cmp x3, x20
    b.lt btb_inner_loop
    
    subs x21, x21, #1
    b.ne btb_loop
    b btb_end
    
    // Jump target table
    .align 3
btb_target_table:
    .quad btb_target_0
    .quad btb_target_1
    .quad btb_target_2
    .quad btb_target_3
    .quad btb_target_4
    .quad btb_target_5
    .quad btb_target_6
    .quad btb_target_7
    
btb_end:
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x22         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Return Stack Buffer (RSB) test
 * Parameters: x0 = iteration count
 * Returns: cycles elapsed in x0
 */
.type return_stack_buffer_test_asm, @function
return_stack_buffer_test_asm:
    stp x19, x20, [sp, #-16]!
    
    mov x19, x0             // Store iteration count
    
    // Start timing
    mrs x20, cntvct_el0     // Read virtual counter
    
rsb_loop:
    // Call sequence to exercise RSB
    bl rsb_func_1
    bl rsb_func_2
    bl rsb_func_3
    bl rsb_func_4
    
    subs x19, x19, #1
    b.ne rsb_loop
    b rsb_end
    
rsb_func_1:
    nop
    nop
    ret
    
rsb_func_2:
    nop
    nop
    ret
    
rsb_func_3:
    nop
    nop
    ret
    
rsb_func_4:
    nop
    nop
    ret
    
rsb_end:
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x20         // Calculate elapsed cycles
    
    ldp x19, x20, [sp], #16
    ret

/*
 * Speculative store bypass test
 * Parameters: x0 = memory buffer
 *             x1 = iteration count
 * Returns: cycles elapsed in x0
 */
.type speculative_store_bypass_asm, @function
speculative_store_bypass_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Memory buffer
    mov x20, x1             // Iteration count
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
store_bypass_loop:
    // Store to memory
    str x20, [x19]          // Store value
    
    // Speculative load from potentially aliasing address
    ldr x2, [x19, #4]       // Load from nearby address
    
    // Use speculative value
    add x2, x2, #1
    str x2, [x19, #8]       // Store result
    
    // Store that may conflict with earlier speculative load
    str x20, [x19, #4]      // Store to previously loaded address
    
    // Dependent load that will show store bypass effects
    ldr x3, [x19, #4]       // This should see the store value
    add x3, x3, x2          // Combine with speculative result
    
    subs x20, x20, #1
    b.ne store_bypass_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

.section .note.GNU-stack,"",@progbits