/*
 * Out-of-Order Execution Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains ARM64 assembly routines to demonstrate out-of-order
 * execution effects, instruction reordering, pipeline behavior, and their
 * impact on performance.
 */

.section .text
.global ooo_dependency_chain_asm
.global ooo_independent_ops_asm
.global ooo_memory_disambiguation_asm
.global ooo_branch_prediction_asm
.global ooo_register_renaming_asm
.global ooo_store_forwarding_asm
.global ooo_pipeline_stall_asm

/*
 * Dependency chain test - forces in-order execution
 * Parameters: x0 = iteration count
 * Returns: cycles elapsed in x0
 */
.type ooo_dependency_chain_asm, @function
ooo_dependency_chain_asm:
    stp x19, x20, [sp, #-16]!
    
    mov x19, x0             // Store iteration count
    
    // Start timing
    mrs x20, cntvct_el0     // Read virtual counter
    
    // Initialize value
    mov x0, #1
    
dependency_loop:
    // Long dependency chain - each instruction depends on previous
    add x0, x0, #1          // x0 = x0 + 1
    lsl x1, x0, #1          // x1 = x0 << 1
    add x0, x1, #3          // x0 = x1 + 3 (depends on x1)
    madd x0, x0, x0, x0     // x0 = x0 * x0 + x0 (depends on x0)
    lsr x0, x0, #1          // x0 = x0 >> 1 (depends on x0)
    add x0, x0, #2          // x0 = x0 + 2 (depends on x0)
    lsl x0, x0, #1          // x0 = x0 << 1 (depends on x0)
    sub x0, x0, #7          // x0 = x0 - 7 (depends on x0)
    
    subs x19, x19, #1
    b.ne dependency_loop
    
    // End timing
    mrs x1, cntvct_el0      // Read virtual counter
    sub x0, x1, x20         // Calculate elapsed cycles
    
    ldp x19, x20, [sp], #16
    ret

/*
 * Independent operations test - allows out-of-order execution
 * Parameters: x0 = iteration count
 * Returns: cycles elapsed in x0
 */
.type ooo_independent_ops_asm, @function
ooo_independent_ops_asm:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    
    mov x19, x0             // Store iteration count
    
    // Start timing
    mrs x20, cntvct_el0     // Read virtual counter
    
    // Initialize independent variables
    mov x0, #1
    mov x1, #2
    mov x2, #3
    mov x3, #4
    mov x4, #5
    mov x5, #6
    
independent_loop:
    // Independent operations - can execute out-of-order
    add x0, x0, #1          // Independent operation 1
    add x1, x1, #2          // Independent operation 2
    add x2, x2, #3          // Independent operation 3
    add x3, x3, #4          // Independent operation 4
    add x4, x4, #5          // Independent operation 5
    add x5, x5, #6          // Independent operation 6
    
    // More independent operations
    lsl x0, x0, #1          // x0 = x0 << 1
    lsl x1, x1, #1          // x1 = x1 << 1
    lsl x2, x2, #1          // x2 = x2 << 1
    lsl x3, x3, #1          // x3 = x3 << 1
    lsl x4, x4, #1          // x4 = x4 << 1
    lsl x5, x5, #1          // x5 = x5 << 1
    
    subs x19, x19, #1
    b.ne independent_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x20         // Calculate elapsed cycles
    
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

/*
 * Memory disambiguation test - tests store-to-load forwarding
 * Parameters: x0 = array base address
 *             x1 = iteration count
 * Returns: cycles elapsed in x0
 */
.type ooo_memory_disambiguation_asm, @function
ooo_memory_disambiguation_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store array address
    mov x20, x1             // Store iteration count
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
disambiguation_loop:
    // Store to memory
    str x20, [x19]          // Store value
    
    // Independent operations that can execute while store is pending
    mov x0, #12345
    add x0, x0, #67890
    lsl x0, x0, #1
    
    // Load from same address (should forward from store buffer)
    ldr x2, [x19]           // Load value (store-to-load forwarding)
    
    // Use the loaded value
    add x2, x2, #1
    str x2, [x19, #8]       // Store to different address
    
    // More independent work
    mov x0, x2
    lsl x0, x0, #2
    add x0, x0, #42
    
    subs x20, x20, #1
    b.ne disambiguation_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Branch prediction test - tests speculative execution
 * Parameters: x0 = array base address
 *             x1 = array size
 *             x2 = pattern (0=predictable, 1=random)
 * Returns: cycles elapsed in x0
 */
.type ooo_branch_prediction_asm, @function
ooo_branch_prediction_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Store array address
    mov x20, x1             // Store array size
    mov x21, x2             // Store pattern type
    mov x22, #12345         // Random seed
    
    // Start timing
    mrs x23, cntvct_el0     // Read virtual counter
    
    mov x24, x20            // Counter
    mov x3, #0              // Index
    
branch_loop:
    cmp x21, #0
    b.eq predictable_pattern
    
    // Random pattern (unpredictable branches)
    mov x4, #1103515245
    mul x5, x22, x4
    add x22, x5, #12345     // Update seed
    tbnz x22, #0, random_branch_b    // Test random bit
    
random_branch_a:
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load element
    add x7, x7, #1          // Increment
    str x7, [x19, x6]       // Store back
    b branch_continue
    
random_branch_b:
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load element
    sub x7, x7, #1          // Decrement
    str x7, [x19, x6]       // Store back
    b branch_continue
    
predictable_pattern:
    // Predictable pattern (good for branch predictor)
    tbnz x3, #0, pred_branch_b    // Alternating pattern
    
pred_branch_a:
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load element
    add x7, x7, #2          // Add 2
    str x7, [x19, x6]       // Store back
    b branch_continue
    
pred_branch_b:
    lsl x6, x3, #3          // Convert to byte offset
    ldr x7, [x19, x6]       // Load element
    sub x7, x7, #2          // Subtract 2
    str x7, [x19, x6]       // Store back
    
branch_continue:
    add x3, x3, #1          // Next index
    cmp x3, x20
    b.lt next_iteration
    mov x3, #0              // Wrap around
    
next_iteration:
    subs x24, x24, #1
    b.ne branch_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x23         // Calculate elapsed cycles
    
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

/*
 * Register renaming demonstration
 * Parameters: x0 = iteration count
 * Returns: cycles elapsed in x0
 */
.type ooo_register_renaming_asm, @function
ooo_register_renaming_asm:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    
    mov x19, x0             // Store iteration count
    
    // Start timing
    mrs x20, cntvct_el0     // Read virtual counter
    
    // Initialize values
    mov x0, #1
    mov x1, #2
    mov x2, #3
    
renaming_loop:
    // These operations create false dependencies that register renaming resolves
    mov x0, #10             // Write to x0
    add x1, x1, x0          // Read old x0 value (renamed)
    mov x0, #20             // Write to x0 again (different physical register)
    add x2, x2, x0          // Read new x0 value
    mov x0, #30             // Another write to x0
    add x3, x3, x0          // Read newest x0 value
    
    // More register reuse to stress renaming
    mov x1, x2              // x1 = x2
    mov x2, x3              // x2 = x3
    mov x3, x1              // x3 = old x2
    add x0, x0, x1          // Use renamed registers
    
    // Chain of operations that benefit from renaming
    mov x4, #100
    add x4, x4, #1          // x4 = 101
    mov x4, #200            // Reuse x4 (gets renamed)
    add x4, x4, #2          // x4 = 202
    mov x4, #300            // Reuse x4 again
    add x4, x4, #3          // x4 = 303
    
    subs x19, x19, #1
    b.ne renaming_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x20         // Calculate elapsed cycles
    
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

/*
 * Store forwarding test - tests store-to-load forwarding efficiency
 * Parameters: x0 = memory buffer
 *             x1 = iteration count
 * Returns: cycles elapsed in x0
 */
.type ooo_store_forwarding_asm, @function
ooo_store_forwarding_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store buffer address
    mov x20, x1             // Store iteration count
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
forwarding_loop:
    // Store-to-load forwarding test
    str x20, [x19]          // Store to address
    ldr x0, [x19]           // Load from same address (should forward)
    add x0, x0, #1          // Use forwarded value
    
    // Store with different sizes
    strh w20, [x19, #2]     // 16-bit store
    ldrh w1, [x19, #2]      // 16-bit load (partial forwarding)
    
    // Store-to-load with offset
    str x20, [x19, #8]      // Store to offset +8
    ldr x2, [x19, #8]       // Load from offset +8
    
    // Multiple stores to same location
    str x20, [x19, #16]     // First store
    str x0, [x19, #16]      // Second store (overwrites first)
    ldr x3, [x19, #16]      // Load (should get second store value)
    
    // Store followed by independent work, then load
    str x20, [x19, #24]     // Store
    add x0, x0, #42         // Independent work
    lsl x0, x0, #1          // More independent work
    ldr x2, [x19, #24]      // Load (may come from store buffer or cache)
    
    subs x20, x20, #1
    b.ne forwarding_loop
    
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/*
 * Pipeline stall demonstration
 * Parameters: x0 = iteration count
 *             x1 = stall type (0=no stall, 1=data hazard, 2=control hazard)
 * Returns: cycles elapsed in x0
 */
.type ooo_pipeline_stall_asm, @function
ooo_pipeline_stall_asm:
    stp x19, x20, [sp, #-32]!
    stp x21, x22, [sp, #16]
    
    mov x19, x0             // Store iteration count
    mov x20, x1             // Store stall type
    
    // Start timing
    mrs x21, cntvct_el0     // Read virtual counter
    
    cmp x20, #0
    b.eq no_stall_test
    cmp x20, #1
    b.eq data_hazard_test
    b control_hazard_test
    
no_stall_test:
    // No stalls - independent operations
    mov x1, x19
no_stall_loop:
    mov x0, #1
    mov x2, #2
    add x0, x0, #3
    add x2, x2, #4
    lsl x0, x0, #1
    lsl x2, x2, #1
    subs x1, x1, #1
    b.ne no_stall_loop
    b stall_end
    
data_hazard_test:
    // Data hazards - dependent operations
    mov x1, x19
    mov x0, #1
data_hazard_loop:
    add x0, x0, #1          // Result needed by next instruction
    lsl x0, x0, #1          // Depends on previous result (stall)
    add x0, x0, #3          // Depends on previous result (stall)
    lsr x0, x0, #1          // Depends on previous result (stall)
    subs x1, x1, #1
    b.ne data_hazard_loop
    b stall_end
    
control_hazard_test:
    // Control hazards - unpredictable branches
    mov x1, x19
    mov x0, #12345          // Random seed
control_hazard_loop:
    // Generate unpredictable branch condition
    mov x2, #1103515245
    mul x3, x0, x2
    add x0, x3, #12345
    tbnz x0, #7, control_branch_a    // Unpredictable branch
    
control_branch_b:
    add x0, x0, #1000
    b control_continue
    
control_branch_a:
    sub x0, x0, #1000
    
control_continue:
    subs x1, x1, #1
    b.ne control_hazard_loop
    
stall_end:
    // End timing
    mrs x0, cntvct_el0      // Read virtual counter
    sub x0, x0, x21         // Calculate elapsed cycles
    
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

.section .note.GNU-stack,"",@progbits