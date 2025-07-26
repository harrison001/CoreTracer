/*
 * Out-of-Order Execution Assembly Demonstrations (x86-64 Intel syntax)
 * 
 * This file contains assembly routines to demonstrate out-of-order execution
 * effects, instruction reordering, pipeline stalls, and their impact on
 * performance and data consistency.
 */

.intel_syntax noprefix
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
 * Parameters: rdi = iteration count
 * Returns: cycles elapsed in rax
 */
.type ooo_dependency_chain_asm, @function
ooo_dependency_chain_asm:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    # Initialize value
    mov rax, 1
    
dependency_loop:
    # Long dependency chain - each instruction depends on previous
    add rax, 1              # rax = rax + 1
    imul rax, rax, 3        # rax = rax * 3
    add rax, 5              # rax = rax + 5
    shr rax, 1              # rax = rax >> 1
    add rax, 2              # rax = rax + 2
    imul rax, rax, 2        # rax = rax * 2
    sub rax, 7              # rax = rax - 7
    add rax, 1              # rax = rax + 1
    
    dec rbx
    jnz dependency_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Independent operations test - allows out-of-order execution
 * Parameters: rdi = iteration count
 * Returns: cycles elapsed in rax
 */
.type ooo_independent_ops_asm, @function
ooo_independent_ops_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    mov rbx, rdi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    # Initialize independent variables
    mov rax, 1
    mov rcx, 2
    mov r8, 3
    mov r9, 4
    mov r10, 5
    mov r11, 6
    
independent_loop:
    # Independent operations - can execute out-of-order
    add rax, 1              # Independent operation 1
    add rcx, 2              # Independent operation 2
    add r8, 3               # Independent operation 3
    add r9, 4               # Independent operation 4
    add r10, 5              # Independent operation 5
    add r11, 6              # Independent operation 6
    
    # More independent operations
    imul rax, rax, 2
    imul rcx, rcx, 2
    imul r8, r8, 2
    imul r9, r9, 2
    imul r10, r10, 2
    imul r11, r11, 2
    
    dec rbx
    jnz independent_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Memory disambiguation test - tests store-to-load forwarding
 * Parameters: rdi = array base address
 *             rsi = iteration count
 * Returns: cycles elapsed in rax
 */
.type ooo_memory_disambiguation_asm, @function
ooo_memory_disambiguation_asm:
    push rbx
    push rcx
    push rdx
    push r8
    
    mov rbx, rdi            # Store array address
    mov rcx, rsi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
disambiguation_loop:
    # Store to memory
    mov [rbx], rcx          # Store value
    
    # Independent operations that can execute while store is pending
    mov rax, 12345
    add rax, 67890
    imul rax, rax, 2
    
    # Load from same address (should forward from store buffer)
    mov r8, [rbx]           # Load value (store-to-load forwarding)
    
    # Use the loaded value
    add r8, 1
    mov [rbx + 8], r8       # Store to different address
    
    # More independent work
    mov rax, r8
    shl rax, 2
    add rax, 42
    
    dec rcx
    jnz disambiguation_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Branch prediction test - tests speculative execution
 * Parameters: rdi = array base address
 *             rsi = array size
 *             rdx = pattern (0=predictable, 1=random)
 * Returns: cycles elapsed in rax
 */
.type ooo_branch_prediction_asm, @function
ooo_branch_prediction_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    
    mov rbx, rdi            # Store array address
    mov rcx, rsi            # Store array size
    mov r8, rdx             # Store pattern type
    mov r9, 12345           # Random seed
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    mov r10, rcx            # Counter
    mov rdi, 0              # Index
    
branch_loop:
    cmp r8, 0
    je predictable_pattern
    
    # Random pattern (unpredictable branches)
    mov rax, r9
    imul rax, rax, 1103515245
    add rax, 12345
    mov r9, rax             # Update seed
    test rax, 1             # Test random bit
    jz random_branch_a
    
random_branch_b:
    mov rax, [rbx + rdi * 8]
    add rax, 1
    mov [rbx + rdi * 8], rax
    jmp branch_continue
    
random_branch_a:
    mov rax, [rbx + rdi * 8]
    sub rax, 1
    mov [rbx + rdi * 8], rax
    jmp branch_continue
    
predictable_pattern:
    # Predictable pattern (good for branch predictor)
    test rdi, 1             # Alternating pattern
    jz pred_branch_a
    
pred_branch_b:
    mov rax, [rbx + rdi * 8]
    add rax, 2
    mov [rbx + rdi * 8], rax
    jmp branch_continue
    
pred_branch_a:
    mov rax, [rbx + rdi * 8]
    sub rax, 2
    mov [rbx + rdi * 8], rax
    
branch_continue:
    inc rdi
    cmp rdi, rcx
    jl next_iteration
    mov rdi, 0              # Wrap around
    
next_iteration:
    dec r10
    jnz branch_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Register renaming demonstration
 * Parameters: rdi = iteration count
 * Returns: cycles elapsed in rax
 */
.type ooo_register_renaming_asm, @function
ooo_register_renaming_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    
    mov rbx, rdi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    # Initialize values
    mov rax, 1
    mov rcx, 2
    mov rdx, 3
    
renaming_loop:
    # These operations create false dependencies that register renaming resolves
    mov rax, 10             # Write to rax
    add rcx, rax            # Read old rax value (renamed)
    mov rax, 20             # Write to rax again (different physical register)
    add rdx, rax            # Read new rax value
    mov rax, 30             # Another write to rax
    add r8, rax             # Read newest rax value
    
    # More register reuse to stress renaming
    mov rcx, rdx            # rcx = rdx
    mov rdx, r8             # rdx = r8
    mov r8, rcx             # r8 = old rdx
    add rax, rcx            # Use renamed registers
    
    # Chain of operations that benefit from renaming
    mov r9, 100
    add r9, 1               # r9 = 101
    mov r9, 200             # Reuse r9 (gets renamed)
    add r9, 2               # r9 = 202
    mov r9, 300             # Reuse r9 again
    add r9, 3               # r9 = 303
    
    dec rbx
    jnz renaming_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Store forwarding test - tests store-to-load forwarding efficiency
 * Parameters: rdi = memory buffer
 *             rsi = iteration count
 * Returns: cycles elapsed in rax
 */
.type ooo_store_forwarding_asm, @function
ooo_store_forwarding_asm:
    push rbx
    push rcx
    push rdx
    push r8
    
    mov rbx, rdi            # Store buffer address
    mov rcx, rsi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
forwarding_loop:
    # Store-to-load forwarding test
    mov [rbx], rcx          # Store to address
    mov rax, [rbx]          # Load from same address (should forward)
    add rax, 1              # Use forwarded value
    
    # Store with different sizes
    mov word ptr [rbx + 2], cx    # 16-bit store
    mov ax, word ptr [rbx + 2]    # 16-bit load (partial forwarding)
    
    # Store-to-load with offset
    mov [rbx + 8], rcx      # Store to offset +8
    mov r8, [rbx + 8]       # Load from offset +8
    
    # Multiple stores to same location
    mov [rbx + 16], rcx     # First store
    mov [rbx + 16], rax     # Second store (overwrites first)
    mov rdx, [rbx + 16]     # Load (should get second store value)
    
    # Store followed by independent work, then load
    mov [rbx + 24], rcx     # Store
    add rax, 42             # Independent work
    imul rax, rax, 2        # More independent work
    mov r8, [rbx + 24]      # Load (may come from store buffer or cache)
    
    dec rcx
    jnz forwarding_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Pipeline stall demonstration
 * Parameters: rdi = iteration count
 *             rsi = stall type (0=no stall, 1=data hazard, 2=control hazard)
 * Returns: cycles elapsed in rax
 */
.type ooo_pipeline_stall_asm, @function
ooo_pipeline_stall_asm:
    push rbx
    push rcx
    push rdx
    push r8
    
    mov rbx, rdi            # Store iteration count
    mov r8, rsi             # Store stall type
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    cmp r8, 0
    je no_stall_test
    cmp r8, 1
    je data_hazard_test
    jmp control_hazard_test
    
no_stall_test:
    # No stalls - independent operations
    mov rcx, rbx
no_stall_loop:
    mov rax, 1
    mov rdx, 2
    add rax, 3
    add rdx, 4
    imul rax, rax, 2
    imul rdx, rdx, 2
    dec rcx
    jnz no_stall_loop
    jmp stall_end
    
data_hazard_test:
    # Data hazards - dependent operations
    mov rcx, rbx
    mov rax, 1
data_hazard_loop:
    add rax, 1              # Result needed by next instruction
    imul rax, rax, 2        # Depends on previous result (stall)
    add rax, 3              # Depends on previous result (stall)
    shr rax, 1              # Depends on previous result (stall)
    dec rcx
    jnz data_hazard_loop
    jmp stall_end
    
control_hazard_test:
    # Control hazards - unpredictable branches
    mov rcx, rbx
    mov rax, 12345          # Random seed
control_hazard_loop:
    # Generate unpredictable branch condition
    imul rax, rax, 1103515245
    add rax, 12345
    test rax, 0xFF          # Test some bits
    jz control_branch_a     # Unpredictable branch
    
control_branch_b:
    add rax, 1000
    jmp control_continue
    
control_branch_a:
    sub rax, 1000
    
control_continue:
    dec rcx
    jnz control_hazard_loop
    
stall_end:
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits