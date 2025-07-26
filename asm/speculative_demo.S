/*
 * Speculative Execution Assembly Demonstrations (x86-64 Intel syntax)
 * 
 * This file contains assembly routines to demonstrate speculative execution
 * effects, branch prediction, speculative memory access, and side-channel
 * vulnerabilities like Spectre-style attacks.
 */

.intel_syntax noprefix
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
 * Parameters: rdi = array base address
 *             rsi = array size
 *             rdx = pattern type (0=predictable, 1=random, 2=mixed)
 * Returns: cycles elapsed in rax
 */
.type speculative_branch_test_asm, @function
speculative_branch_test_asm:
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
    mov r10, 0              # Sum accumulator
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    mov rdi, 0              # Index
    
speculation_loop:
    # Generate branch condition based on pattern
    cmp r8, 0
    je predictable_branch
    cmp r8, 1
    je random_branch
    
mixed_branch:
    # Mixed pattern - alternates between predictable and random
    test rdi, 0x100         # Every 256 iterations
    jz predictable_branch
    jmp random_branch
    
predictable_branch:
    # Predictable pattern - alternating
    test rdi, 1
    jz spec_branch_taken
    jmp spec_branch_not_taken
    
random_branch:
    # Generate pseudo-random condition
    mov rax, r9
    imul rax, rax, 1103515245
    add rax, 12345
    mov r9, rax
    test rax, 0xFF
    jz spec_branch_taken
    
spec_branch_not_taken:
    # Branch not taken path
    mov rax, [rbx + rdi * 8]
    add r10, rax            # Accumulate
    jmp spec_continue
    
spec_branch_taken:
    # Branch taken path - simulate expensive operation
    mov rax, [rbx + rdi * 8]
    imul rax, rax, 3        # Expensive multiply
    add rax, 1000           # Additional work
    add r10, rax            # Accumulate
    
spec_continue:
    inc rdi
    cmp rdi, rcx
    jl speculation_loop
    
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
 * Speculative memory access test - demonstrates speculative loads
 * Parameters: rdi = primary array
 *             rsi = secondary array (for speculation)
 *             rdx = size
 *             rcx = speculation depth
 * Returns: cycles elapsed in rax
 */
.type speculative_memory_access_asm, @function
speculative_memory_access_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    mov rbx, rdi            # Primary array
    mov r8, rsi             # Secondary array
    mov r9, rdx             # Size
    mov r10, rcx            # Speculation depth
    mov r11, 12345          # Random seed
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    mov rdi, 0              # Index
    
spec_memory_loop:
    # Generate condition for speculation
    mov rax, r11
    imul rax, rax, 1103515245
    add rax, 12345
    mov r11, rax
    
    # Check if we should speculate
    test rax, 0x3F          # Check low 6 bits
    jnz no_speculation
    
    # Speculative path - access secondary array
    mov rax, rdi
    add rax, r10            # Add speculation depth
    cmp rax, r9
    jge no_speculation      # Bounds check
    
    # Speculative memory accesses
    mov rcx, [r8 + rax * 8]         # Speculative load 1
    add rax, 1
    cmp rax, r9
    jge spec_memory_continue
    mov rdx, [r8 + rax * 8]         # Speculative load 2
    add rcx, rdx                    # Use speculative data
    
spec_memory_continue:
    jmp normal_access
    
no_speculation:
    mov rcx, 0              # No speculative value
    
normal_access:
    # Normal memory access
    mov rax, [rbx + rdi * 8]
    add rax, rcx            # Combine with speculative result
    mov [rbx + rdi * 8], rax
    
    inc rdi
    cmp rdi, r9
    jl spec_memory_loop
    
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
 * Indirect branch speculation test
 * Parameters: rdi = function pointer array
 *             rsi = array size
 *             rdx = call pattern (0=sequential, 1=random)
 * Returns: cycles elapsed in rax
 */
.type indirect_branch_test_asm, @function
indirect_branch_test_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    
    mov rbx, rdi            # Function pointer array
    mov rcx, rsi            # Array size
    mov r8, rdx             # Call pattern
    mov r9, 12345           # Random seed
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    mov rdi, 0              # Index
    mov r10, 1000           # Iteration count
    
indirect_loop:
    # Determine which function to call
    cmp r8, 0
    je sequential_calls
    
random_calls:
    # Random function selection
    mov rax, r9
    imul rax, rax, 1103515245
    add rax, 12345
    mov r9, rax
    xor rdx, rdx
    div rcx                 # rdx = index
    jmp call_function
    
sequential_calls:
    mov rdx, rdi
    xor rax, rax
    div rcx                 # rdx = rdi % size
    
call_function:
    # Load function pointer and call (indirect branch)
    mov rax, [rbx + rdx * 8]
    test rax, rax           # Check for null pointer
    jz skip_call
    
    # Simulate indirect call without actually calling
    # (to avoid complications with function setup)
    mov rax, [rax]          # Dereference as if calling
    
skip_call:
    inc rdi
    dec r10
    jnz indirect_loop
    
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
 * Speculative cache timing attack simulation
 * Parameters: rdi = secret data address
 *             rsi = probe array address
 *             rdx = probe array size
 * Returns: inferred data in rax
 */
.type speculative_cache_timing_asm, @function
speculative_cache_timing_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    mov rbx, rdi            # Secret data address
    mov r8, rsi             # Probe array address
    mov r9, rdx             # Probe array size
    
    # Flush probe array from cache
    mov rcx, 0
flush_loop:
    mov rax, r8
    add rax, rcx
    clflush [rax]           # Flush cache line
    add rcx, 64             # Next cache line (assuming 64-byte lines)
    cmp rcx, r9
    jl flush_loop
    
    mfence                  # Ensure flushes complete
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r10, rax            # Save start time
    
    # Speculative access pattern
    mov al, byte ptr [rbx]  # Load secret byte
    and rax, 0xFF           # Mask to byte value
    
    # Use secret as index into probe array (speculative)
    imul rax, rax, 64       # Scale by cache line size
    mov rbx, [r8 + rax]     # Access probe array (brings into cache)
    
    mfence                  # Ensure speculation completes
    
    # Timing-based inference
    mov r11, 0              # Best candidate
    mov rcx, 0              # Current index
    mov rdx, 0xFFFFFFFF     # Best time (start with max)
    
timing_loop:
    # Time access to each probe array location
    rdtsc
    shl rax, 32
    or rax, rdx
    push rax                # Save start time
    
    mov rax, rcx
    imul rax, rax, 64       # Scale by cache line size
    mov rbx, [r8 + rax]     # Access probe location
    
    rdtsc
    shl rax, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate access time
    
    # Check if this is the fastest access (likely cached)
    cmp rax, rdx
    jge not_fastest
    mov rdx, rax            # Update best time
    mov r11, rcx            # Update best candidate
    
not_fastest:
    inc rcx
    cmp rcx, 256            # Check all possible byte values
    jl timing_loop
    
    mov rax, r11            # Return inferred secret value
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

/*
 * Branch Target Buffer (BTB) test
 * Parameters: rdi = target array
 *             rsi = array size
 * Returns: cycles elapsed in rax
 */
.type branch_target_buffer_test_asm, @function
branch_target_buffer_test_asm:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    
    mov rbx, rdi            # Target array
    mov rcx, rsi            # Array size
    mov r8, 1000            # Iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
btb_loop:
    mov rdi, 0              # Index
    
btb_inner_loop:
    # Indirect jump to test BTB prediction
    mov rax, rdi
    and rax, 0x7            # Modulo 8 for target selection
    lea r9, [rip + btb_target_0]
    add r9, rax             # Calculate target address
    jmp r9                  # Indirect jump
    
btb_target_0:
    add qword ptr [rbx + rdi * 8], 1
    jmp btb_continue
btb_target_1:
    add qword ptr [rbx + rdi * 8], 2
    jmp btb_continue
btb_target_2:
    add qword ptr [rbx + rdi * 8], 3
    jmp btb_continue
btb_target_3:
    add qword ptr [rbx + rdi * 8], 4
    jmp btb_continue
btb_target_4:
    add qword ptr [rbx + rdi * 8], 5
    jmp btb_continue
btb_target_5:
    add qword ptr [rbx + rdi * 8], 6
    jmp btb_continue
btb_target_6:
    add qword ptr [rbx + rdi * 8], 7
    jmp btb_continue
btb_target_7:
    add qword ptr [rbx + rdi * 8], 8
    
btb_continue:
    inc rdi
    cmp rdi, rcx
    jl btb_inner_loop
    
    dec r8
    jnz btb_loop
    
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
 * Return Stack Buffer (RSB) test
 * Parameters: rdi = iteration count
 * Returns: cycles elapsed in rax
 */
.type return_stack_buffer_test_asm, @function
return_stack_buffer_test_asm:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
rsb_loop:
    # Call sequence to fill RSB
    call rsb_func_1
    call rsb_func_2
    call rsb_func_3
    call rsb_func_4
    
    dec rbx
    jnz rsb_loop
    jmp rsb_end
    
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
 * Speculative store bypass test
 * Parameters: rdi = memory buffer
 *             rsi = iteration count
 * Returns: cycles elapsed in rax
 */
.type speculative_store_bypass_asm, @function
speculative_store_bypass_asm:
    push rbx
    push rcx
    push rdx
    push r8
    
    mov rbx, rdi            # Memory buffer
    mov rcx, rsi            # Iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
store_bypass_loop:
    # Store to memory
    mov [rbx], rcx
    
    # Speculative load from potentially aliasing address
    # CPU may speculatively bypass the store
    mov rax, [rbx + 4]      # Load from nearby address
    
    # Use speculative value
    add rax, 1
    mov [rbx + 8], rax
    
    # Store that may conflict with earlier speculative load
    mov [rbx + 4], rcx
    
    # Dependent load that will show store bypass effects
    mov r8, [rbx + 4]       # This should see the store value
    add r8, rax             # Combine with speculative result
    
    dec rcx
    jnz store_bypass_loop
    
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