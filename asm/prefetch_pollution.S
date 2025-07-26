/*
 * Cache Prefetch and Pollution Assembly Demonstrations (x86-64 Intel syntax)
 * 
 * This file contains assembly routines to demonstrate hardware prefetcher behavior,
 * manual prefetch instructions, cache pollution effects, and their impact on
 * memory performance across different access patterns.
 */

.intel_syntax noprefix
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
 * Parameters: rdi = array base address
 *             rsi = array size (elements)
 *             rdx = prefetch distance (elements ahead)
 * Returns: cycles elapsed in rax
 */
.type manual_prefetch_test_asm, @function
manual_prefetch_test_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store array size
    mov r14, rdx            # Store prefetch distance
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Manual prefetch loop
    mov rbx, 0              # Current index
    mov rcx, r13            # Element count
    
prefetch_loop:
    # Calculate prefetch address (current + distance)
    mov rax, rbx
    add rax, r14            # Add prefetch distance
    cmp rax, r13            # Check bounds
    jge skip_prefetch       # Skip if beyond array
    
    # Prefetch future data
    lea r8, [r12 + rax * 8] # Address = base + (index * 8)
    prefetcht0 [r8]         # Prefetch to L1 cache
    
skip_prefetch:
    # Access current element
    mov rax, [r12 + rbx * 8]
    add rax, 1              # Simple computation
    mov [r12 + rbx * 8], rax
    
    inc rbx                 # Next element
    dec rcx
    jnz prefetch_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r15            # Calculate elapsed cycles
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Hardware prefetcher test - linear access to trigger HW prefetcher
 * Parameters: rdi = array base address
 *             rsi = array size (elements)
 * Returns: cycles elapsed in rax
 */
.type hardware_prefetch_test_asm, @function
hardware_prefetch_test_asm:
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store array size
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r14, rax            # Store start time
    
    # Linear access to trigger hardware prefetcher
    mov rbx, 0              # Current index
    mov rcx, r13            # Element count
    
hw_prefetch_loop:
    # Sequential access (hardware prefetcher friendly)
    mov rax, [r12 + rbx * 8]
    add rax, 1
    mov [r12 + rbx * 8], rax
    
    inc rbx
    dec rcx
    jnz hw_prefetch_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r14            # Calculate elapsed cycles
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Cache pollution test - demonstrates impact of polluting accesses
 * Parameters: rdi = main array address
 *             rsi = main array size
 *             rdx = pollution array address
 *             rcx = pollution array size
 * Returns: cycles elapsed for main array access in rax
 */
.type cache_pollution_test_asm, @function
cache_pollution_test_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Main array
    mov r13, rsi            # Main array size
    mov r14, rdx            # Pollution array
    mov r15, rcx            # Pollution array size
    
    # First, warm up the cache with main array
    mov rbx, 0
warmup_loop:
    mov rax, [r12 + rbx * 8]
    inc rbx
    cmp rbx, r13
    jl warmup_loop
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Store start time on stack
    
    # Access main array
    mov rbx, 0
main_access_loop:
    mov rax, [r12 + rbx * 8]
    add rax, 1
    mov [r12 + rbx * 8], rax
    
    # Interleave with pollution accesses every 4 elements
    test rbx, 3             # Check if rbx % 4 == 0
    jnz skip_pollution
    
    # Pollute cache with random access to pollution array
    mov rcx, rbx
    and rcx, 0xFF           # Use low 8 bits for pollution index
    cmp rcx, r15
    jge skip_pollution
    mov rax, [r14 + rcx * 8] # Pollution access
    
skip_pollution:
    inc rbx
    cmp rbx, r13
    jl main_access_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rbx                 # Retrieve start time
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Prefetch distance optimization test
 * Parameters: rdi = array base address
 *             rsi = array size
 *             rdx = maximum prefetch distance to test
 * Returns: optimal distance in rax
 */
.type prefetch_distance_test_asm, @function
prefetch_distance_test_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store array size
    mov r14, rdx            # Store max prefetch distance
    mov r15, 0              # Best time so far
    mov rbx, 1              # Best distance (start with 1)
    
distance_test_loop:
    # Test current prefetch distance
    push rbx                # Save current distance
    
    # Start timing for this distance
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax                # Save start time
    
    # Run prefetch test with current distance
    mov rcx, 0              # Array index
    mov r8, r13             # Element count
    
distance_access_loop:
    # Calculate prefetch address
    mov rax, rcx
    add rax, rbx            # Add current distance
    cmp rax, r13
    jge skip_distance_prefetch
    
    # Prefetch
    prefetcht0 [r12 + rax * 8]
    
skip_distance_prefetch:
    # Access current element
    mov rax, [r12 + rcx * 8]
    add rax, 1
    mov [r12 + rcx * 8], rax
    
    inc rcx
    dec r8
    jnz distance_access_loop
    
    # End timing for this distance
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rcx                 # Retrieve start time
    sub rax, rcx            # Calculate elapsed time
    
    # Check if this is the best time so far
    cmp r15, 0              # First measurement?
    je set_new_best
    cmp rax, r15            # Compare with best time
    jge not_better
    
set_new_best:
    mov r15, rax            # Update best time
    pop rax                 # Get current distance
    push rax                # Put it back
    mov rbx, rax            # Update best distance
    
not_better:
    pop rax                 # Retrieve current distance
    inc rax                 # Next distance
    cmp rax, r14            # Check against max
    jle distance_test_loop
    
    mov rax, rbx            # Return best distance
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Streaming prefetch test - optimized for memory bandwidth
 * Parameters: rdi = source array
 *             rsi = destination array
 *             rdx = size (elements)
 * Returns: cycles elapsed in rax
 */
.type stream_prefetch_asm, @function
stream_prefetch_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Source array
    mov r13, rsi            # Destination array
    mov r14, rdx            # Size
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Streaming copy with aggressive prefetch
    mov rbx, 0              # Current index
    mov rcx, r14            # Element count
    
stream_loop:
    # Prefetch multiple cache lines ahead
    mov rax, rbx
    add rax, 8              # Prefetch 8 elements ahead
    cmp rax, r14
    jge skip_stream_prefetch1
    prefetcht0 [r12 + rax * 8]      # Prefetch source
    prefetcht0 [r13 + rax * 8]      # Prefetch destination
    
skip_stream_prefetch1:
    mov rax, rbx
    add rax, 16             # Also prefetch 16 ahead
    cmp rax, r14
    jge skip_stream_prefetch2
    prefetcht0 [r12 + rax * 8]
    prefetcht0 [r13 + rax * 8]
    
skip_stream_prefetch2:
    # Perform the actual copy
    mov rax, [r12 + rbx * 8]        # Load from source
    mov [r13 + rbx * 8], rax        # Store to destination
    
    inc rbx
    dec rcx
    jnz stream_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r15            # Calculate elapsed cycles
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Random access with prefetch hints
 * Parameters: rdi = array base
 *             rsi = array size
 *             rdx = random seed
 * Returns: cycles elapsed in rax
 */
.type random_prefetch_asm, @function
random_prefetch_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Array base
    mov r13, rsi            # Array size
    mov r14, rdx            # Random seed
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Random access loop
    mov rbx, r13            # Access count
    
random_loop:
    # Generate pseudo-random index
    mov rax, r14
    mov rcx, 1103515245
    mul rcx                 # rax = seed * 1103515245
    add rax, 12345          # rax += 12345
    mov r14, rax            # Update seed
    
    # Get array index
    xor rdx, rdx
    div r13                 # rdx = rax % size
    
    # Try to predict next few accesses and prefetch
    mov rcx, r14            # Use current seed
    mov r8, 1103515245
    mul r8
    add rax, 12345
    xor r8, r8
    div r13                 # Next index in r8
    
    cmp r8, r13
    jge skip_random_prefetch
    prefetcht0 [r12 + r8 * 8]       # Prefetch next predicted access
    
skip_random_prefetch:
    # Access current element
    mov rax, [r12 + rdx * 8]
    add rax, 1
    mov [r12 + rdx * 8], rax
    
    dec rbx
    jnz random_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r15            # Calculate elapsed cycles
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Cache bypass test using non-temporal stores
 * Parameters: rdi = array base
 *             rsi = array size
 * Returns: cycles elapsed in rax
 */
.type cache_bypass_test_asm, @function
cache_bypass_test_asm:
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi            # Array base
    mov r13, rsi            # Array size
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r14, rax            # Store start time
    
    # Non-temporal store loop (bypasses cache)
    mov rbx, 0              # Current index
    mov rcx, r13            # Element count
    
bypass_loop:
    mov rax, rbx            # Use index as data
    movnti [r12 + rbx * 8], rax     # Non-temporal store
    
    inc rbx
    dec rcx
    jnz bypass_loop
    
    # Ensure all stores complete
    sfence                  # Store fence
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r14            # Calculate elapsed cycles
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits