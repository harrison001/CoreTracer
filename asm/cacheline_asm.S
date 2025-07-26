/*
 * Cache Line Assembly Demonstrations (Intel Syntax)
 * 
 * This file contains x86-64 assembly routines to demonstrate cache line effects,
 * false sharing, cache coherency protocols, and memory access patterns
 * that affect cache performance.
 */

.intel_syntax noprefix
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
 * Parameters: rdi = base address
 *             rsi = thread_id (0-3)
 *             rdx = iteration count
 * Returns: number of cycles elapsed
 */
.type cache_false_sharing_test_asm, @function
cache_false_sharing_test_asm:
    push rbx
    push r12
    push r13
    push r14
    
    # Calculate offset for this thread (8 bytes apart in same cache line)
    mov rax, rsi            # thread_id
    shl rax, 3              # * 8 bytes
    add rax, rdi            # base + offset
    mov r12, rax            # Store address in r12
    
    mov r13, rdx            # Store iteration count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r14, rax            # Store start time
    
    # Main loop - read-modify-write operations causing false sharing
    mov rcx, r13            # Load iteration count
false_sharing_loop:
    # Load current value
    mov rax, QWORD PTR [r12]
    
    # Modify (simple increment with some computation)
    inc rax
    xor rax, 0x5555555555555555
    
    # Store back (this will invalidate cache lines on other cores)
    mov QWORD PTR [r12], rax
    
    # Add some work to make cache effects more visible
    mov rbx, QWORD PTR [r12]  # Load again (may hit modified cache line)
    add rbx, 17             # Simple computation
    mov QWORD PTR [r12], rbx  # Store again
    
    dec rcx
    jnz false_sharing_loop
    
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
 * Sequential memory access pattern - cache-friendly
 * Parameters: rdi = array base address
 *             rsi = array size in elements (8-byte each)
 * Returns: cycles elapsed
 */
.type cache_sequential_access_asm, @function
cache_sequential_access_asm:
    push rbx
    push r12
    push r13
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store size
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax            # Store start time
    
    # Sequential access loop
    mov rcx, r12            # Current pointer
    mov rdx, r13            # Counter
sequential_loop:
    # Load and modify
    mov rax, QWORD PTR [rcx]
    inc rax
    mov QWORD PTR [rcx], rax
    
    add rcx, 8              # Move to next element
    dec rdx
    jnz sequential_loop
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx            # Calculate elapsed cycles
    
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Random memory access pattern - cache-unfriendly
 * Parameters: rdi = array base address
 *             rsi = array size in elements
 *             rdx = seed for random number generation
 * Returns: cycles elapsed
 */
.type cache_random_access_asm, @function
cache_random_access_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store size
    mov r14, rdx            # Store seed
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Random access loop
    mov rcx, r13            # Counter
random_loop:
    # Simple LCG for pseudo-random numbers
    mov rax, r14
    mov rbx, 1103515245
    mul rbx                 # rax = seed * 1103515245
    add rax, 12345          # rax += 12345
    mov r14, rax            # Update seed
    
    # Modulo operation to get array index
    xor rdx, rdx
    div r13                 # rdx = rax % size
    shl rdx, 3              # Convert to byte offset
    
    # Access memory at random location
    mov rax, QWORD PTR [r12 + rdx]
    inc rax
    mov QWORD PTR [r12 + rdx], rax
    
    dec rcx
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
 * Strided memory access - configurable stride for cache line testing
 * Parameters: rdi = array base address
 *             rsi = number of accesses
 *             rdx = stride in elements (8-byte each)
 * Returns: cycles elapsed
 */
.type cache_stride_access_asm, @function
cache_stride_access_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store access count
    mov r14, rdx            # Store stride
    shl r14, 3              # Convert stride to bytes
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Strided access loop
    xor rbx, rbx            # Current offset
    mov rcx, r13            # Counter
stride_loop:
    # Access memory at current offset
    mov rax, QWORD PTR [r12 + rbx]
    inc rax
    mov QWORD PTR [r12 + rbx], rax
    
    add rbx, r14            # Add stride to offset
    dec rcx
    jnz stride_loop
    
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
 * Flush a range of cache lines
 * Parameters: %rdi = start address
 *            %rsi = size in bytes
 */
.type cache_flush_range_asm, @function
cache_flush_range_asm:
    push rbx
    
    mov rax, rdi            # Current address
    add rdi, rsi            # End address
    
flush_loop:
    clflush BYTE PTR [rax]  # Flush cache line containing this address
    add rax, 64             # Move to next cache line (assuming 64-byte lines)
    cmp rax, rdi
    jl flush_loop
    
    mfence                  # Ensure all flushes complete
    
    pop rbx
    ret

/*
 * Prefetch a range of memory
 * Parameters: %rdi = start address
 *            %rsi = size in bytes
 */
.type cache_prefetch_range_asm, @function
cache_prefetch_range_asm:
    push rbx
    
    mov rax, rdi            # Current address
    add rdi, rsi            # End address
    
prefetch_loop:
    prefetcht0 BYTE PTR [rax]  # Prefetch to L1 cache
    add rax, 64             # Move to next cache line
    cmp rax, rdi
    jl prefetch_loop
    
    pop rbx
    ret

/*
 * Memory latency test - measures latency of memory access
 * Parameters: rdi = memory address
 *             rsi = number of iterations
 * Returns: average latency in cycles
 */
.type memory_latency_test_asm, @function
memory_latency_test_asm:
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi            # Store address
    mov r13, rsi            # Store iterations
    xor r14, r14            # Total cycles
    
latency_loop:
    # Flush the cache line to ensure we measure memory latency
    clflush BYTE PTR [r12]
    mfence
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax            # Store start time
    
    # Access memory
    mov rax, QWORD PTR [r12]  # This should go to main memory
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx            # Calculate elapsed cycles
    add r14, rax            # Accumulate total
    
    dec r13
    jnz latency_loop
    
    # Calculate average
    mov rax, r14
    xor rdx, rdx
    div rsi                 # rax = total / iterations
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * Cache miss benchmark - compares cache hits vs misses
 * Parameters: rdi = array address
 *             rsi = array size (elements)
 *             rdx = test type (0=hits, 1=misses)
 * Returns: cycles elapsed
 */
.type cache_miss_benchmark_asm, @function
cache_miss_benchmark_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store array address
    mov r13, rsi            # Store array size
    mov r14, rdx            # Store test type
    
    # Test preparation
    cmp r14, 0
    je cache_hits_test
    
    # Cache misses test - flush entire array first
    mov rdi, r12
    mov rax, r13
    shl rax, 3              # Convert elements to bytes
    mov rsi, rax
    call cache_flush_range_asm
    jmp benchmark_start
    
cache_hits_test:
    # Cache hits test - warm up the cache first
    mov rcx, r12            # Start address
    mov rdx, r13            # Counter
warmup_loop:
    mov rax, QWORD PTR [rcx]  # Load to warm cache
    add rcx, 8
    dec rdx
    jnz warmup_loop
    
benchmark_start:
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Main benchmark loop
    mov rcx, r12            # Current address
    mov rdx, r13            # Counter
benchmark_loop:
    mov rax, QWORD PTR [rcx]  # Load from memory
    inc rax                 # Modify
    mov QWORD PTR [rcx], rax  # Store back
    
    add rcx, 8              # Next element
    dec rdx
    jnz benchmark_loop
    
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

.section .note.GNU-stack,"",@progbits