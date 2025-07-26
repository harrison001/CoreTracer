/*
 * TLB Shootdown Assembly Demonstrations (x86-64 Intel syntax)
 * 
 * This file contains assembly routines to demonstrate TLB (Translation Lookaside Buffer)
 * operations, shootdown effects, and their performance impact on multi-core systems.
 */

.intel_syntax noprefix
.section .text
.global tlb_flush_single_asm
.global tlb_flush_all_asm
.global tlb_shootdown_benchmark_asm
.global page_walk_timing_asm
.global tlb_miss_generator_asm

/*
 * Flush a single page from TLB
 * Parameters: rdi = virtual address to flush
 */
.type tlb_flush_single_asm, @function
tlb_flush_single_asm:
    invlpg [rdi]            # Invalidate page in TLB
    ret

/*
 * Flush entire TLB (privileged operation, may not work in all contexts)
 * This is mainly for demonstration - actual usage requires appropriate privileges
 */
.type tlb_flush_all_asm, @function
tlb_flush_all_asm:
    mov rax, cr3            # Load page directory base
    mov cr3, rax            # Reload CR3 to flush TLB
    ret

/*
 * TLB shootdown benchmark - measures cost of TLB invalidation
 * Parameters: rdi = array of virtual addresses
 *             rsi = number of addresses
 *             rdx = iterations
 * Returns: cycles elapsed in rax
 */
.type tlb_shootdown_benchmark_asm, @function
tlb_shootdown_benchmark_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store address array
    mov r13, rsi            # Store count
    mov r14, rdx            # Store iterations
    
    # Start timing
    rdtsc                   # Read time stamp counter
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Benchmark loop
    mov rbx, r14            # Load iteration count
benchmark_loop:
    mov rcx, r13            # Load address count
    mov rdi, r12            # Load address array
    
invalidate_loop:
    mov rax, [rdi]          # Load virtual address
    invlpg [rax]            # Invalidate TLB entry
    add rdi, 8              # Next address
    dec rcx
    jnz invalidate_loop
    
    dec rbx
    jnz benchmark_loop
    
    # End timing
    rdtsc                   # Read time stamp counter
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
 * Page walk timing test - measures page table walk latency
 * Parameters: rdi = virtual address to access
 *             rsi = access count
 * Returns: average cycles per access in rax
 */
.type page_walk_timing_asm, @function
page_walk_timing_asm:
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi            # Store address
    mov r13, rsi            # Store access count
    mov r14, 0              # Total cycles
    
    # Ensure TLB is cold for this address
    invlpg [r12]
    
timing_loop:
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax            # Store start time
    
    # Access memory (forces page table walk if TLB miss)
    mov rax, [r12]
    
    # End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx            # Calculate elapsed cycles
    add r14, rax            # Accumulate total
    
    # Flush TLB again for next iteration
    invlpg [r12]
    
    dec r13
    jnz timing_loop
    
    # Calculate average
    mov rax, r14
    mov rdx, 0
    div rsi                 # rax = total / count
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/*
 * TLB miss generator - creates predictable TLB misses
 * Parameters: rdi = base address
 *             rsi = stride (bytes)
 *             rdx = access count
 * Returns: cycles elapsed in rax
 */
.type tlb_miss_generator_asm, @function
tlb_miss_generator_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store stride
    mov r14, rdx            # Store access count
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    mov rbx, r14            # Load access count
    mov rdi, r12            # Start address
    
miss_loop:
    # Access memory location
    mov rax, [rdi]
    
    # Move to next location with stride
    add rdi, r13
    
    # Invalidate current page to force TLB miss on next access
    # (This creates artificial TLB pressure)
    mov rcx, rdi
    sub rcx, r13            # Previous address
    invlpg [rcx]
    
    dec rbx
    jnz miss_loop
    
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
 * Multi-core TLB interference test
 * Parameters: rdi = shared memory region
 *             rsi = region size
 *             rdx = core ID
 * Returns: cycles elapsed in rax
 */
.type tlb_interference_test_asm, @function
tlb_interference_test_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store region size
    mov r14, rdx            # Store core ID
    
    # Calculate starting offset for this core
    mov rax, r14
    shl rax, 12             # Core ID * 4KB (page size)
    add r12, rax            # Offset into shared region
    
    # Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax            # Store start time
    
    # Access pattern that causes TLB conflicts
    mov rbx, 1000           # Number of iterations
    mov rdi, r12            # Start address
    
interference_loop:
    # Access multiple pages in sequence
    mov rcx, 16             # Number of pages to touch
page_touch_loop:
    mov rax, [rdi]          # Touch page
    add rdi, 4096           # Next page (4KB)
    dec rcx
    jnz page_touch_loop
    
    # Reset to start
    mov rdi, r12
    
    # Introduce some TLB invalidations
    invlpg [rdi]
    add rdi, 4096
    invlpg [rdi]
    add rdi, 4096
    invlpg [rdi]
    
    # Reset for next iteration
    mov rdi, r12
    
    dec rbx
    jnz interference_loop
    
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
 * TLB entry count estimation
 * This function tries to estimate TLB capacity by measuring latency changes
 * Parameters: rdi = base address
 *             rsi = max pages to test
 * Returns: estimated TLB entries in rax
 */
.type tlb_capacity_test_asm, @function
tlb_capacity_test_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            # Store base address
    mov r13, rsi            # Store max pages
    mov r14, 0              # Current page count
    mov r15, 0              # Baseline latency
    
capacity_test_loop:
    # Access pages sequentially to warm TLB
    mov rbx, r14            # Current page count
    mov rdi, r12            # Base address
    
warmup_loop:
    mov rax, [rdi]          # Touch page
    add rdi, 4096           # Next page
    dec rbx
    jnz warmup_loop
    
    # Measure access latency for first page
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax            # Start time
    
    mov rax, [r12]          # Access first page
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx            # Latency
    
    # Check if latency increased significantly (TLB overflow)
    cmp r15, 0              # First measurement?
    je set_baseline
    
    # Compare with baseline
    mov rbx, r15
    shl rbx, 1              # 2x baseline
    cmp rax, rbx
    jg tlb_overflow         # Latency > 2x baseline = TLB overflow
    
    jmp continue_test
    
set_baseline:
    mov r15, rax            # Set baseline latency
    
continue_test:
    inc r14                 # Next page count
    cmp r14, r13            # Check limit
    jl capacity_test_loop
    
    # Return max pages if no overflow detected
    mov rax, r13
    jmp capacity_done
    
tlb_overflow:
    mov rax, r14            # Return page count where overflow occurred
    
capacity_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits