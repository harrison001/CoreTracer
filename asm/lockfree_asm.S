/*
 * Lock-free Assembly Demonstrations (Intel Syntax)
 * 
 * This file contains hand-optimized x86-64 assembly implementations of lock-free
 * data structures and atomic operations to demonstrate low-level concurrency
 * primitives and their performance characteristics.
 */

.intel_syntax noprefix
.section .text
.global atomic_increment_asm
.global atomic_compare_exchange_asm  
.global lockfree_stack_push_asm
.global lockfree_stack_pop_asm
.global memory_barrier_asm
.global cpu_pause_asm
.global get_cpu_cycles_asm

/*
 * Atomic increment using LOCK prefix
 * Parameters: rdi = pointer to value
 * Returns: previous value in rax
 */
.type atomic_increment_asm, @function
atomic_increment_asm:
    mov rax, 1              # Load increment value
    lock xadd QWORD PTR [rdi], rax  # Atomic exchange and add
    ret                     # Return previous value in rax

/*
 * Atomic compare-and-swap (CAS) operation
 * Parameters: rdi = pointer to value
 *             rsi = expected value  
 *             rdx = new value
 * Returns: 1 if successful, 0 if failed
 */
.type atomic_compare_exchange_asm, @function
atomic_compare_exchange_asm:
    mov rax, rsi            # Load expected value into rax
    lock cmpxchg QWORD PTR [rdi], rdx  # Compare rax with [rdi], swap if equal
    sete al                 # Set al to 1 if equal (success), 0 if not
    movzx eax, al           # Zero-extend to full register
    ret

/*
 * Lock-free stack push operation
 * Parameters: rdi = pointer to stack head
 *             rsi = pointer to new node
 * Node structure: [next_ptr][data]
 * Returns: 1 on success, 0 on failure
 */
.type lockfree_stack_push_asm, @function
lockfree_stack_push_asm:
    mov rax, QWORD PTR [rdi]  # Load current head
push_retry:
    mov QWORD PTR [rsi], rax  # Set new node's next = current head
    lock cmpxchg QWORD PTR [rdi], rsi  # Try to update head atomically
    jne push_retry          # Retry if head changed
    mov rax, 1              # Return success
    ret

/*
 * Lock-free stack pop operation  
 * Parameters: rdi = pointer to stack head
 * Returns: pointer to popped node in rax (NULL if empty)
 */
.type lockfree_stack_pop_asm, @function
lockfree_stack_pop_asm:
    mov rax, QWORD PTR [rdi]  # Load current head
pop_retry:
    test rax, rax           # Check if stack is empty
    jz pop_empty            # Jump if empty
    mov rdx, QWORD PTR [rax]  # Load next pointer from head node
    lock cmpxchg QWORD PTR [rdi], rdx  # Try to update head to next
    jne pop_reload          # If failed, reload and retry
    ret                     # Return popped node in rax
pop_reload:
    mov rax, QWORD PTR [rdi]  # Reload head (it changed)
    jmp pop_retry           # Retry
pop_empty:
    xor rax, rax            # Return NULL
    ret

/*
 * Memory barriers for ordering guarantees
 */
.type memory_barrier_asm, @function
memory_barrier_asm:
    mfence                  # Full memory barrier
    ret

/*
 * CPU pause instruction for spin loops
 */
.type cpu_pause_asm, @function  
cpu_pause_asm:
    pause                   # Hint to CPU this is a spin loop
    ret

/*
 * High-precision CPU cycle counter
 * Returns: 64-bit cycle count in rax
 */
.type get_cpu_cycles_asm, @function
get_cpu_cycles_asm:
    rdtsc                   # Read timestamp counter
    shl rdx, 32             # Shift high 32 bits
    or rax, rdx             # Combine into 64-bit value
    ret

/*
 * Spin-wait with exponential backoff
 * Parameters: rdi = pointer to flag to wait for (wait until non-zero)
 *             rsi = max spin count
 */
.type spin_wait_backoff_asm, @function
spin_wait_backoff_asm:
    xor rcx, rcx            # Initialize spin count
    mov r8, 1               # Initialize backoff delay
spin_loop:
    mov rax, QWORD PTR [rdi]  # Load flag value
    test rax, rax           # Test if non-zero
    jnz spin_done           # Exit if flag is set
    
    # Exponential backoff
    mov r9, r8              # Copy delay count
backoff_loop:
    pause                   # CPU pause hint
    dec r9                  # Decrement delay counter
    jnz backoff_loop        # Continue delay loop
    
    shl r8, 1               # Double backoff delay
    cmp r8, 1024            # Cap maximum delay
    jle no_cap
    mov r8, 1024            # Reset to max
no_cap:
    
    inc rcx                 # Increment spin count
    cmp rcx, rsi            # Check against max spins
    jl spin_loop            # Continue if under limit
    
    xor rax, rax            # Return 0 (timeout)
    ret
spin_done:
    mov rax, 1              # Return 1 (success)
    ret

/*
 * Lock-free queue enqueue operation (Michael & Scott algorithm)
 * Parameters: rdi = pointer to queue structure
 *             rsi = pointer to new node
 * Queue structure: [head_ptr][tail_ptr]
 * Node structure: [next_ptr][data]
 */
.type lockfree_queue_enqueue_asm, @function
lockfree_queue_enqueue_asm:
    mov QWORD PTR [rsi], 0  # Initialize node->next = NULL
enqueue_retry:
    mov rdx, QWORD PTR [rdi + 8]  # Load tail pointer
    mov rcx, QWORD PTR [rdx]      # Load tail->next
    
    # Check if tail is still the last node
    cmp rdx, QWORD PTR [rdi + 8]  # Compare with current tail
    jne enqueue_retry       # Retry if tail changed
    
    test rcx, rcx           # Check if tail->next is NULL
    jnz enqueue_help        # Help advance tail if not NULL
    
    # Try to link new node
    lock cmpxchg QWORD PTR [rdx], rsi  # Try to set tail->next = new_node  
    jne enqueue_retry       # Retry if failed
    
    # Try to advance tail pointer
    lock cmpxchg QWORD PTR [rdi + 8], rsi  # Try to set tail = new_node
    
    mov rax, 1              # Return success
    ret
    
enqueue_help:
    # Help advance tail pointer
    lock cmpxchg QWORD PTR [rdi + 8], rcx  # Try to advance tail
    jmp enqueue_retry       # Retry operation

/*
 * Lock-free queue dequeue operation  
 * Parameters: rdi = pointer to queue structure
 * Returns: pointer to dequeued node in rax (NULL if empty)
 */
.type lockfree_queue_dequeue_asm, @function
lockfree_queue_dequeue_asm:
dequeue_retry:
    mov rax, QWORD PTR [rdi]      # Load head pointer
    mov rdx, QWORD PTR [rdi + 8]  # Load tail pointer  
    mov rcx, QWORD PTR [rax]      # Load head->next
    
    # Check consistency
    cmp rax, QWORD PTR [rdi]      # Verify head hasn't changed
    jne dequeue_retry       # Retry if inconsistent
    
    cmp rax, rdx            # Compare head and tail
    jne dequeue_nonempty    # Queue not empty
    
    # Queue appears empty or single element
    test rcx, rcx           # Check if head->next is NULL
    jz dequeue_empty        # Queue is empty
    
    # Help advance tail
    lock cmpxchg QWORD PTR [rdi + 8], rcx  # Try to advance tail
    jmp dequeue_retry       # Retry
    
dequeue_nonempty:
    test rcx, rcx           # Check if head->next exists  
    jz dequeue_retry        # Retry if inconsistent
    
    # Try to advance head
    lock cmpxchg QWORD PTR [rdi], rcx  # Try to set head = head->next
    jne dequeue_retry       # Retry if failed
    
    ret                     # Return old head in rax
    
dequeue_empty:
    xor rax, rax            # Return NULL
    ret

/*
 * Cache line flush for testing cache effects
 * Parameters: rdi = memory address to flush
 */
.type cache_flush_asm, @function
cache_flush_asm:
    clflush BYTE PTR [rdi]  # Flush cache line containing address
    ret

/*
 * Prefetch memory for better cache performance
 * Parameters: rdi = memory address to prefetch
 */
.type prefetch_asm, @function
prefetch_asm:
    prefetcht0 BYTE PTR [rdi]  # Prefetch to L1 cache
    ret

.section .note.GNU-stack,"",@progbits