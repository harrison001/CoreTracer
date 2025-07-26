/*
 * Lock-free Assembly Demonstrations (ARM64/AArch64)
 * 
 * This file contains hand-optimized ARM64 assembly implementations of lock-free
 * data structures and atomic operations to demonstrate low-level concurrency
 * primitives and their performance characteristics.
 */

.section .text
.global atomic_increment_asm
.global atomic_compare_exchange_asm  
.global lockfree_stack_push_asm
.global lockfree_stack_pop_asm
.global memory_barrier_asm
.global cpu_pause_asm
.global get_cpu_cycles_asm

/*
 * Atomic increment using LDXR/STXR exclusive access
 * Parameters: x0 = pointer to value
 * Returns: previous value in x0
 */
.type atomic_increment_asm, @function
atomic_increment_asm:
    mov x2, #1              // Load increment value
1:  ldxr x1, [x0]          // Load exclusive
    add x3, x1, x2          // Add increment
    stxr w4, x3, [x0]       // Store exclusive
    cbnz w4, 1b             // Retry if failed
    mov x0, x1              // Return previous value
    ret

/*
 * Atomic compare-and-swap (CAS) operation
 * Parameters: x0 = pointer to value
 *             x1 = expected value  
 *             x2 = new value
 * Returns: 1 if successful, 0 if failed
 */
.type atomic_compare_exchange_asm, @function
atomic_compare_exchange_asm:
1:  ldxr x3, [x0]          // Load exclusive
    cmp x3, x1              // Compare with expected
    b.ne 2f                 // Branch if not equal
    stxr w4, x2, [x0]       // Store exclusive if equal
    cbnz w4, 1b             // Retry if store failed
    mov x0, #1              // Return success
    ret
2:  clrex                   // Clear exclusive monitor
    mov x0, #0              // Return failure
    ret

/*
 * Lock-free stack push operation
 * Parameters: x0 = pointer to stack head
 *             x1 = pointer to new node
 * Node structure: [next_ptr][data]
 * Returns: 1 on success, 0 on failure
 */
.type lockfree_stack_push_asm, @function
lockfree_stack_push_asm:
    ldr x2, [x0]            // Load current head
push_retry:
    str x2, [x1]            // Set new node's next = current head
    ldxr x3, [x0]           // Load head exclusive
    cmp x3, x2              // Check if head changed
    b.ne push_reload        // If changed, reload
    stxr w4, x1, [x0]       // Try to update head
    cbnz w4, push_retry     // Retry if failed
    mov x0, #1              // Return success
    ret
push_reload:
    clrex                   // Clear exclusive monitor
    mov x2, x3              // Update current head
    b push_retry            // Retry

/*
 * Lock-free stack pop operation  
 * Parameters: x0 = pointer to stack head
 * Returns: pointer to popped node in x0 (NULL if empty)
 */
.type lockfree_stack_pop_asm, @function
lockfree_stack_pop_asm:
pop_retry:
    ldxr x1, [x0]           // Load head exclusive
    cbz x1, pop_empty       // Check if stack is empty
    ldr x2, [x1]            // Load next pointer from head node
    stxr w3, x2, [x0]       // Try to update head to next
    cbnz w3, pop_retry      // Retry if failed
    mov x0, x1              // Return popped node
    ret
pop_empty:
    clrex                   // Clear exclusive monitor
    mov x0, #0              // Return NULL
    ret

/*
 * Memory barriers for ordering guarantees
 */
.type memory_barrier_asm, @function
memory_barrier_asm:
    dmb sy                  // Full system data memory barrier
    ret

/*
 * CPU pause instruction for spin loops (yield)
 */
.type cpu_pause_asm, @function  
cpu_pause_asm:
    yield                   // Hint to CPU this is a spin loop
    ret

/*
 * High-precision CPU cycle counter
 * Returns: 64-bit cycle count in x0  
 */
.type get_cpu_cycles_asm, @function
get_cpu_cycles_asm:
    mrs x0, cntvct_el0      // Read virtual counter
    ret

/*
 * Spin-wait with exponential backoff
 * Parameters: x0 = pointer to flag to wait for (wait until non-zero)
 *             x1 = max spin count
 */
.type spin_wait_backoff_asm, @function
spin_wait_backoff_asm:
    mov x2, #0              // Initialize spin count
    mov x3, #1              // Initialize backoff delay
spin_loop:
    ldr x4, [x0]            // Load flag value
    cbnz x4, spin_done      // Exit if flag is set
    
    // Exponential backoff
    mov x5, x3              // Copy delay count
backoff_loop:
    yield                   // CPU pause hint
    subs x5, x5, #1         // Decrement delay counter
    b.ne backoff_loop       // Continue delay loop
    
    lsl x3, x3, #1          // Double backoff delay
    cmp x3, #1024           // Cap maximum delay
    b.le no_cap
    mov x3, #1024           // Reset to max
no_cap:
    
    add x2, x2, #1          // Increment spin count
    cmp x2, x1              // Check against max spins
    b.lt spin_loop          // Continue if under limit
    
    mov x0, #0              // Return 0 (timeout)
    ret
spin_done:
    mov x0, #1              // Return 1 (success)
    ret

/*
 * Lock-free queue enqueue operation (Michael & Scott algorithm)
 * Parameters: x0 = pointer to queue structure
 *             x1 = pointer to new node
 * Queue structure: [head_ptr][tail_ptr]
 * Node structure: [next_ptr][data]
 */
.type lockfree_queue_enqueue_asm, @function
lockfree_queue_enqueue_asm:
    str xzr, [x1]           // Initialize node->next = NULL
enqueue_retry:
    ldr x2, [x0, #8]        // Load tail pointer
    ldr x3, [x2]            // Load tail->next
    
    // Check if tail is still the last node
    ldr x4, [x0, #8]        // Reload tail pointer
    cmp x2, x4              // Compare with current tail
    b.ne enqueue_retry      // Retry if tail changed
    
    cbnz x3, enqueue_help   // Help advance tail if not NULL
    
    // Try to link new node
    ldxr x5, [x2]           // Load tail->next exclusive
    cbnz x5, enqueue_retry_clear  // Retry if changed
    stxr w6, x1, [x2]       // Try to set tail->next = new_node
    cbnz w6, enqueue_retry  // Retry if failed
    
    // Try to advance tail pointer
    ldxr x7, [x0, #8]       // Load tail exclusive
    cmp x7, x2              // Check if still same
    b.ne enqueue_success_clear  // Don't care if tail advanced
    stxr w8, x1, [x0, #8]   // Try to set tail = new_node
    // Don't care if this fails - someone else will help
    
enqueue_success_clear:
    clrex                   // Clear exclusive monitor
    mov x0, #1              // Return success
    ret
    
enqueue_retry_clear:
    clrex                   // Clear exclusive monitor
    b enqueue_retry         // Retry operation
    
enqueue_help:
    // Help advance tail pointer
    ldxr x5, [x0, #8]       // Load tail exclusive
    cmp x5, x2              // Check if still same
    b.ne enqueue_help_clear // Skip if changed
    stxr w6, x3, [x0, #8]   // Try to advance tail
enqueue_help_clear:
    clrex                   // Clear exclusive monitor
    b enqueue_retry         // Retry operation

/*
 * Lock-free queue dequeue operation  
 * Parameters: x0 = pointer to queue structure
 * Returns: pointer to dequeued node in x0 (NULL if empty)
 */
.type lockfree_queue_dequeue_asm, @function
lockfree_queue_dequeue_asm:
dequeue_retry:
    ldr x1, [x0]            // Load head pointer
    ldr x2, [x0, #8]        // Load tail pointer  
    ldr x3, [x1]            // Load head->next
    
    // Check consistency
    ldr x4, [x0]            // Reload head pointer
    cmp x1, x4              // Verify head hasn't changed
    b.ne dequeue_retry      // Retry if inconsistent
    
    cmp x1, x2              // Compare head and tail
    b.ne dequeue_nonempty   // Queue not empty
    
    // Queue appears empty or single element
    cbz x3, dequeue_empty   // Queue is empty if head->next is NULL
    
    // Help advance tail
    ldxr x5, [x0, #8]       // Load tail exclusive
    cmp x5, x2              // Check if still same
    b.ne dequeue_help_clear // Skip if changed
    stxr w6, x3, [x0, #8]   // Try to advance tail
dequeue_help_clear:
    clrex                   // Clear exclusive monitor
    b dequeue_retry         // Retry
    
dequeue_nonempty:
    cbz x3, dequeue_retry   // Retry if head->next is NULL
    
    // Try to advance head
    ldxr x5, [x0]           // Load head exclusive
    cmp x5, x1              // Check if still same
    b.ne dequeue_nonempty_clear  // Retry if changed
    stxr w6, x3, [x0]       // Try to set head = head->next
    cbnz w6, dequeue_retry  // Retry if failed
    
    mov x0, x1              // Return old head
    ret
    
dequeue_nonempty_clear:
    clrex                   // Clear exclusive monitor
    b dequeue_retry         // Retry
    
dequeue_empty:
    mov x0, #0              // Return NULL
    ret

/*
 * Cache line flush for testing cache effects
 * Parameters: x0 = memory address to flush
 */
.type cache_flush_asm, @function
cache_flush_asm:
    dc civac, x0            // Clean and invalidate by VA to PoC
    dsb sy                  // Data synchronization barrier
    ret

/*
 * Prefetch memory for better cache performance
 * Parameters: x0 = memory address to prefetch
 */
.type prefetch_asm, @function
prefetch_asm:
    prfm pldl1keep, [x0]    // Prefetch for load to L1 cache
    ret

.section .note.GNU-stack,"",@progbits