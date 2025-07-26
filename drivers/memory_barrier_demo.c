/*
 * Memory Barrier and Fence Consistency Demonstration
 * 
 * This module demonstrates memory ordering effects, store/load reordering,
 * and the impact of different memory barrier types on multi-core visibility
 * and consistency.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpuset.h>
#include <linux/atomic.h>
#include <asm/barrier.h>

#define MODULE_NAME "memory_barrier_demo"
#define PROC_NAME "memory_barrier"
#define MAX_THREADS 8
#define TEST_ITERATIONS 10000

static struct proc_dir_entry *proc_entry;

struct barrier_test_data {
    volatile int flag1;
    volatile int flag2;
    volatile int data1;
    volatile int data2;
    volatile int observed_order[MAX_THREADS][TEST_ITERATIONS];
    atomic_t ready_count;
    atomic_t start_flag;
    atomic_t done_count;
    int reorder_count;
    int total_observations;
};

struct thread_context {
    int thread_id;
    int cpu_id;
    struct barrier_test_data *test_data;
    enum barrier_type test_type;
    struct task_struct *task;
};

enum barrier_type {
    BARRIER_NONE,
    BARRIER_COMPILER,
    BARRIER_SMP_MB,
    BARRIER_SMP_WMB,
    BARRIER_SMP_RMB,
    BARRIER_MFENCE_ASM
};

static const char *barrier_names[] = {
    "No Barriers",
    "Compiler Barrier Only",
    "SMP Memory Barrier (smp_mb)",
    "SMP Write Barrier (smp_wmb)", 
    "SMP Read Barrier (smp_rmb)",
    "Assembly MFENCE"
};

static struct barrier_test_data test_data;
static struct thread_context thread_contexts[MAX_THREADS];
static bool test_running = false;
static int num_test_threads = 2;

/*
 * Assembly memory fence for x86-64
 */
static inline void asm_mfence(void)
{
#ifdef CONFIG_X86
    asm volatile("mfence" ::: "memory");
#else
    smp_mb(); // Fallback for other architectures
#endif
}

/*
 * Writer thread - demonstrates store reordering
 */
static int barrier_writer_thread(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct barrier_test_data *td = ctx->test_data;
    enum barrier_type barrier = ctx->test_type;
    int iteration;
    
    pr_info("Writer thread %d starting on CPU %d\n", ctx->thread_id, smp_processor_id());
    
    // Signal ready
    atomic_inc(&td->ready_count);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Reset flags
        td->flag1 = 0;
        td->flag2 = 0;
        td->data1 = 0;
        td->data2 = 0;
        
        // Ensure all readers see the reset
        smp_mb();
        
        // Write data first
        td->data1 = iteration + 1;
        td->data2 = iteration + 2;
        
        // Apply memory barrier based on test type
        switch (barrier) {
            case BARRIER_NONE:
                // No barrier - allow reordering
                break;
            case BARRIER_COMPILER:
                barrier(); // Compiler barrier only
                break;
            case BARRIER_SMP_MB:
                smp_mb(); // Full memory barrier
                break;
            case BARRIER_SMP_WMB:
                smp_wmb(); // Write memory barrier
                break;
            case BARRIER_SMP_RMB:
                smp_rmb(); // Read memory barrier (not useful for writes)
                break;
            case BARRIER_MFENCE_ASM:
                asm_mfence(); // Assembly fence
                break;
        }
        
        // Set flags to signal data is ready
        td->flag1 = 1;
        td->flag2 = 1;
        
        // Wait for readers to observe
        while (atomic_read(&td->done_count) < num_test_threads - 1 && !kthread_should_stop()) {
            cpu_relax();
        }
        
        atomic_set(&td->done_count, 0);
        
        // Small delay between iterations
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    pr_info("Writer thread %d completed\n", ctx->thread_id);
    return 0;
}

/*
 * Reader thread - observes memory ordering
 */
static int barrier_reader_thread(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct barrier_test_data *td = ctx->test_data;
    enum barrier_type barrier = ctx->test_type;
    int iteration;
    int local_reorders = 0;
    
    pr_info("Reader thread %d starting on CPU %d\n", ctx->thread_id, smp_processor_id());
    
    // Signal ready
    atomic_inc(&td->ready_count);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        int flag1_val, flag2_val, data1_val, data2_val;
        int observed_reorder = 0;
        
        // Wait for flags to be set
        while ((td->flag1 == 0 || td->flag2 == 0) && !kthread_should_stop()) {
            cpu_relax();
        }
        
        // Apply read barrier based on test type
        switch (barrier) {
            case BARRIER_NONE:
                break;
            case BARRIER_COMPILER:
                barrier();
                break;
            case BARRIER_SMP_MB:
                smp_mb();
                break;
            case BARRIER_SMP_WMB:
                smp_wmb(); // Not useful for reads
                break;
            case BARRIER_SMP_RMB:
                smp_rmb(); // Read memory barrier
                break;
            case BARRIER_MFENCE_ASM:
                asm_mfence();
                break;
        }
        
        // Read data after seeing flags
        flag1_val = td->flag1;
        flag2_val = td->flag2;
        data1_val = td->data1;
        data2_val = td->data2;
        
        // Check for reordering: if flags are set but data is stale
        if (flag1_val == 1 && flag2_val == 1) {
            if (data1_val != iteration + 1 || data2_val != iteration + 2) {
                observed_reorder = 1;
                local_reorders++;
            }
        }
        
        // Record observation
        if (ctx->thread_id < MAX_THREADS && iteration < TEST_ITERATIONS) {
            td->observed_order[ctx->thread_id][iteration] = observed_reorder;
        }
        
        // Signal completion
        atomic_inc(&td->done_count);
        
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    // Update global reorder count
    atomic_add(local_reorders, (atomic_t *)&td->reorder_count);
    
    pr_info("Reader thread %d completed, observed %d reorders\n", 
            ctx->thread_id, local_reorders);
    return 0;
}

/*
 * Start memory barrier test with specified barrier type
 */
static int start_barrier_test(enum barrier_type barrier_type)
{
    int i;
    int writer_cpu, reader_cpu;
    
    if (test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    if (num_online_cpus() < 2) {
        pr_warn("Need at least 2 CPUs for meaningful test\n");
        return -EINVAL;
    }
    
    // Initialize test data
    memset(&test_data, 0, sizeof(test_data));
    atomic_set(&test_data.ready_count, 0);
    atomic_set(&test_data.start_flag, 0);
    atomic_set(&test_data.done_count, 0);
    test_data.reorder_count = 0;
    test_data.total_observations = 0;
    
    test_running = true;
    
    // Choose CPUs for writer and readers
    writer_cpu = 0;
    reader_cpu = 1;
    
    pr_info("Starting memory barrier test: %s\n", barrier_names[barrier_type]);
    pr_info("Writer CPU: %d, Reader CPU: %d\n", writer_cpu, reader_cpu);
    
    // Create writer thread
    thread_contexts[0].thread_id = 0;
    thread_contexts[0].cpu_id = writer_cpu;
    thread_contexts[0].test_data = &test_data;
    thread_contexts[0].test_type = barrier_type;
    
    thread_contexts[0].task = kthread_create(barrier_writer_thread, 
                                           &thread_contexts[0], 
                                           "barrier_writer");
    if (IS_ERR(thread_contexts[0].task)) {
        pr_err("Failed to create writer thread\n");
        test_running = false;
        return PTR_ERR(thread_contexts[0].task);
    }
    
    kthread_bind(thread_contexts[0].task, writer_cpu);
    wake_up_process(thread_contexts[0].task);
    
    // Create reader threads
    for (i = 1; i < num_test_threads; i++) {
        thread_contexts[i].thread_id = i;
        thread_contexts[i].cpu_id = reader_cpu;
        thread_contexts[i].test_data = &test_data;
        thread_contexts[i].test_type = barrier_type;
        
        thread_contexts[i].task = kthread_create(barrier_reader_thread,
                                               &thread_contexts[i],
                                               "barrier_reader_%d", i);
        if (IS_ERR(thread_contexts[i].task)) {
            pr_err("Failed to create reader thread %d\n", i);
            // Stop already created threads
            for (int j = 0; j < i; j++) {
                if (thread_contexts[j].task) {
                    kthread_stop(thread_contexts[j].task);
                }
            }
            test_running = false;
            return PTR_ERR(thread_contexts[i].task);
        }
        
        kthread_bind(thread_contexts[i].task, reader_cpu);
        wake_up_process(thread_contexts[i].task);
    }
    
    // Wait for all threads to be ready
    while (atomic_read(&test_data.ready_count) < num_test_threads) {
        msleep(1);
    }
    
    pr_info("All threads ready, starting test\n");
    
    // Start the test
    atomic_set(&test_data.start_flag, 1);
    
    return 0;
}

/*
 * Stop running barrier test
 */
static void stop_barrier_test(void)
{
    int i;
    
    if (!test_running)
        return;
    
    pr_info("Stopping memory barrier test\n");
    
    // Stop all threads
    for (i = 0; i < num_test_threads; i++) {
        if (thread_contexts[i].task) {
            kthread_stop(thread_contexts[i].task);
            thread_contexts[i].task = NULL;
        }
    }
    
    test_running = false;
    
    // Calculate total observations
    test_data.total_observations = TEST_ITERATIONS * (num_test_threads - 1);
    
    pr_info("Memory barrier test completed\n");
    pr_info("Total reorderings observed: %d/%d (%.2f%%)\n",
            test_data.reorder_count, test_data.total_observations,
            test_data.total_observations > 0 ? 
                (test_data.reorder_count * 100.0) / test_data.total_observations : 0.0);
}

static int memory_barrier_show(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "=== Memory Barrier & Fence Consistency Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  CPUs: %d online\n", num_online_cpus());
    seq_printf(m, "  Test Status: %s\n", test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Test Threads: %d\n", num_test_threads);
    seq_printf(m, "  Test Iterations: %d\n\n", TEST_ITERATIONS);
    
    if (!test_running && test_data.total_observations > 0) {
        seq_printf(m, "Last Test Results:\n");
        seq_printf(m, "  Total Observations: %d\n", test_data.total_observations);
        seq_printf(m, "  Reorderings Detected: %d\n", test_data.reorder_count);
        seq_printf(m, "  Reordering Rate: %.4f%%\n\n",
                  test_data.total_observations > 0 ? 
                      (test_data.reorder_count * 100.0) / test_data.total_observations : 0.0);
        
        seq_printf(m, "Per-Thread Reordering Summary:\n");
        for (i = 1; i < num_test_threads; i++) {
            int thread_reorders = 0;
            int j;
            
            for (j = 0; j < TEST_ITERATIONS; j++) {
                if (test_data.observed_order[i][j]) {
                    thread_reorders++;
                }
            }
            
            seq_printf(m, "  Thread %d: %d reorders\n", i, thread_reorders);
        }
        seq_printf(m, "\n");
    }
    
    seq_printf(m, "Available Barrier Types:\n");
    for (i = 0; i < ARRAY_SIZE(barrier_names); i++) {
        seq_printf(m, "  %d: %s\n", i, barrier_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start <type>' > /proc/%s  # Start test (0-%d)\n", 
              PROC_NAME, (int)ARRAY_SIZE(barrier_names) - 1);
    seq_printf(m, "  echo 'stop' > /proc/%s          # Stop test\n", PROC_NAME);
    seq_printf(m, "  echo 'threads <n>' > /proc/%s   # Set thread count (2-%d)\n", 
              PROC_NAME, MAX_THREADS);
    
    seq_printf(m, "\nMemory Ordering Analysis:\n");
    seq_printf(m, "  - No barriers: Expect visible reorderings\n");
    seq_printf(m, "  - Compiler barrier: Prevents compile-time reordering only\n");
    seq_printf(m, "  - smp_mb(): Full memory barrier, prevents all reordering\n");
    seq_printf(m, "  - smp_wmb(): Write barrier, orders stores\n");
    seq_printf(m, "  - smp_rmb(): Read barrier, orders loads\n");
    seq_printf(m, "  - MFENCE: x86 assembly fence instruction\n");
    
    seq_printf(m, "\nInterpretation:\n");
    seq_printf(m, "  - Higher reordering rate indicates weaker memory ordering\n");
    seq_printf(m, "  - Use 'perf stat -e cycles,instructions' during test\n");
    seq_printf(m, "  - Check /proc/cpuinfo for CPU memory ordering model\n");
    
    return 0;
}

static int memory_barrier_open(struct inode *inode, struct file *file)
{
    return single_open(file, memory_barrier_show, NULL);
}

static ssize_t memory_barrier_write(struct file *file, const char __user *buffer,
                                   size_t count, loff_t *pos)
{
    char cmd[32];
    int barrier_type, thread_count;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (sscanf(cmd, "start %d", &barrier_type) == 1) {
        if (barrier_type >= 0 && barrier_type < ARRAY_SIZE(barrier_names)) {
            int ret = start_barrier_test(barrier_type);
            if (ret)
                return ret;
            pr_info("Started memory barrier test: %s\n", barrier_names[barrier_type]);
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_barrier_test();
    } else if (sscanf(cmd, "threads %d", &thread_count) == 1) {
        if (thread_count >= 2 && thread_count <= MAX_THREADS) {
            num_test_threads = thread_count;
            pr_info("Set thread count to %d\n", thread_count);
        } else {
            return -EINVAL;
        }
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops memory_barrier_proc_ops = {
    .proc_open = memory_barrier_open,
    .proc_read = seq_read,
    .proc_write = memory_barrier_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init memory_barrier_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &memory_barrier_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("Memory barrier demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit memory_barrier_exit(void)
{
    stop_barrier_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("Memory barrier demo module unloaded\n");
}

module_init(memory_barrier_init);
module_exit(memory_barrier_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Memory barrier and fence consistency demonstration");
MODULE_VERSION("1.0");