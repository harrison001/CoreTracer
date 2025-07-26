/*
 * Per-CPU Variables vs False Sharing Comparison
 * 
 * This module demonstrates the performance differences between per-CPU variables
 * and regular shared variables, showing the impact of false sharing and
 * NUMA-local vs global variable access patterns.
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
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/cpumask.h>
#include <linux/numa.h>
#include <linux/topology.h>

#define MODULE_NAME "percpu_demo"
#define PROC_NAME "percpu_demo"
#define MAX_THREADS 16
#define TEST_ITERATIONS 100000
#define CACHELINE_SIZE 64

static struct proc_dir_entry *proc_entry;

// Test data structures
struct shared_counters {
    volatile long counter1;
    volatile long counter2;
    volatile long counter3;
    volatile long counter4;
    volatile long counter5;
    volatile long counter6;
    volatile long counter7;
    volatile long counter8;
} __attribute__((packed)); // Force false sharing

struct aligned_counters {
    volatile long counter1 ____cacheline_aligned;
    volatile long counter2 ____cacheline_aligned;
    volatile long counter3 ____cacheline_aligned;
    volatile long counter4 ____cacheline_aligned;
    volatile long counter5 ____cacheline_aligned;
    volatile long counter6 ____cacheline_aligned;
    volatile long counter7 ____cacheline_aligned;
    volatile long counter8 ____cacheline_aligned;
};

struct percpu_test_data {
    // Different counter types for comparison
    struct shared_counters *shared_false_sharing;
    struct aligned_counters *shared_aligned;
    
    // Per-CPU variables
    long __percpu *percpu_counters;
    atomic_t __percpu *percpu_atomics;
    
    // Global atomics for comparison
    atomic_t global_atomic;
    atomic_t global_atomic_array[MAX_THREADS];
    
    // NUMA-aware data
    long *numa_local_data[MAX_NUMNODES];
    long *numa_remote_data;
    
    // Test control
    atomic_t active_threads;
    atomic_t start_flag;
    atomic_t stop_flag;
    bool test_running;
    
    // Performance measurements
    unsigned long test_duration[MAX_THREADS];
    unsigned long operations_per_second[MAX_THREADS];
    unsigned long cache_misses[MAX_THREADS];
    unsigned long context_switches[MAX_THREADS];
    
    // Thread management
    struct task_struct *worker_threads[MAX_THREADS];
    enum percpu_test_type test_type;
    
    // Statistics
    unsigned long total_false_sharing_time;
    unsigned long total_aligned_time;
    unsigned long total_percpu_time;
    unsigned long total_numa_local_time;
    unsigned long total_numa_remote_time;
};

struct thread_context {
    int thread_id;
    int cpu_id;
    int numa_node;
    struct percpu_test_data *test_data;
    unsigned long local_operations;
    unsigned long local_duration;
    unsigned long start_time;
    unsigned long end_time;
};

enum percpu_test_type {
    PERCPU_TEST_FALSE_SHARING,
    PERCPU_TEST_CACHE_ALIGNED,
    PERCPU_TEST_PERCPU_VARS,
    PERCPU_TEST_NUMA_LOCAL,
    PERCPU_TEST_NUMA_REMOTE,
    PERCPU_TEST_ATOMIC_CONTENTION,
    PERCPU_TEST_COMPARISON
};

static const char *percpu_test_names[] = {
    "False Sharing Test",
    "Cache-Aligned Test", 
    "Per-CPU Variables Test",
    "NUMA Local Access",
    "NUMA Remote Access",
    "Atomic Contention",
    "Performance Comparison"
};

static struct percpu_test_data test_data;

/*
 * False sharing worker - all threads access packed structure
 */
static int percpu_false_sharing_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    volatile long *counter;
    
    // Each thread gets its own counter in the packed structure
    counter = &((volatile long *)td->shared_false_sharing)[ctx->thread_id % 8];
    
    pr_info("False sharing worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Read-modify-write operations that cause false sharing
        (*counter)++;
        (*counter) += iteration;
        (*counter) *= 2;
        (*counter) /= 2;
        
        ctx->local_operations += 4;
        
        // Occasional yield to allow measurement
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("False sharing worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * Cache-aligned worker - threads access cache-aligned structure
 */
static int percpu_aligned_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    volatile long *counter;
    
    // Each thread gets its own cache-aligned counter
    counter = &((volatile long *)td->shared_aligned)[ctx->thread_id % 8];
    
    pr_info("Aligned worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Same operations as false sharing test, but no false sharing
        (*counter)++;
        (*counter) += iteration;
        (*counter) *= 2;
        (*counter) /= 2;
        
        ctx->local_operations += 4;
        
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("Aligned worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * Per-CPU variable worker - uses kernel per-CPU variables
 */
static int percpu_variable_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    long *counter;
    
    pr_info("Per-CPU worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Access per-CPU variable (automatically CPU-local)
        counter = this_cpu_ptr(td->percpu_counters);
        
        (*counter)++;
        (*counter) += iteration;
        (*counter) *= 2;
        (*counter) /= 2;
        
        ctx->local_operations += 4;
        
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("Per-CPU worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * NUMA local access worker
 */
static int percpu_numa_local_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    long *local_data;
    int node = numa_node_id();
    
    pr_info("NUMA local worker %d starting on CPU %d, node %d\n", 
            ctx->thread_id, smp_processor_id(), node);
    
    // Use NUMA-local data if available
    if (node < MAX_NUMNODES && td->numa_local_data[node]) {
        local_data = td->numa_local_data[node];
    } else {
        local_data = td->numa_remote_data; // Fallback
    }
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Access NUMA-local memory
        int idx = ctx->thread_id % 1024; // Spread across array
        local_data[idx]++;
        local_data[idx] += iteration;
        local_data[idx] *= 2;
        local_data[idx] /= 2;
        
        ctx->local_operations += 4;
        
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("NUMA local worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * NUMA remote access worker - deliberately accesses remote memory
 */
static int percpu_numa_remote_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    long *remote_data;
    
    pr_info("NUMA remote worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    // Always use the remote data (allocated on different node)
    remote_data = td->numa_remote_data;
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Access NUMA-remote memory
        int idx = ctx->thread_id % 1024;
        remote_data[idx]++;
        remote_data[idx] += iteration;
        remote_data[idx] *= 2;
        remote_data[idx] /= 2;
        
        ctx->local_operations += 4;
        
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("NUMA remote worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * Atomic contention worker - tests atomic variable contention
 */
static int percpu_atomic_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct percpu_test_data *td = ctx->test_data;
    int iteration;
    atomic_t *percpu_atomic, *global_atomic;
    
    pr_info("Atomic worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    percpu_atomic = this_cpu_ptr(td->percpu_atomics);
    global_atomic = &td->global_atomic;
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    ctx->start_time = get_cycles();
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Alternate between per-CPU and global atomics
        if (iteration % 2 == 0) {
            atomic_inc(percpu_atomic);
            atomic_add(iteration, percpu_atomic);
        } else {
            atomic_inc(global_atomic);
            atomic_add(iteration, global_atomic);
        }
        
        ctx->local_operations += 2;
        
        if (iteration % 10000 == 0) {
            cond_resched();
        }
    }
    
    ctx->end_time = get_cycles();
    ctx->local_duration = ctx->end_time - ctx->start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("Atomic worker %d completed, ops: %lu, duration: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_duration);
    
    return 0;
}

/*
 * Allocate NUMA-aware data structures
 */
static int allocate_numa_data(void)
{
    int node;
    
    // Allocate local data for each NUMA node
    for_each_online_node(node) {
        test_data.numa_local_data[node] = kmalloc_node(
            1024 * sizeof(long), GFP_KERNEL, node);
        if (!test_data.numa_local_data[node]) {
            pr_err("Failed to allocate NUMA local data for node %d\n", node);
            return -ENOMEM;
        }
        memset(test_data.numa_local_data[node], 0, 1024 * sizeof(long));
    }
    
    // Allocate remote data on a different node if possible
    int current_node = numa_node_id();
    int remote_node = current_node;
    
    for_each_online_node(node) {
        if (node != current_node) {
            remote_node = node;
            break;
        }
    }
    
    test_data.numa_remote_data = kmalloc_node(
        1024 * sizeof(long), GFP_KERNEL, remote_node);
    if (!test_data.numa_remote_data) {
        pr_err("Failed to allocate NUMA remote data\n");
        return -ENOMEM;
    }
    memset(test_data.numa_remote_data, 0, 1024 * sizeof(long));
    
    pr_info("Allocated NUMA data: local nodes, remote on node %d\n", remote_node);
    return 0;
}

/*
 * Free NUMA data structures
 */
static void free_numa_data(void)
{
    int node;
    
    for_each_online_node(node) {
        if (test_data.numa_local_data[node]) {
            kfree(test_data.numa_local_data[node]);
            test_data.numa_local_data[node] = NULL;
        }
    }
    
    if (test_data.numa_remote_data) {
        kfree(test_data.numa_remote_data);
        test_data.numa_remote_data = NULL;
    }
}

/*
 * Start per-CPU test with specified type
 */
static int start_percpu_test(enum percpu_test_type test_type, int num_threads)
{
    int i, ret;
    int (*worker_func)(void *);
    struct thread_context *contexts;
    
    if (test_data.test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    if (num_threads > MAX_THREADS) {
        pr_warn("Too many threads: %d (max: %d)\n", num_threads, MAX_THREADS);
        return -EINVAL;
    }
    
    // Select worker function
    switch (test_type) {
        case PERCPU_TEST_FALSE_SHARING:
            worker_func = percpu_false_sharing_worker;
            break;
        case PERCPU_TEST_CACHE_ALIGNED:
            worker_func = percpu_aligned_worker;
            break;
        case PERCPU_TEST_PERCPU_VARS:
            worker_func = percpu_variable_worker;
            break;
        case PERCPU_TEST_NUMA_LOCAL:
            worker_func = percpu_numa_local_worker;
            break;
        case PERCPU_TEST_NUMA_REMOTE:
            worker_func = percpu_numa_remote_worker;
            break;
        case PERCPU_TEST_ATOMIC_CONTENTION:
            worker_func = percpu_atomic_worker;
            break;
        default:
            pr_err("Unsupported test type: %d\n", test_type);
            return -EINVAL;
    }
    
    contexts = kzalloc(num_threads * sizeof(struct thread_context), GFP_KERNEL);
    if (!contexts) {
        pr_err("Failed to allocate contexts\n");
        return -ENOMEM;
    }
    
    // Initialize test state
    memset(&test_data.test_duration, 0, sizeof(test_data.test_duration));
    memset(&test_data.operations_per_second, 0, sizeof(test_data.operations_per_second));
    atomic_set(&test_data.active_threads, 0);
    atomic_set(&test_data.start_flag, 0);
    atomic_set(&test_data.stop_flag, 0);
    
    test_data.test_type = test_type;
    test_data.test_running = true;
    
    pr_info("Starting per-CPU test: %s with %d threads\n", 
            percpu_test_names[test_type], num_threads);
    
    // Create worker threads
    for (i = 0; i < num_threads; i++) {
        contexts[i].thread_id = i;
        contexts[i].cpu_id = i % num_online_cpus();
        contexts[i].numa_node = cpu_to_node(contexts[i].cpu_id);
        contexts[i].test_data = &test_data;
        contexts[i].local_operations = 0;
        contexts[i].local_duration = 0;
        
        test_data.worker_threads[i] = kthread_create(worker_func, &contexts[i],
                                                    "percpu_%d", i);
        if (IS_ERR(test_data.worker_threads[i])) {
            pr_err("Failed to create thread %d\n", i);
            ret = PTR_ERR(test_data.worker_threads[i]);
            // Cleanup
            for (int j = 0; j < i; j++) {
                if (test_data.worker_threads[j]) {
                    kthread_stop(test_data.worker_threads[j]);
                }
            }
            kfree(contexts);
            test_data.test_running = false;
            return ret;
        }
        
        // Bind to specific CPU
        kthread_bind(test_data.worker_threads[i], contexts[i].cpu_id);
        wake_up_process(test_data.worker_threads[i]);
    }
    
    // Wait for threads to be ready
    while (atomic_read(&test_data.active_threads) < num_threads) {
        msleep(1);
    }
    
    pr_info("All threads ready, starting test\n");
    atomic_set(&test_data.start_flag, 1);
    
    return 0;
}

/*
 * Stop running test
 */
static void stop_percpu_test(void)
{
    int i;
    
    if (!test_data.test_running)
        return;
    
    pr_info("Stopping per-CPU test\n");
    
    atomic_set(&test_data.stop_flag, 1);
    test_data.test_running = false;
    
    // Stop threads
    for (i = 0; i < MAX_THREADS; i++) {
        if (test_data.worker_threads[i]) {
            kthread_stop(test_data.worker_threads[i]);
            test_data.worker_threads[i] = NULL;
        }
    }
    
    pr_info("Per-CPU test stopped\n");
}

static int percpu_demo_show(struct seq_file *m, void *v)
{
    int i, node;
    
    seq_printf(m, "=== Per-CPU Variables vs False Sharing Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  Test Status: %s\n", test_data.test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Active Threads: %d\n", atomic_read(&test_data.active_threads));
    seq_printf(m, "  CPUs Online: %d\n", num_online_cpus());
    seq_printf(m, "  NUMA Nodes: %d\n", num_online_nodes());
    seq_printf(m, "  Cache Line Size: %d bytes\n\n", CACHELINE_SIZE);
    
    if (!test_data.test_running) {
        seq_printf(m, "Performance Results:\n");
        for (i = 0; i < MAX_THREADS; i++) {
            if (test_data.test_duration[i] > 0) {
                seq_printf(m, "  Thread %d: %lu cycles, %lu ops/sec\n", 
                          i, test_data.test_duration[i], test_data.operations_per_second[i]);
            }
        }
        seq_printf(m, "\n");
    }
    
    seq_printf(m, "Per-CPU Variable Status:\n");
    if (test_data.percpu_counters) {
        seq_printf(m, "  Per-CPU counters allocated: Yes\n");
        for_each_online_cpu(i) {
            long *counter = per_cpu_ptr(test_data.percpu_counters, i);
            seq_printf(m, "    CPU %d: %ld\n", i, *counter);
        }
    } else {
        seq_printf(m, "  Per-CPU counters allocated: No\n");
    }
    seq_printf(m, "\n");
    
    seq_printf(m, "NUMA Memory Layout:\n");
    for_each_online_node(node) {
        seq_printf(m, "  Node %d: %s\n", node, 
                  test_data.numa_local_data[node] ? "allocated" : "not allocated");
    }
    seq_printf(m, "  Remote data: %s\n\n", 
              test_data.numa_remote_data ? "allocated" : "not allocated");
    
    seq_printf(m, "Atomic Counters:\n");
    seq_printf(m, "  Global atomic: %d\n", atomic_read(&test_data.global_atomic));
    if (test_data.percpu_atomics) {
        for_each_online_cpu(i) {
            atomic_t *atomic = per_cpu_ptr(test_data.percpu_atomics, i);
            seq_printf(m, "  Per-CPU atomic %d: %d\n", i, atomic_read(atomic));
        }
    }
    seq_printf(m, "\n");
    
    seq_printf(m, "Available Tests:\n");
    for (i = 0; i < ARRAY_SIZE(percpu_test_names); i++) {
        seq_printf(m, "  %d: %s\n", i, percpu_test_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start <type> <threads>' > /proc/%s\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Compare performance between false sharing and aligned tests\n");
    seq_printf(m, "  - Observe per-CPU vs global atomic contention\n");
    seq_printf(m, "  - Monitor NUMA effects with 'numastat' during tests\n");
    seq_printf(m, "  - Use 'perf stat -e cache-misses' to measure cache behavior\n");
    
    return 0;
}

static int percpu_demo_open(struct inode *inode, struct file *file)
{
    return single_open(file, percpu_demo_show, NULL);
}

static ssize_t percpu_demo_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *pos)
{
    char cmd[32];
    int test_type, num_threads;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (sscanf(cmd, "start %d %d", &test_type, &num_threads) == 2) {
        if (test_type >= 0 && test_type < ARRAY_SIZE(percpu_test_names)) {
            int ret = start_percpu_test(test_type, num_threads);
            if (ret)
                return ret;
            pr_info("Started per-CPU test: %s\n", percpu_test_names[test_type]);
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_percpu_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops percpu_demo_proc_ops = {
    .proc_open = percpu_demo_open,
    .proc_read = seq_read,
    .proc_write = percpu_demo_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init percpu_demo_init(void)
{
    int ret;
    
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &percpu_demo_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    // Allocate shared data structures
    test_data.shared_false_sharing = kzalloc(sizeof(struct shared_counters), GFP_KERNEL);
    if (!test_data.shared_false_sharing) {
        pr_err("Failed to allocate shared false sharing structure\n");
        ret = -ENOMEM;
        goto err_proc;
    }
    
    test_data.shared_aligned = kzalloc(sizeof(struct aligned_counters), GFP_KERNEL);
    if (!test_data.shared_aligned) {
        pr_err("Failed to allocate shared aligned structure\n");
        ret = -ENOMEM;
        goto err_false_sharing;
    }
    
    // Allocate per-CPU variables
    test_data.percpu_counters = alloc_percpu(long);
    if (!test_data.percpu_counters) {
        pr_err("Failed to allocate per-CPU counters\n");
        ret = -ENOMEM;
        goto err_aligned;
    }
    
    test_data.percpu_atomics = alloc_percpu(atomic_t);
    if (!test_data.percpu_atomics) {
        pr_err("Failed to allocate per-CPU atomics\n");
        ret = -ENOMEM;
        goto err_percpu_counters;
    }
    
    // Initialize atomics
    atomic_set(&test_data.global_atomic, 0);
    for (int i = 0; i < MAX_THREADS; i++) {
        atomic_set(&test_data.global_atomic_array[i], 0);
    }
    
    // Allocate NUMA-aware data
    ret = allocate_numa_data();
    if (ret) {
        goto err_percpu_atomics;
    }
    
    // Initialize test data
    memset(&test_data.worker_threads, 0, sizeof(test_data.worker_threads));
    
    pr_info("Per-CPU demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
    
err_percpu_atomics:
    free_percpu(test_data.percpu_atomics);
err_percpu_counters:
    free_percpu(test_data.percpu_counters);
err_aligned:
    kfree(test_data.shared_aligned);
err_false_sharing:
    kfree(test_data.shared_false_sharing);
err_proc:
    proc_remove(proc_entry);
    return ret;
}

static void __exit percpu_demo_exit(void)
{
    stop_percpu_test();
    
    // Free all allocated memory
    free_numa_data();
    
    if (test_data.percpu_atomics) {
        free_percpu(test_data.percpu_atomics);
    }
    
    if (test_data.percpu_counters) {
        free_percpu(test_data.percpu_counters);
    }
    
    if (test_data.shared_aligned) {
        kfree(test_data.shared_aligned);
    }
    
    if (test_data.shared_false_sharing) {
        kfree(test_data.shared_false_sharing);
    }
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("Per-CPU demo module unloaded\n");
}

module_init(percpu_demo_init);
module_exit(percpu_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Per-CPU variables vs false sharing comparison");
MODULE_VERSION("1.0");