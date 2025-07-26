/*
 * CPU Affinity and NUMA Demonstration Kernel Module
 * 
 * This module demonstrates CPU affinity manipulation and NUMA-aware
 * memory allocation patterns that can reveal performance bottlenecks
 * in multi-core systems.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/numa.h>
#include <linux/topology.h>
#include <linux/uaccess.h>
#include <linux/time.h>

#define MODULE_NAME "affinity_numa_demo"
#define PROC_NAME "affinity_numa"
#define BUFFER_SIZE 1024 * 1024  // 1MB buffer
#define TEST_ITERATIONS 10000

static struct proc_dir_entry *proc_entry;
static struct task_struct *worker_threads[NR_CPUS];
static void *test_buffers[MAX_NUMNODES];
static atomic_t test_results[NR_CPUS];
static bool test_running = false;

struct affinity_test_data {
    int cpu_id;
    int node_id;
    cycles_t start_time;
    cycles_t end_time;
    unsigned long access_count;
};

static int affinity_worker_func(void *data)
{
    struct affinity_test_data *test_data = (struct affinity_test_data *)data;
    void *buffer;
    int i, j;
    volatile char *ptr;
    cycles_t start, end;
    
    set_current_state(TASK_RUNNING);
    
    // Bind to specific CPU
    set_cpus_allowed_ptr(current, cpumask_of(test_data->cpu_id));
    
    // Get buffer from specified NUMA node
    buffer = test_buffers[test_data->node_id];
    if (!buffer) {
        pr_err("No buffer available for node %d\n", test_data->node_id);
        return -ENOMEM;
    }
    
    ptr = (volatile char *)buffer;
    
    pr_info("Worker thread on CPU %d accessing NUMA node %d\n", 
            test_data->cpu_id, test_data->node_id);
    
    start = get_cycles();
    
    // Memory access pattern that will show NUMA effects
    for (i = 0; i < TEST_ITERATIONS && !kthread_should_stop(); i++) {
        for (j = 0; j < BUFFER_SIZE; j += 64) {  // Cache line stride
            ptr[j] = (char)(i + j);
            ptr[j] += 1;  // Read-modify-write
        }
        test_data->access_count++;
        
        if (i % 1000 == 0) {
            cond_resched();  // Be nice to other tasks
        }
    }
    
    end = get_cycles();
    
    test_data->start_time = start;
    test_data->end_time = end;
    
    atomic_inc(&test_results[test_data->cpu_id]);
    
    pr_info("Worker on CPU %d completed: %llu cycles, %lu accesses\n",
            test_data->cpu_id, end - start, test_data->access_count);
    
    return 0;
}

static int start_affinity_test(void)
{
    int cpu, node;
    struct affinity_test_data *test_data;
    
    if (test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    test_running = true;
    
    // Initialize atomic counters
    for_each_possible_cpu(cpu) {
        atomic_set(&test_results[cpu], 0);
    }
    
    // Allocate buffers on each NUMA node
    for_each_online_node(node) {
        test_buffers[node] = kmalloc_node(BUFFER_SIZE, GFP_KERNEL, node);
        if (!test_buffers[node]) {
            pr_err("Failed to allocate buffer on node %d\n", node);
            goto cleanup_buffers;
        }
        pr_info("Allocated %d bytes on NUMA node %d\n", BUFFER_SIZE, node);
    }
    
    // Start worker threads
    for_each_online_cpu(cpu) {
        test_data = kmalloc(sizeof(*test_data), GFP_KERNEL);
        if (!test_data) {
            pr_err("Failed to allocate test data for CPU %d\n", cpu);
            continue;
        }
        
        test_data->cpu_id = cpu;
        test_data->node_id = cpu_to_node(cpu);  // Use local node
        test_data->access_count = 0;
        
        worker_threads[cpu] = kthread_create(affinity_worker_func, test_data,
                                           "affinity_worker_%d", cpu);
        if (IS_ERR(worker_threads[cpu])) {
            pr_err("Failed to create thread for CPU %d\n", cpu);
            kfree(test_data);
            worker_threads[cpu] = NULL;
            continue;
        }
        
        wake_up_process(worker_threads[cpu]);
    }
    
    return 0;

cleanup_buffers:
    for_each_online_node(node) {
        if (test_buffers[node]) {
            kfree(test_buffers[node]);
            test_buffers[node] = NULL;
        }
    }
    test_running = false;
    return -ENOMEM;
}

static void stop_affinity_test(void)
{
    int cpu, node;
    
    if (!test_running)
        return;
    
    // Stop all worker threads
    for_each_possible_cpu(cpu) {
        if (worker_threads[cpu]) {
            kthread_stop(worker_threads[cpu]);
            worker_threads[cpu] = NULL;
        }
    }
    
    // Clean up buffers
    for_each_online_node(node) {
        if (test_buffers[node]) {
            kfree(test_buffers[node]);
            test_buffers[node] = NULL;
        }
    }
    
    test_running = false;
    pr_info("Affinity test stopped\n");
}

static int affinity_numa_show(struct seq_file *m, void *v)
{
    int cpu, node;
    
    seq_printf(m, "=== CPU Affinity & NUMA Demo ===\n\n");
    
    seq_printf(m, "System Info:\n");
    seq_printf(m, "  Online CPUs: %d\n", num_online_cpus());
    seq_printf(m, "  Online Nodes: %d\n", num_online_nodes());
    seq_printf(m, "  Test Status: %s\n\n", test_running ? "RUNNING" : "STOPPED");
    
    seq_printf(m, "CPU-to-Node Mapping:\n");
    for_each_online_cpu(cpu) {
        node = cpu_to_node(cpu);
        seq_printf(m, "  CPU %2d -> Node %d\n", cpu, node);
    }
    seq_printf(m, "\n");
    
    if (test_running) {
        seq_printf(m, "Current Test Results:\n");
        for_each_online_cpu(cpu) {
            seq_printf(m, "  CPU %2d: %d completions\n", 
                      cpu, atomic_read(&test_results[cpu]));
        }
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start' > /proc/%s  # Start affinity test\n", PROC_NAME);
    seq_printf(m, "  echo 'stop'  > /proc/%s  # Stop test\n", PROC_NAME);
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Use 'perf stat -e node-loads,node-load-misses' during test\n");
    seq_printf(m, "  - Monitor with 'numastat' command\n");
    seq_printf(m, "  - Check /proc/buddyinfo for memory fragmentation\n");
    
    return 0;
}

static int affinity_numa_open(struct inode *inode, struct file *file)
{
    return single_open(file, affinity_numa_show, NULL);
}

static ssize_t affinity_numa_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[16];
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (strncmp(cmd, "start", 5) == 0) {
        int ret = start_affinity_test();
        if (ret)
            return ret;
        pr_info("Affinity test started\n");
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_affinity_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops affinity_numa_proc_ops = {
    .proc_open = affinity_numa_open,
    .proc_read = seq_read,
    .proc_write = affinity_numa_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init affinity_numa_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &affinity_numa_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("CPU Affinity & NUMA demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit affinity_numa_exit(void)
{
    stop_affinity_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("CPU Affinity & NUMA demo module unloaded\n");
}

module_init(affinity_numa_init);
module_exit(affinity_numa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("CPU Affinity and NUMA performance demonstration");
MODULE_VERSION("1.0");