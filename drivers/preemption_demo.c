/*
 * Kernel Preemption and Interrupt Demonstration
 * 
 * This module demonstrates kernel preemption behavior, interrupt handling
 * effects, real-time vs throughput trade-offs, and interrupt storm analysis.
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
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#define MODULE_NAME "preemption_demo"
#define PROC_NAME "preemption_demo"
#define MAX_THREADS 8
#define TEST_ITERATIONS 10000
#define TIMER_INTERVAL_MS 1

static struct proc_dir_entry *proc_entry;

struct preemption_test_data {
    // Preemption tracking
    atomic_t preemption_count[MAX_THREADS];
    atomic_t voluntary_preemption;
    atomic_t involuntary_preemption;
    unsigned long max_latency[MAX_THREADS];
    unsigned long total_latency[MAX_THREADS];
    unsigned long schedule_count[MAX_THREADS];
    
    // Interrupt simulation
    struct timer_list test_timer;
    atomic_t timer_interrupts;
    unsigned long interrupt_latency;
    unsigned long interrupt_overhead;
    
    // High-resolution timer for RT testing
    struct hrtimer hr_timer;
    atomic_t hr_timer_count;
    ktime_t hr_timer_start;
    unsigned long rt_latency_max;
    unsigned long rt_latency_avg;
    
    // Workqueue for bottom-half simulation
    struct workqueue_struct *test_wq;
    struct work_struct test_work;
    atomic_t work_count;
    
    // Test control
    atomic_t active_threads;
    atomic_t start_flag;
    atomic_t stop_flag;
    bool test_running;
    
    // Thread management
    struct task_struct *worker_threads[MAX_THREADS];
    enum preemption_test_type test_type;
    
    // Critical section tracking
    spinlock_t critical_lock;
    unsigned long critical_section_time[MAX_THREADS];
    atomic_t lock_contention_count;
};

struct thread_context {
    int thread_id;
    int priority;
    struct preemption_test_data *test_data;
    unsigned long local_preemptions;
    unsigned long local_latency;
    unsigned long work_start_time;
    unsigned long work_end_time;
    bool is_rt_thread;
};

enum preemption_test_type {
    PREEMPT_TEST_BASIC,
    PREEMPT_TEST_RT_LATENCY,
    PREEMPT_TEST_INTERRUPT_STORM,
    PREEMPT_TEST_LOCK_CONTENTION,
    PREEMPT_TEST_WORKQUEUE
};

static const char *preemption_test_names[] = {
    "Basic Preemption",
    "RT Latency Analysis",
    "Interrupt Storm",
    "Lock Contention",
    "Workqueue Performance"
};

static struct preemption_test_data test_data;

/*
 * Timer interrupt handler for interrupt storm simulation
 */
static void test_timer_handler(struct timer_list *timer)
{
    unsigned long start_time, end_time;
    
    start_time = get_cycles();
    
    atomic_inc(&test_data.timer_interrupts);
    
    // Simulate interrupt work
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }
    
    end_time = get_cycles();
    test_data.interrupt_overhead += (end_time - start_time);
    
    // Re-arm timer if test is still running
    if (test_data.test_running && test_data.test_type == PREEMPT_TEST_INTERRUPT_STORM) {
        mod_timer(&test_data.test_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
    }
}

/*
 * High-resolution timer handler for RT latency testing
 */
static enum hrtimer_restart hr_timer_handler(struct hrtimer *timer)
{
    ktime_t now = ktime_get();
    unsigned long latency;
    
    latency = ktime_to_ns(ktime_sub(now, test_data.hr_timer_start));
    
    atomic_inc(&test_data.hr_timer_count);
    
    if (latency > test_data.rt_latency_max) {
        test_data.rt_latency_max = latency;
    }
    
    // Update running average
    test_data.rt_latency_avg = (test_data.rt_latency_avg + latency) / 2;
    
    if (test_data.test_running && test_data.test_type == PREEMPT_TEST_RT_LATENCY) {
        test_data.hr_timer_start = ktime_add_ms(now, TIMER_INTERVAL_MS);
        hrtimer_forward_now(timer, ms_to_ktime(TIMER_INTERVAL_MS));
        return HRTIMER_RESTART;
    }
    
    return HRTIMER_NORESTART;
}

/*
 * Workqueue handler for bottom-half simulation
 */
static void test_work_handler(struct work_struct *work)
{
    unsigned long start_time, end_time;
    
    start_time = get_cycles();
    
    atomic_inc(&test_data.work_count);
    
    // Simulate work processing
    msleep(1);
    
    end_time = get_cycles();
    
    // Schedule more work if test is running
    if (test_data.test_running && test_data.test_type == PREEMPT_TEST_WORKQUEUE) {
        queue_work(test_data.test_wq, &test_data.test_work);
    }
}

/*
 * Basic preemption worker - tests voluntary and involuntary preemption
 */
static int preemption_basic_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct preemption_test_data *td = ctx->test_data;
    int iteration;
    unsigned long start_time, end_time, preempt_start;
    unsigned long prev_voluntary, prev_involuntary;
    
    pr_info("Basic preemption worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    // Get initial preemption counts
    prev_voluntary = current->nvcsw;
    prev_involuntary = current->nivcsw;
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        start_time = get_cycles();
        
        // CPU-intensive work to trigger involuntary preemption
        volatile long sum = 0;
        for (int i = 0; i < 10000; i++) {
            sum += i * i;
        }
        
        // Voluntary preemption point
        if (iteration % 100 == 0) {
            preempt_start = get_cycles();
            cond_resched();
            end_time = get_cycles();
            
            ctx->local_latency += (end_time - preempt_start);
        }
        
        // Check for preemption
        if (current->nvcsw > prev_voluntary) {
            atomic_inc(&td->voluntary_preemption);
            atomic_inc(&td->preemption_count[ctx->thread_id]);
            prev_voluntary = current->nvcsw;
        }
        
        if (current->nivcsw > prev_involuntary) {
            atomic_inc(&td->involuntary_preemption);
            atomic_inc(&td->preemption_count[ctx->thread_id]);
            prev_involuntary = current->nivcsw;
        }
        
        ctx->local_preemptions = atomic_read(&td->preemption_count[ctx->thread_id]);
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Basic preemption worker %d completed, preemptions: %lu\n",
            ctx->thread_id, ctx->local_preemptions);
    
    return 0;
}

/*
 * RT latency worker - high priority thread for latency measurement
 */
static int preemption_rt_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct preemption_test_data *td = ctx->test_data;
    int iteration;
    unsigned long start_time, end_time, latency;
    struct sched_param param;
    
    // Set RT priority
    param.sched_priority = ctx->priority;
    sched_setscheduler(current, SCHED_FIFO, &param);
    
    pr_info("RT latency worker %d starting (priority %d) on CPU %d\n", 
            ctx->thread_id, ctx->priority, smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        start_time = get_cycles();
        
        // Wait for a condition (simulating RT response requirement)
        while (atomic_read(&td->timer_interrupts) < iteration + 1 && 
               !kthread_should_stop()) {
            cpu_relax();
        }
        
        end_time = get_cycles();
        latency = end_time - start_time;
        
        // Track latency statistics
        if (latency > td->max_latency[ctx->thread_id]) {
            td->max_latency[ctx->thread_id] = latency;
        }
        
        td->total_latency[ctx->thread_id] += latency;
        td->schedule_count[ctx->thread_id]++;
        
        // RT work (should be quick and deterministic)
        volatile int dummy = 0;
        for (int i = 0; i < 10; i++) {
            dummy += i;
        }
        
        if (iteration % 1000 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("RT latency worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Lock contention worker - tests preemption during critical sections
 */
static int preemption_lock_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct preemption_test_data *td = ctx->test_data;
    int iteration;
    unsigned long start_time, end_time;
    unsigned long flags;
    
    pr_info("Lock contention worker %d starting on CPU %d\n", 
            ctx->thread_id, smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        start_time = get_cycles();
        
        // Try to acquire spinlock (disables preemption)
        if (spin_trylock_irqsave(&td->critical_lock, flags)) {
            // Critical section work
            volatile long sum = 0;
            for (int i = 0; i < 1000; i++) {
                sum += i;
            }
            
            end_time = get_cycles();
            td->critical_section_time[ctx->thread_id] += (end_time - start_time);
            
            spin_unlock_irqrestore(&td->critical_lock, flags);
        } else {
            // Lock contention
            atomic_inc(&td->lock_contention_count);
            
            // Fallback work without lock
            volatile long sum = 0;
            for (int i = 0; i < 100; i++) {
                sum += i;
            }
        }
        
        // Voluntary preemption outside critical section
        if (iteration % 50 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Lock contention worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Start preemption test with specified type
 */
static int start_preemption_test(enum preemption_test_type test_type, int num_threads)
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
        case PREEMPT_TEST_BASIC:
            worker_func = preemption_basic_worker;
            break;
        case PREEMPT_TEST_RT_LATENCY:
            worker_func = preemption_rt_worker;
            break;
        case PREEMPT_TEST_LOCK_CONTENTION:
            worker_func = preemption_lock_worker;
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
    for (i = 0; i < MAX_THREADS; i++) {
        atomic_set(&test_data.preemption_count[i], 0);
        test_data.max_latency[i] = 0;
        test_data.total_latency[i] = 0;
        test_data.schedule_count[i] = 0;
        test_data.critical_section_time[i] = 0;
    }
    
    atomic_set(&test_data.voluntary_preemption, 0);
    atomic_set(&test_data.involuntary_preemption, 0);
    atomic_set(&test_data.timer_interrupts, 0);
    atomic_set(&test_data.hr_timer_count, 0);
    atomic_set(&test_data.work_count, 0);
    atomic_set(&test_data.lock_contention_count, 0);
    atomic_set(&test_data.active_threads, 0);
    atomic_set(&test_data.start_flag, 0);
    atomic_set(&test_data.stop_flag, 0);
    
    test_data.test_type = test_type;
    test_data.test_running = true;
    test_data.interrupt_overhead = 0;
    test_data.rt_latency_max = 0;
    test_data.rt_latency_avg = 0;
    
    pr_info("Starting preemption test: %s with %d threads\n", 
            preemption_test_names[test_type], num_threads);
    
    // Start timers/workqueues based on test type
    if (test_type == PREEMPT_TEST_INTERRUPT_STORM) {
        mod_timer(&test_data.test_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
    } else if (test_type == PREEMPT_TEST_RT_LATENCY) {
        test_data.hr_timer_start = ktime_get();
        hrtimer_start(&test_data.hr_timer, ms_to_ktime(TIMER_INTERVAL_MS), HRTIMER_MODE_REL);
    } else if (test_type == PREEMPT_TEST_WORKQUEUE) {
        queue_work(test_data.test_wq, &test_data.test_work);
    }
    
    // Create worker threads
    for (i = 0; i < num_threads; i++) {
        contexts[i].thread_id = i;
        contexts[i].test_data = &test_data;
        contexts[i].local_preemptions = 0;
        contexts[i].local_latency = 0;
        contexts[i].is_rt_thread = (test_type == PREEMPT_TEST_RT_LATENCY && i == 0);
        
        // Set priority for RT test
        if (test_type == PREEMPT_TEST_RT_LATENCY) {
            contexts[i].priority = (i == 0) ? 50 : 0; // First thread high priority
        } else {
            contexts[i].priority = 0;
        }
        
        test_data.worker_threads[i] = kthread_create(worker_func, &contexts[i],
                                                    "preempt_%d", i);
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
static void stop_preemption_test(void)
{
    int i;
    
    if (!test_data.test_running)
        return;
    
    pr_info("Stopping preemption test\n");
    
    atomic_set(&test_data.stop_flag, 1);
    test_data.test_running = false;
    
    // Stop timers and workqueue
    del_timer_sync(&test_data.test_timer);
    hrtimer_cancel(&test_data.hr_timer);
    if (test_data.test_wq) {
        cancel_work_sync(&test_data.test_work);
    }
    
    // Stop threads
    for (i = 0; i < MAX_THREADS; i++) {
        if (test_data.worker_threads[i]) {
            kthread_stop(test_data.worker_threads[i]);
            test_data.worker_threads[i] = NULL;
        }
    }
    
    pr_info("Preemption test stopped\n");
}

static int preemption_demo_show(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "=== Kernel Preemption & Interrupt Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  Test Status: %s\n", test_data.test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Active Threads: %d\n", atomic_read(&test_data.active_threads));
    seq_printf(m, "  Preemption Enabled: %s\n", 
#ifdef CONFIG_PREEMPT
              "Yes"
#else
              "No"
#endif
              );
    seq_printf(m, "  RT Preemption: %s\n\n",
#ifdef CONFIG_PREEMPT_RT
              "Yes"
#else
              "No"
#endif
              );
    
    if (!test_data.test_running) {
        seq_printf(m, "Preemption Statistics:\n");
        seq_printf(m, "  Voluntary Preemptions: %d\n", atomic_read(&test_data.voluntary_preemption));
        seq_printf(m, "  Involuntary Preemptions: %d\n", atomic_read(&test_data.involuntary_preemption));
        seq_printf(m, "  Lock Contentions: %d\n\n", atomic_read(&test_data.lock_contention_count));
        
        seq_printf(m, "Per-Thread Statistics:\n");
        for (i = 0; i < MAX_THREADS; i++) {
            if (test_data.schedule_count[i] > 0) {
                seq_printf(m, "  Thread %d:\n", i);
                seq_printf(m, "    Preemptions: %d\n", atomic_read(&test_data.preemption_count[i]));
                seq_printf(m, "    Max Latency: %lu cycles\n", test_data.max_latency[i]);
                seq_printf(m, "    Avg Latency: %lu cycles\n", 
                          test_data.schedule_count[i] > 0 ? 
                              test_data.total_latency[i] / test_data.schedule_count[i] : 0);
                seq_printf(m, "    Critical Section Time: %lu cycles\n", test_data.critical_section_time[i]);
            }
        }
        
        seq_printf(m, "\nTimer/Interrupt Statistics:\n");
        seq_printf(m, "  Timer Interrupts: %d\n", atomic_read(&test_data.timer_interrupts));
        seq_printf(m, "  HR Timer Count: %d\n", atomic_read(&test_data.hr_timer_count));
        seq_printf(m, "  Work Items: %d\n", atomic_read(&test_data.work_count));
        seq_printf(m, "  Interrupt Overhead: %lu cycles\n", test_data.interrupt_overhead);
        seq_printf(m, "  RT Max Latency: %lu ns\n", test_data.rt_latency_max);
        seq_printf(m, "  RT Avg Latency: %lu ns\n\n", test_data.rt_latency_avg);
    }
    
    seq_printf(m, "Available Tests:\n");
    for (i = 0; i < ARRAY_SIZE(preemption_test_names); i++) {
        seq_printf(m, "  %d: %s\n", i, preemption_test_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start <type> <threads>' > /proc/%s\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Monitor /proc/interrupts during interrupt storm test\n");
    seq_printf(m, "  - Use 'cyclictest' for external RT latency comparison\n");
    seq_printf(m, "  - Check /proc/stat for context switch statistics\n");
    seq_printf(m, "  - Use 'perf sched record/report' for detailed scheduling analysis\n");
    
    return 0;
}

static int preemption_demo_open(struct inode *inode, struct file *file)
{
    return single_open(file, preemption_demo_show, NULL);
}

static ssize_t preemption_demo_write(struct file *file, const char __user *buffer,
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
        if (test_type >= 0 && test_type < ARRAY_SIZE(preemption_test_names)) {
            int ret = start_preemption_test(test_type, num_threads);
            if (ret)
                return ret;
            pr_info("Started preemption test: %s\n", preemption_test_names[test_type]);
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_preemption_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops preemption_demo_proc_ops = {
    .proc_open = preemption_demo_open,
    .proc_read = seq_read,
    .proc_write = preemption_demo_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init preemption_demo_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &preemption_demo_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    // Initialize locks and timers
    spin_lock_init(&test_data.critical_lock);
    timer_setup(&test_data.test_timer, test_timer_handler, 0);
    hrtimer_init(&test_data.hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    test_data.hr_timer.function = hr_timer_handler;
    
    // Create workqueue
    test_data.test_wq = create_workqueue("preemption_test_wq");
    if (!test_data.test_wq) {
        pr_err("Failed to create workqueue\n");
        proc_remove(proc_entry);
        return -ENOMEM;
    }
    
    INIT_WORK(&test_data.test_work, test_work_handler);
    
    // Initialize test data
    memset(&test_data.worker_threads, 0, sizeof(test_data.worker_threads));
    
    pr_info("Preemption demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit preemption_demo_exit(void)
{
    stop_preemption_test();
    
    // Cleanup workqueue
    if (test_data.test_wq) {
        destroy_workqueue(test_data.test_wq);
    }
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("Preemption demo module unloaded\n");
}

module_init(preemption_demo_init);
module_exit(preemption_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Kernel preemption and interrupt demonstration");
MODULE_VERSION("1.0");