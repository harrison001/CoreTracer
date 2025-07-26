/*
 * Deadlock, Livelock, and Priority Inversion Demonstration
 * 
 * This module demonstrates classic concurrency problems in kernel space:
 * - Deadlock scenarios with multiple locks
 * - Livelock situations with competing threads
 * - Priority inversion with RT and normal priority tasks
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
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>

#define MODULE_NAME "deadlock_demo"
#define PROC_NAME "deadlock_demo"
#define MAX_THREADS 8
#define TEST_ITERATIONS 1000

static struct proc_dir_entry *proc_entry;

struct deadlock_test_data {
    // Locks for deadlock scenarios
    struct mutex mutex_a;
    struct mutex mutex_b;
    struct mutex mutex_c;
    spinlock_t spin_a;
    spinlock_t spin_b;
    rwlock_t rw_lock;
    struct semaphore sem_a;
    struct semaphore sem_b;
    
    // Shared resources
    volatile int shared_resource1;
    volatile int shared_resource2;
    volatile int shared_resource3;
    
    // Test control
    atomic_t active_threads;
    atomic_t start_flag;
    atomic_t stop_flag;
    bool test_running;
    
    // Statistics
    unsigned long deadlock_count;
    unsigned long livelock_count;
    unsigned long priority_inversion_count;
    unsigned long successful_operations;
    
    // Thread management
    struct task_struct *worker_threads[MAX_THREADS];
    struct completion test_completion;
    
    // Priority inversion tracking
    unsigned long high_prio_start_time;
    unsigned long high_prio_wait_time;
    unsigned long low_prio_hold_time;
};

struct thread_context {
    int thread_id;
    int priority;
    struct deadlock_test_data *test_data;
    enum test_scenario scenario;
    unsigned long local_operations;
    unsigned long local_wait_time;
    unsigned long local_deadlocks;
};

enum test_scenario {
    SCENARIO_DEADLOCK_AB,
    SCENARIO_DEADLOCK_ABC,
    SCENARIO_LIVELOCK,
    SCENARIO_PRIORITY_INVERSION,
    SCENARIO_STARVATION,
    SCENARIO_READER_WRITER
};

static const char *scenario_names[] = {
    "Deadlock AB (Classic 2-lock)",
    "Deadlock ABC (3-lock circular)",
    "Livelock (Competing retry)",
    "Priority Inversion",
    "Starvation Test",
    "Reader-Writer Fairness"
};

static struct deadlock_test_data test_data;

/*
 * Deadlock scenario: Thread takes locks in different order
 */
static int deadlock_ab_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct deadlock_test_data *td = ctx->test_data;
    int iteration;
    unsigned long start_time, wait_start;
    bool take_a_first = (ctx->thread_id % 2 == 0);
    
    pr_info("Deadlock AB worker %d starting (take A first: %s)\n", 
            ctx->thread_id, take_a_first ? "yes" : "no");
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        wait_start = get_cycles();
        
        if (take_a_first) {
            // Thread A order: mutex_a -> mutex_b
            if (mutex_trylock(&td->mutex_a)) {
                // Introduce delay to increase deadlock probability
                msleep(1);
                
                if (mutex_trylock(&td->mutex_b)) {
                    // Critical section
                    td->shared_resource1++;
                    td->shared_resource2++;
                    ctx->local_operations++;
                    
                    // Hold locks briefly
                    udelay(10);
                    
                    mutex_unlock(&td->mutex_b);
                    mutex_unlock(&td->mutex_a);
                } else {
                    // Failed to get mutex_b, potential deadlock
                    mutex_unlock(&td->mutex_a);
                    ctx->local_deadlocks++;
                    td->deadlock_count++;
                }
            }
        } else {
            // Thread B order: mutex_b -> mutex_a (reverse order)
            if (mutex_trylock(&td->mutex_b)) {
                msleep(1);
                
                if (mutex_trylock(&td->mutex_a)) {
                    // Critical section
                    td->shared_resource1--;
                    td->shared_resource2--;
                    ctx->local_operations++;
                    
                    udelay(10);
                    
                    mutex_unlock(&td->mutex_a);
                    mutex_unlock(&td->mutex_b);
                } else {
                    mutex_unlock(&td->mutex_b);
                    ctx->local_deadlocks++;
                    td->deadlock_count++;
                }
            }
        }
        
        ctx->local_wait_time += get_cycles() - wait_start;
        
        // Yield occasionally
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Deadlock AB worker %d completed, ops: %lu, deadlocks: %lu\n",
            ctx->thread_id, ctx->local_operations, ctx->local_deadlocks);
    
    return 0;
}

/*
 * Three-way deadlock scenario (A->B->C->A)
 */
static int deadlock_abc_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct deadlock_test_data *td = ctx->test_data;
    int iteration;
    unsigned long wait_start;
    int lock_order = ctx->thread_id % 3; // 0: A->B->C, 1: B->C->A, 2: C->A->B
    
    pr_info("Deadlock ABC worker %d starting (order: %d)\n", ctx->thread_id, lock_order);
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        wait_start = get_cycles();
        bool got_all_locks = false;
        
        switch (lock_order) {
            case 0: // A -> B -> C
                if (mutex_trylock(&td->mutex_a)) {
                    msleep(1);
                    if (mutex_trylock(&td->mutex_b)) {
                        msleep(1);
                        if (mutex_trylock(&td->mutex_c)) {
                            got_all_locks = true;
                            // Critical section
                            td->shared_resource1 += 1;
                            td->shared_resource2 += 2;
                            td->shared_resource3 += 3;
                            udelay(15);
                            mutex_unlock(&td->mutex_c);
                        }
                        mutex_unlock(&td->mutex_b);
                    }
                    mutex_unlock(&td->mutex_a);
                }
                break;
                
            case 1: // B -> C -> A
                if (mutex_trylock(&td->mutex_b)) {
                    msleep(1);
                    if (mutex_trylock(&td->mutex_c)) {
                        msleep(1);
                        if (mutex_trylock(&td->mutex_a)) {
                            got_all_locks = true;
                            td->shared_resource1 += 2;
                            td->shared_resource2 += 3;
                            td->shared_resource3 += 1;
                            udelay(15);
                            mutex_unlock(&td->mutex_a);
                        }
                        mutex_unlock(&td->mutex_c);
                    }
                    mutex_unlock(&td->mutex_b);
                }
                break;
                
            case 2: // C -> A -> B
                if (mutex_trylock(&td->mutex_c)) {
                    msleep(1);
                    if (mutex_trylock(&td->mutex_a)) {
                        msleep(1);
                        if (mutex_trylock(&td->mutex_b)) {
                            got_all_locks = true;
                            td->shared_resource1 += 3;
                            td->shared_resource2 += 1;
                            td->shared_resource3 += 2;
                            udelay(15);
                            mutex_unlock(&td->mutex_b);
                        }
                        mutex_unlock(&td->mutex_a);
                    }
                    mutex_unlock(&td->mutex_c);
                }
                break;
        }
        
        if (got_all_locks) {
            ctx->local_operations++;
        } else {
            ctx->local_deadlocks++;
            td->deadlock_count++;
        }
        
        ctx->local_wait_time += get_cycles() - wait_start;
        
        if (iteration % 50 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Deadlock ABC worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Livelock scenario: Threads keep retrying and yielding to each other
 */
static int livelock_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct deadlock_test_data *td = ctx->test_data;
    int iteration;
    unsigned long retry_count;
    
    pr_info("Livelock worker %d starting\n", ctx->thread_id);
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        retry_count = 0;
        
        // Livelock: Keep trying to get both locks, but politely yield when failing
        while (retry_count < 100 && !kthread_should_stop()) {
            if (mutex_trylock(&td->mutex_a)) {
                if (mutex_trylock(&td->mutex_b)) {
                    // Success! Do work
                    td->shared_resource1++;
                    ctx->local_operations++;
                    udelay(5);
                    mutex_unlock(&td->mutex_b);
                    mutex_unlock(&td->mutex_a);
                    break;
                } else {
                    // Failed to get mutex_b, be "polite" and release mutex_a
                    mutex_unlock(&td->mutex_a);
                    
                    // Yield to let other thread proceed (causes livelock)
                    yield();
                    retry_count++;
                }
            } else {
                // Failed to get mutex_a, yield and retry
                yield();
                retry_count++;
            }
        }
        
        if (retry_count >= 100) {
            // Livelock detected
            td->livelock_count++;
        }
        
        if (iteration % 50 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Livelock worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Priority inversion scenario
 */
static int priority_inversion_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct deadlock_test_data *td = ctx->test_data;
    int iteration;
    unsigned long start_time;
    struct sched_param param;
    
    // Set thread priority based on context
    param.sched_priority = ctx->priority;
    if (ctx->priority > 0) {
        sched_setscheduler(current, SCHED_FIFO, &param);
        pr_info("Priority inversion worker %d starting (RT priority %d)\n", 
                ctx->thread_id, ctx->priority);
    } else {
        sched_setscheduler(current, SCHED_NORMAL, &param);
        pr_info("Priority inversion worker %d starting (normal priority)\n", ctx->thread_id);
    }
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        start_time = get_cycles();
        
        if (ctx->priority > 0) {
            // High priority thread
            td->high_prio_start_time = get_cycles();
            
            mutex_lock(&td->mutex_a);
            
            // Record how long high priority thread waited
            td->high_prio_wait_time += get_cycles() - td->high_prio_start_time;
            
            // High priority work (should be quick)
            td->shared_resource1 = ctx->thread_id;
            udelay(1);
            ctx->local_operations++;
            
            mutex_unlock(&td->mutex_a);
        } else {
            // Low priority thread
            mutex_lock(&td->mutex_a);
            
            td->low_prio_hold_time = get_cycles();
            
            // Low priority work (deliberately slow to cause inversion)
            td->shared_resource2 = ctx->thread_id;
            msleep(2); // Long work that blocks high priority
            
            td->low_prio_hold_time = get_cycles() - td->low_prio_hold_time;
            ctx->local_operations++;
            
            mutex_unlock(&td->mutex_a);
        }
        
        ctx->local_wait_time += get_cycles() - start_time;
        
        if (iteration % 20 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Priority inversion worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Reader-writer fairness test
 */
static int reader_writer_worker(void *data)
{
    struct thread_context *ctx = (struct thread_context *)data;
    struct deadlock_test_data *td = ctx->test_data;
    int iteration;
    bool is_writer = (ctx->thread_id % 4 == 0); // 1 writer per 4 threads
    
    pr_info("Reader-writer worker %d starting (%s)\n", 
            ctx->thread_id, is_writer ? "writer" : "reader");
    
    atomic_inc(&td->active_threads);
    
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    for (iteration = 0; iteration < TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        if (is_writer) {
            // Writer
            write_lock(&td->rw_lock);
            
            // Writer work
            td->shared_resource1 = ctx->thread_id;
            td->shared_resource2 = iteration;
            udelay(10); // Writers take longer
            ctx->local_operations++;
            
            write_unlock(&td->rw_lock);
        } else {
            // Reader
            read_lock(&td->rw_lock);
            
            // Reader work
            volatile int val1 = td->shared_resource1;
            volatile int val2 = td->shared_resource2;
            udelay(1); // Readers are quick
            ctx->local_operations++;
            
            read_unlock(&td->rw_lock);
        }
        
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    atomic_dec(&td->active_threads);
    pr_info("Reader-writer worker %d completed\n", ctx->thread_id);
    
    return 0;
}

/*
 * Start deadlock test with specified scenario
 */
static int start_deadlock_test(enum test_scenario scenario, int num_threads)
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
    switch (scenario) {
        case SCENARIO_DEADLOCK_AB:
            worker_func = deadlock_ab_worker;
            break;
        case SCENARIO_DEADLOCK_ABC:
            worker_func = deadlock_abc_worker;
            break;
        case SCENARIO_LIVELOCK:
            worker_func = livelock_worker;
            break;
        case SCENARIO_PRIORITY_INVERSION:
            worker_func = priority_inversion_worker;
            break;
        case SCENARIO_READER_WRITER:
            worker_func = reader_writer_worker;
            break;
        default:
            pr_err("Unsupported scenario: %d\n", scenario);
            return -EINVAL;
    }
    
    contexts = kzalloc(num_threads * sizeof(struct thread_context), GFP_KERNEL);
    if (!contexts) {
        pr_err("Failed to allocate contexts\n");
        return -ENOMEM;
    }
    
    // Initialize test state
    test_data.deadlock_count = 0;
    test_data.livelock_count = 0;
    test_data.priority_inversion_count = 0;
    test_data.successful_operations = 0;
    atomic_set(&test_data.active_threads, 0);
    atomic_set(&test_data.start_flag, 0);
    atomic_set(&test_data.stop_flag, 0);
    test_data.test_running = true;
    
    pr_info("Starting deadlock test: %s with %d threads\n", 
            scenario_names[scenario], num_threads);
    
    // Create worker threads
    for (i = 0; i < num_threads; i++) {
        contexts[i].thread_id = i;
        contexts[i].test_data = &test_data;
        contexts[i].scenario = scenario;
        contexts[i].local_operations = 0;
        contexts[i].local_wait_time = 0;
        contexts[i].local_deadlocks = 0;
        
        // Set priority for priority inversion test
        if (scenario == SCENARIO_PRIORITY_INVERSION) {
            contexts[i].priority = (i == 0) ? 50 : 0; // First thread high priority
        } else {
            contexts[i].priority = 0;
        }
        
        test_data.worker_threads[i] = kthread_create(worker_func, &contexts[i],
                                                    "deadlock_%d", i);
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
static void stop_deadlock_test(void)
{
    int i;
    
    if (!test_data.test_running)
        return;
    
    pr_info("Stopping deadlock test\n");
    
    atomic_set(&test_data.stop_flag, 1);
    
    for (i = 0; i < MAX_THREADS; i++) {
        if (test_data.worker_threads[i]) {
            kthread_stop(test_data.worker_threads[i]);
            test_data.worker_threads[i] = NULL;
        }
    }
    
    test_data.test_running = false;
    pr_info("Deadlock test stopped\n");
}

static int deadlock_demo_show(struct seq_file *m, void *v)
{
    seq_printf(m, "=== Deadlock, Livelock & Priority Inversion Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  Test Status: %s\n", test_data.test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Active Threads: %d\n", atomic_read(&test_data.active_threads));
    seq_printf(m, "  Shared Resource 1: %d\n", test_data.shared_resource1);
    seq_printf(m, "  Shared Resource 2: %d\n", test_data.shared_resource2);
    seq_printf(m, "  Shared Resource 3: %d\n\n", test_data.shared_resource3);
    
    seq_printf(m, "Test Statistics:\n");
    seq_printf(m, "  Deadlocks Detected: %lu\n", test_data.deadlock_count);
    seq_printf(m, "  Livelocks Detected: %lu\n", test_data.livelock_count);
    seq_printf(m, "  Priority Inversions: %lu\n", test_data.priority_inversion_count);
    seq_printf(m, "  Successful Operations: %lu\n\n", test_data.successful_operations);
    
    if (test_data.high_prio_wait_time > 0) {
        seq_printf(m, "Priority Inversion Analysis:\n");
        seq_printf(m, "  High Priority Wait Time: %lu cycles\n", test_data.high_prio_wait_time);
        seq_printf(m, "  Low Priority Hold Time: %lu cycles\n", test_data.low_prio_hold_time);
        seq_printf(m, "  Inversion Ratio: %.2fx\n\n", 
                  test_data.low_prio_hold_time > 0 ? 
                      (double)test_data.high_prio_wait_time / test_data.low_prio_hold_time : 0.0);
    }
    
    seq_printf(m, "Available Scenarios:\n");
    for (int i = 0; i < ARRAY_SIZE(scenario_names); i++) {
        seq_printf(m, "  %d: %s\n", i, scenario_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start <scenario> <threads>' > /proc/%s\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Monitor with 'echo t > /proc/sysrq-trigger' for stack traces\n");
    seq_printf(m, "  - Use 'cat /proc/lockdep_stats' for lock statistics\n");
    seq_printf(m, "  - Check 'dmesg' for deadlock detection messages\n");
    seq_printf(m, "  - Use 'perf record -g' to profile lock contention\n");
    
    return 0;
}

static int deadlock_demo_open(struct inode *inode, struct file *file)
{
    return single_open(file, deadlock_demo_show, NULL);
}

static ssize_t deadlock_demo_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[32];
    int scenario, num_threads;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (sscanf(cmd, "start %d %d", &scenario, &num_threads) == 2) {
        if (scenario >= 0 && scenario < ARRAY_SIZE(scenario_names)) {
            int ret = start_deadlock_test(scenario, num_threads);
            if (ret)
                return ret;
            pr_info("Started deadlock test: %s\n", scenario_names[scenario]);
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_deadlock_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops deadlock_demo_proc_ops = {
    .proc_open = deadlock_demo_open,
    .proc_read = seq_read,
    .proc_write = deadlock_demo_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init deadlock_demo_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &deadlock_demo_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    // Initialize locks
    mutex_init(&test_data.mutex_a);
    mutex_init(&test_data.mutex_b);
    mutex_init(&test_data.mutex_c);
    spin_lock_init(&test_data.spin_a);
    spin_lock_init(&test_data.spin_b);
    rwlock_init(&test_data.rw_lock);
    sema_init(&test_data.sem_a, 1);
    sema_init(&test_data.sem_b, 1);
    
    // Initialize test data
    memset(&test_data.worker_threads, 0, sizeof(test_data.worker_threads));
    init_completion(&test_data.test_completion);
    
    pr_info("Deadlock demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit deadlock_demo_exit(void)
{
    stop_deadlock_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("Deadlock demo module unloaded\n");
}

module_init(deadlock_demo_init);
module_exit(deadlock_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Deadlock, livelock, and priority inversion demonstration");
MODULE_VERSION("1.0");