/* =====================================================================
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * Single-file build (all modules combined; sections marked below)
 *
 * Contents:
 *   SECTION 0 - Terminal UI helpers (ASCII boxes, tables, animations)
 *   SECTION A - Producer-Consumer          (mutex + semaphore)
 *   SECTION B - Race Condition demo        (unsafe vs mutex-protected)
 *   SECTION C - Deadlock Prevention demo   (strict lock ordering)
 *   SECTION D - Gantt-Chart Scheduler      (round-robin simulation)
 *   SECTION E - Live Thread Scheduler      (round-robin, condition var)
 *   SECTION F - Main menu
 * ===================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

/* =====================================================================
 * SECTION 0: TERMINAL UI HELPERS
 * ===================================================================== */
#define UI_WIDTH 60

static void ui_clear(void) {
    printf("\033[H\033[J");
    fflush(stdout);
}

static void ui_hline(char ch) {
    putchar('+');
    for (int i = 0; i < UI_WIDTH; i++) putchar(ch);
    putchar('+');
    putchar('\n');
}

/* Boxed banner, e.g.
 * +------------------------------------------------------------+
 * |                  PRODUCER - CONSUMER DEMO                  |
 * +------------------------------------------------------------+
 */
static void ui_banner(const char *title) {
    ui_hline('=');
    int len = (int)strlen(title);
    int pad_left = (UI_WIDTH - len) / 2;
    int pad_right = UI_WIDTH - len - pad_left;
    printf("|");
    for (int i = 0; i < pad_left; i++) putchar(' ');
    printf("%s", title);
    for (int i = 0; i < pad_right; i++) putchar(' ');
    printf("|\n");
    ui_hline('=');
}

static void ui_section(const char *title) {
    printf("\n-- %s ", title);
    int len = (int)strlen(title);
    for (int i = 0; i < UI_WIDTH - len - 4; i++) putchar('-');
    printf("\n");
}

/* Simple spinner animation used before a demo starts working */
static void ui_spinner(const char *label, int cycles) {
    const char frames[4] = {'|', '/', '-', '\\'};
    for (int i = 0; i < cycles; i++) {
        printf("\r  %s  %c ", label, frames[i % 4]);
        fflush(stdout);
        usleep(70000);
    }
    printf("\r  %s  done.      \n", label);
}

/* Determinate progress bar, e.g. [#############-----] 65% */
static void ui_progress(const char *label, int steps, int delay_us) {
    int width = 30;
    for (int i = 0; i <= steps; i++) {
        int filled = width * i / steps;
        printf("\r  %-22s [", label);
        for (int j = 0; j < width; j++) putchar(j < filled ? '#' : '-');
        printf("] %3d%%", i * 100 / steps);
        fflush(stdout);
        usleep(delay_us);
    }
    printf("\n");
}

static void ui_press_enter(void) {
    printf("\n  Press ENTER to return to the main menu...");
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

/* =====================================================================
 * SECTION A: PRODUCER-CONSUMER (mutex + semaphore synchronization)
 *
 * Two producers and two consumers share a fixed-size circular buffer.
 * A mutex protects the buffer itself (the critical section), and two
 * counting semaphores (sem_empty / sem_full) block producers when the
 * buffer is full and consumers when it is empty -- the classic bounded
 * buffer solution.
 * ===================================================================== */
#define BUFFER_SIZE   5
#define NUM_ITEMS     8   /* items each producer will produce */

static int buffer[BUFFER_SIZE];
static int buf_count = 0;
static int in_index  = 0;
static int out_index = 0;

static pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
static sem_t sem_empty;
static sem_t sem_full;

static void *producer(void *arg) {
    long id = (long)arg;
    for (int i = 1; i <= NUM_ITEMS; i++) {
        int item = (int)(id * 100 + i);

        sem_wait(&sem_empty);
        pthread_mutex_lock(&buffer_mutex);

        buffer[in_index] = item;
        in_index = (in_index + 1) % BUFFER_SIZE;
        buf_count++;
        printf("  | Producer %ld -> produced item %-4d | buffer count = %d/%d\n",
               id, item, buf_count, BUFFER_SIZE);

        pthread_mutex_unlock(&buffer_mutex);
        sem_post(&sem_full);

        usleep(10000);
    }
    return NULL;
}

static void *consumer(void *arg) {
    long id = (long)arg;
    for (int i = 1; i <= NUM_ITEMS; i++) {
        sem_wait(&sem_full);
        pthread_mutex_lock(&buffer_mutex);

        int item = buffer[out_index];
        out_index = (out_index + 1) % BUFFER_SIZE;
        buf_count--;
        printf("  |     Consumer %ld -> consumed item %-4d | buffer count = %d/%d\n",
               id, item, buf_count, BUFFER_SIZE);

        pthread_mutex_unlock(&buffer_mutex);
        sem_post(&sem_empty);

        usleep(14000);
    }
    return NULL;
}

static void run_producer_consumer(void) {
    ui_banner("PRODUCER - CONSUMER DEMO");
    printf("  Synchronization: pthread_mutex_t (buffer) + sem_t x2 (slots)\n");
    printf("  Threads: 2 producers, 2 consumers | buffer size = %d\n", BUFFER_SIZE);
    ui_spinner("Initializing semaphores", 8);

    buf_count = 0; in_index = 0; out_index = 0;
    sem_init(&sem_empty, 0, BUFFER_SIZE);
    sem_init(&sem_full, 0, 0);

    ui_section("Live activity log");
    pthread_t producers[2], consumers[2];
    for (long i = 0; i < 2; i++)
        pthread_create(&producers[i], NULL, producer, (void *)(i + 1));
    for (long i = 0; i < 2; i++)
        pthread_create(&consumers[i], NULL, consumer, (void *)(i + 1));

    for (int i = 0; i < 2; i++) pthread_join(producers[i], NULL);
    for (int i = 0; i < 2; i++) pthread_join(consumers[i], NULL);

    sem_destroy(&sem_empty);
    sem_destroy(&sem_full);

    ui_section("Result");
    printf("  All %d items produced and consumed with zero buffer overrun/underrun.\n",
           2 * NUM_ITEMS);
}

/* =====================================================================
 * SECTION B: RACE CONDITION DEMONSTRATION
 *
 * Runs the same "increment N times per thread" workload twice: once on
 * a plain long with no locking (unsafe_counter) and once through a
 * mutex-protected critical section (safe_counter). `counter++` is not
 * atomic -- it decomposes into a read, an add, and a write -- so two
 * threads can interleave those steps and lose updates. The result is
 * non-deterministic, which is the whole point of the demonstration.
 * ===================================================================== */
#define INCREMENTS_PER_THREAD 200000
#define RACE_THREAD_COUNT     4

static long unsafe_counter = 0;
static long safe_counter   = 0;
static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *increment_unsafe(void *arg) {
    (void)arg;
    for (int i = 0; i < INCREMENTS_PER_THREAD; i++) unsafe_counter++;
    return NULL;
}

static void *increment_safe(void *arg) {
    (void)arg;
    for (int i = 0; i < INCREMENTS_PER_THREAD; i++) {
        pthread_mutex_lock(&counter_mutex);
        safe_counter++;
        pthread_mutex_unlock(&counter_mutex);
    }
    return NULL;
}

static void run_race_condition(void) {
    ui_banner("RACE CONDITION DEMONSTRATION");
    printf("  %d threads x %d increments each, with and without a mutex.\n",
           RACE_THREAD_COUNT, INCREMENTS_PER_THREAD);

    unsafe_counter = 0;
    safe_counter = 0;
    pthread_t unsafe_threads[RACE_THREAD_COUNT], safe_threads[RACE_THREAD_COUNT];

    ui_progress("Running unsynchronized run", 20, 15000);
    for (long i = 0; i < RACE_THREAD_COUNT; i++)
        pthread_create(&unsafe_threads[i], NULL, increment_unsafe, NULL);
    for (int i = 0; i < RACE_THREAD_COUNT; i++)
        pthread_join(unsafe_threads[i], NULL);

    ui_progress("Running mutex-protected run", 20, 15000);
    for (long i = 0; i < RACE_THREAD_COUNT; i++)
        pthread_create(&safe_threads[i], NULL, increment_safe, NULL);
    for (int i = 0; i < RACE_THREAD_COUNT; i++)
        pthread_join(safe_threads[i], NULL);

    long expected = (long)RACE_THREAD_COUNT * INCREMENTS_PER_THREAD;

    ui_section("Results");
    ui_hline('-');
    printf("| %-20s | %-15s | %-16s |\n", "Counter", "Final Value", "Status");
    ui_hline('-');
    printf("| %-20s | %-15ld | %-16s |\n", "Expected", expected, "-");
    printf("| %-20s | %-15ld | %-16s |\n", "Unsafe (no mutex)", unsafe_counter,
           (unsafe_counter != expected) ? "LOST UPDATES" : "no loss this run");
    printf("| %-20s | %-15ld | %-16s |\n", "Safe (mutex)", safe_counter,
           (safe_counter == expected) ? "CORRECT" : "UNEXPECTED");
    ui_hline('-');
    printf("  Note: lost updates from the unsafe run are not guaranteed to appear\n");
    printf("  on every execution -- that is the nature of a race condition.\n");
}

/* =====================================================================
 * SECTION C: DEADLOCK PREVENTION DEMONSTRATION (strict lock ordering)
 *
 * Three threads all need exclusive access to two shared resources
 * (Resource A and Resource B). Classic deadlock occurs when threads
 * acquire locks in different orders (A-then-B vs B-then-A), creating a
 * circular wait. This demo PREVENTS that by having every thread lock
 * strictly in the same global order: A, then B. With a fixed order,
 * circular wait -- one of the four Coffman conditions required for
 * deadlock -- can never form.
 * ===================================================================== */
static pthread_mutex_t resource_A = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resource_B = PTHREAD_MUTEX_INITIALIZER;

static void *deadlock_safe_worker(void *arg) {
    long id = (long)arg;

    pthread_mutex_lock(&resource_A);
    printf("  | Thread %ld locked   Resource A\n", id);
    usleep(5000); /* widen the window; deadlock still cannot occur */

    pthread_mutex_lock(&resource_B);
    printf("  | Thread %ld locked   Resource B\n", id);

    printf("  | Thread %ld using both resources safely...\n", id);
    usleep(5000);

    pthread_mutex_unlock(&resource_B);
    pthread_mutex_unlock(&resource_A);
    printf("  | Thread %ld released both resources\n", id);

    return NULL;
}

static void run_deadlock_demo(void) {
    ui_banner("DEADLOCK PREVENTION DEMO");
    printf("  Strategy: every thread locks Resource A THEN Resource B (fixed\n");
    printf("  global order) so the circular-wait condition can never form.\n");
    ui_spinner("Spawning 3 competing threads", 10);

    ui_section("Live activity log");
    pthread_t dl_threads[3];
    for (long i = 0; i < 3; i++)
        pthread_create(&dl_threads[i], NULL, deadlock_safe_worker, (void *)(i + 1));
    for (int i = 0; i < 3; i++)
        pthread_join(dl_threads[i], NULL);

    ui_section("Result");
    printf("  All 3 threads completed. No deadlock occurred.\n");
}

/* =====================================================================
 * SECTION D: GANTT-CHART SCHEDULER (round-robin simulation)
 *
 * Classic textbook round-robin CPU scheduling simulation: given a fixed
 * time quantum, work out the order and timing in which 4 processes with
 * different burst times would be scheduled, then report waiting and
 * turnaround time statistics. This is a *simulation* of scheduling
 * decisions (no OS threads are actually created here) -- it complements
 * Section E, which performs real turn-taking between live threads
 * using a condition variable.
 * ===================================================================== */
typedef struct {
    int pid;
    int burst_time;
    int remaining_time;
    int waiting_time;
    int turnaround_time;
} Process;

#define TIME_QUANTUM 4

static void run_gantt_scheduler(void) {
    ui_banner("GANTT-CHART SCHEDULER SIMULATION");
    printf("  Time quantum = %d\n", TIME_QUANTUM);

    Process procs[] = {
        {1, 10, 10, 0, 0},
        {2, 5,  5,  0, 0},
        {3, 8,  8,  0, 0},
        {4, 3,  3,  0, 0},
    };
    int n = (int)(sizeof(procs) / sizeof(procs[0]));

    ui_spinner("Loading process table", 8);

    ui_section("Process table (arrival)");
    ui_hline('-');
    printf("| %-6s | %-10s |\n", "PID", "Burst Time");
    ui_hline('-');
    for (int i = 0; i < n; i++)
        printf("| P%-5d | %-10d |\n", procs[i].pid, procs[i].burst_time);
    ui_hline('-');

    ui_section("Gantt chart");
    printf("  |");
    int time = 0, done = 0;
    while (done < n) {
        int idle = 1;
        for (int i = 0; i < n; i++) {
            if (procs[i].remaining_time > 0) {
                idle = 0;
                int slice = (procs[i].remaining_time < TIME_QUANTUM)
                                ? procs[i].remaining_time
                                : TIME_QUANTUM;
                printf(" P%d(%d-%d) |", procs[i].pid, time, time + slice);
                fflush(stdout);
                usleep(120000); /* animate the chart being drawn */

                time += slice;
                procs[i].remaining_time -= slice;

                if (procs[i].remaining_time == 0) {
                    procs[i].turnaround_time = time;
                    procs[i].waiting_time =
                        procs[i].turnaround_time - procs[i].burst_time;
                    done++;
                }
            }
        }
        if (idle) break;
    }
    printf("\n");

    ui_section("Waiting / turnaround times");
    ui_hline('-');
    printf("| %-6s | %-10s | %-9s | %-11s |\n", "PID", "Burst", "Waiting", "Turnaround");
    ui_hline('-');
    int total_wait = 0, total_turn = 0;
    for (int i = 0; i < n; i++) {
        printf("| P%-5d | %-10d | %-9d | %-11d |\n", procs[i].pid,
               procs[i].burst_time, procs[i].waiting_time, procs[i].turnaround_time);
        total_wait += procs[i].waiting_time;
        total_turn += procs[i].turnaround_time;
    }
    ui_hline('-');
    printf("  Average waiting time    : %.2f\n", (double)total_wait / n);
    printf("  Average turnaround time : %.2f\n", (double)total_turn / n);
}

/* =====================================================================
 * SECTION E: LIVE ROUND-ROBIN THREAD SCHEDULER (condition variable)
 *
 * A LIVE round-robin scheduler for real threads (not a simulation).
 * Three threads each run 3 rounds. `current_turn` says whose round it
 * is; a thread whose turn it isn't goes to sleep on a condition
 * variable instead of busy-waiting (spinning), which would burn CPU
 * for no reason.
 *
 * Deadlock prevention: this section uses two locks -- scheduler_mutex
 * (protects current_turn) and counter_mutex (protects shared_counter).
 * They are (a) always acquired in the same global order when both are
 * needed (scheduler_mutex first) and (b) never held at the same time --
 * scheduler_mutex is released before counter_mutex is acquired. Both
 * properties independently rule out circular wait, so deadlock cannot
 * occur here.
 * ===================================================================== */
#define RR_NUM_THREADS 3
#define RR_ROUNDS      3
#define RR_TIME_SLICE_US 300000  /* simulated "work" per round, shortened for demo */

/* A thread in C receives exactly one void* argument, so a struct is
 * used to pass richer data (here just an ID, but easily extended with
 * a priority, a work queue, a timeout, etc. without touching the rest
 * of the code). */
typedef struct {
    int thread_id;
} ThreadArgs;

static int rr_shared_counter = 0;
static int rr_current_turn   = 0;

static pthread_mutex_t rr_counter_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rr_scheduler_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  rr_turn_cond       = PTHREAD_COND_INITIALIZER;

static void *rr_thread_task(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    int id = args->thread_id;

    for (int round = 1; round <= RR_ROUNDS; round++) {
        /* --- wait for our turn (sleep, don't spin) --- */
        pthread_mutex_lock(&rr_scheduler_mutex);
        while (rr_current_turn != id) {
            /* pthread_cond_wait atomically releases rr_scheduler_mutex
             * and sleeps; on wakeup it re-acquires the mutex before
             * returning. The loop (not "if") guards against spurious
             * wakeups, which POSIX explicitly permits. */
            pthread_cond_wait(&rr_turn_cond, &rr_scheduler_mutex);
        }
        pthread_mutex_unlock(&rr_scheduler_mutex);

        /* --- it is now this thread's turn: do the round of work --- */
        printf("  | Thread %d | Round %d -- working...\n", id, round);
        usleep(RR_TIME_SLICE_US);

        /* --- update shared counter under its own lock --- */
        pthread_mutex_lock(&rr_counter_mutex);
        rr_shared_counter++;
        printf("  | Thread %d | Shared counter is now: %d\n", id, rr_shared_counter);
        pthread_mutex_unlock(&rr_counter_mutex);

        /* --- pass the turn to the next thread and wake everyone --- */
        pthread_mutex_lock(&rr_scheduler_mutex);
        rr_current_turn = (rr_current_turn + 1) % RR_NUM_THREADS;
        pthread_cond_broadcast(&rr_turn_cond); /* not _signal: wakes ALL
            waiters so the correct one (and only that one) proceeds;
            _signal could wake the wrong thread and stall the program */
        pthread_mutex_unlock(&rr_scheduler_mutex);
    }

    printf("  | Thread %d | Finished all work.\n", id);
    return NULL;
}

static void run_rr_thread_scheduler(void) {
    ui_banner("LIVE ROUND-ROBIN THREAD SCHEDULER");
    printf("  Threads: %d | Rounds each: %d | Turn-passing: condition variable\n",
           RR_NUM_THREADS, RR_ROUNDS);
    printf("  (Unlike the Gantt-chart demo, real threads take turns here.)\n");
    ui_spinner("Preparing thread arguments", 8);

    rr_shared_counter = 0;
    rr_current_turn = 0;

    pthread_t threads[RR_NUM_THREADS];
    ThreadArgs args[RR_NUM_THREADS];

    ui_section("Live activity log");
    for (int i = 0; i < RR_NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, rr_thread_task, &args[i]);
    }
    for (int i = 0; i < RR_NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    int expected = RR_NUM_THREADS * RR_ROUNDS;

    ui_section("Result");
    ui_hline('-');
    printf("| %-30s | %-23s |\n", "Metric", "Value");
    ui_hline('-');
    printf("| %-30s | %-23d |\n", "Final shared_counter value", rr_shared_counter);
    printf("| %-30s | %-23d |\n", "Expected (threads x rounds)", expected);
    printf("| %-30s | %-23s |\n", "Status",
           (rr_shared_counter == expected) ? "CORRECT - no lost updates" : "MISMATCH");
    ui_hline('-');
    printf("  The counter is exactly %d every run because counter_mutex fully\n",
           expected);
    printf("  serializes every increment -- no interleaving is possible.\n");
}

/* =====================================================================
 * SECTION F: MAIN MENU
 * ===================================================================== */
static void print_main_menu(void) {
    ui_clear();
    ui_hline('=');
    const char *title = "ST5004CEM  -  TASK 1: PROCESS & THREAD MANAGER";
    int len = (int)strlen(title);
    int pad_left = (UI_WIDTH - len) / 2, pad_right = UI_WIDTH - len - pad_left;
    printf("|");
    for (int i = 0; i < pad_left; i++) putchar(' ');
    printf("%s", title);
    for (int i = 0; i < pad_right; i++) putchar(' ');
    printf("|\n");
    ui_hline('=');
    printf("|                                                            |\n");
    printf("|   [1] Producer-Consumer Demo   (Mutex + Semaphore)         |\n");
    printf("|   [2] Race Condition Demo      (Unsafe vs Safe Counter)    |\n");
    printf("|   [3] Deadlock Prevention Demo (Ordered Locking)           |\n");
    printf("|   [4] Gantt-Chart Scheduler    (Round-Robin Simulation)    |\n");
    printf("|   [5] Live Thread Scheduler    (Round-Robin, Cond. Var.)   |\n");
    printf("|   [6] Run ALL demonstrations in sequence                   |\n");
    printf("|   [0] Exit                                                 |\n");
    printf("|                                                            |\n");
    ui_hline('=');
    printf("  Select an option: ");
    fflush(stdout);
}

static void run_all(void) {
    run_producer_consumer();
    run_race_condition();
    run_deadlock_demo();
    run_gantt_scheduler();
    run_rr_thread_scheduler();
}

int main(void) {
    int choice = -1;
    char line[16];

    while (choice != 0) {
        print_main_menu();
        if (!fgets(line, sizeof(line), stdin)) break;
        choice = atoi(line);

        ui_clear();
        switch (choice) {
            case 1: run_producer_consumer();   ui_press_enter(); break;
            case 2: run_race_condition();      ui_press_enter(); break;
            case 3: run_deadlock_demo();       ui_press_enter(); break;
            case 4: run_gantt_scheduler();     ui_press_enter(); break;
            case 5: run_rr_thread_scheduler(); ui_press_enter(); break;
            case 6: run_all();                 ui_press_enter(); break;
            case 0:
                ui_banner("GOODBYE");
                printf("  Program finished successfully.\n");
                break;
            default:
                printf("  Invalid choice. Please select a number from the menu.\n");
                ui_press_enter();
                break;
        }
    }
    return 0;
}
