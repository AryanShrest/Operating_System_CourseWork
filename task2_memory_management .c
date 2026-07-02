/* =====================================================================
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * ===================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* =====================================================================
 * SECTION 0: TERMINAL UI HELPERS 
 * ===================================================================== */
#define UI_WIDTH 66

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

static void ui_spinner(const char *label, int cycles) {
    const char frames[4] = {'|', '/', '-', '\\'};
    for (int i = 0; i < cycles; i++) {
        printf("\r  %s  %c ", label, frames[i % 4]);
        fflush(stdout);
        usleep(60000);
    }
    printf("\r  %s  done.      \n", label);
}

static void ui_press_enter(void) {
    printf("\n  Press ENTER to return to the main menu...");
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

static int ui_ask_int(const char *prompt, int min, int max, int def) {
    char line[64];
    printf("  %s [default %d, range %d-%d]: ", prompt, def, min, max);
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return def;
    if (line[0] == '\n') return def;
    int val = atoi(line);
    if (val < min || val > max) {
        printf("  (out of range, using default %d)\n", def);
        return def;
    }
    return val;
}

/* =====================================================================
 * SECTION 1: THE FRAME -- physical memory representation
 *
 * Physical RAM is an array of these structs. page_id == -1 means the
 * frame is empty. `data[]` is a small simulated content buffer (not
 * real memory) purely so the frame's contents can be shown visually:
 * page 0 fills with 'A', page 1 with 'B', and so on.
 * ===================================================================== */
#define DATA_BYTES 4   /* simulated bytes of "content" per frame, for display only */

typedef struct {
    int  page_id;            /* which page is loaded here, -1 = empty */
    int  loaded_at;           /* tick this page was brought in (FIFO)  */
    int  last_used;           /* tick of most recent access (LRU)      */
    char data[DATA_BYTES];    /* simulated page content, for display   */
} Frame;

static void load_page(Frame *f, int page_id, int tick) {
    f->page_id   = page_id;
    f->loaded_at = tick;
    f->last_used = tick;
    char letter = (char)('A' + (page_id % 26));
    for (int b = 0; b < DATA_BYTES; b++) f->data[b] = letter;
}

static void frames_init(Frame *frames, int n) {
    for (int i = 0; i < n; i++) {
        frames[i].page_id   = -1;
        frames[i].loaded_at = 0;
        frames[i].last_used = 0;
        memset(frames[i].data, 0, DATA_BYTES);
    }
}

/* Prints frame contents as visual boxes, e.g.
 * [P0: A A A A]  [P1: B B B B]  [ -- ]  [ -- ]                       */
static void print_frame_boxes(Frame *frames, int n) {
    printf("  ");
    for (int i = 0; i < n; i++) {
        if (frames[i].page_id == -1) {
            printf("[ -- ]  ");
        } else {
            printf("[P%d:", frames[i].page_id);
            for (int b = 0; b < DATA_BYTES; b++) printf(" %c", frames[i].data[b]);
            printf("]  ");
        }
    }
    printf("\n");
}

/* =====================================================================
 * SECTION 2: SIMULATION CONFIGURATION & REFERENCE STRING GENERATOR
 *
 * "Configurable page size" is modelled by splitting a fixed 64 KB
 * virtual address space into pages of the chosen size; a stream of
 * virtual addresses is generated with a locality-of-reference bias
 * (mostly revisits a small "working set" of hot pages, occasionally
 * jumps to a fresh one) and translated into page numbers, exactly the
 * way a real MMU would extract a page number from an address.
 * ===================================================================== */
#define VIRTUAL_MEM_SIZE  65536
#define MAX_FRAMES        10
#define MAX_REF_LEN       60
#define MAX_PAGES         64

static int g_page_size  = 4096;
static int g_num_pages  = VIRTUAL_MEM_SIZE / 4096;
static int g_num_frames = 4;
static int g_ref_len    = 20;

static int g_addresses[MAX_REF_LEN];
static int g_pages[MAX_REF_LEN];

static void generate_reference_string(void) {
    int working_set_size = g_num_frames + 2;
    if (working_set_size > g_num_pages) working_set_size = g_num_pages;

    int working_set[MAX_PAGES];
    for (int i = 0; i < working_set_size; i++)
        working_set[i] = rand() % g_num_pages;

    for (int i = 0; i < g_ref_len; i++) {
        int page;
        if (i > 0 && (rand() % 100) < 75) {
            page = working_set[rand() % working_set_size];  /* revisit: -> HIT later */
        } else {
            page = rand() % g_num_pages;                    /* fresh page            */
            working_set[rand() % working_set_size] = page;
        }
        int offset = rand() % g_page_size;
        g_pages[i] = page;
        g_addresses[i] = page * g_page_size + offset;
    }
}

/* =====================================================================
 * SECTION 3: STATS
 * ===================================================================== */
typedef struct {
    int hits;
    int faults;
} Stats;

static void print_stats_table(const char *label, Stats s) {
    double total = (double)(s.hits + s.faults);
    double hit_ratio = total > 0 ? (s.hits / total) * 100.0 : 0.0;
    double fault_ratio = total > 0 ? (s.faults / total) * 100.0 : 0.0;
    char hit_str[16], fault_str[16];
    snprintf(hit_str, sizeof(hit_str), "%.1f%%", hit_ratio);
    snprintf(fault_str, sizeof(fault_str), "%.1f%%", fault_ratio);

    ui_hline('-');
    printf("| %-24s | %-14s | %-19s |\n", "Metric", label, "");
    ui_hline('-');
    printf("| %-24s | %-14d |%-20s|\n", "Total references", (int)total, "");
    printf("| %-24s | %-14d |%-20s|\n", "Page hits", s.hits, "");
    printf("| %-24s | %-14d |%-20s|\n", "Page faults", s.faults, "");
    printf("| %-24s | %-14s |%-20s|\n", "Hit ratio", hit_str, "");
    printf("| %-24s | %-14s |%-20s|\n", "Miss (fault) ratio", fault_str, "");
    ui_hline('-');
}

static void print_config(void) {
    ui_section("Current configuration");
    printf("  Virtual address space : %d bytes\n", VIRTUAL_MEM_SIZE);
    printf("  Page size              : %d bytes\n", g_page_size);
    printf("  Number of pages        : %d  (address space / page size)\n", g_num_pages);
    printf("  Physical frames        : %d\n", g_num_frames);
    printf("  Reference string length: %d\n", g_ref_len);
}

/* =====================================================================
 * SECTION 4: FIFO PAGE REPLACEMENT
 *
 * Evicts the frame with the smallest loaded_at (the page sitting in
 * RAM the longest), regardless of whether it was used recently. This
 * ignorance of recency is exactly what makes FIFO vulnerable to
 * Belady's Anomaly, and why it under-performs on reference strings
 * with temporal locality (see documentation section 6 and 9).
 * ===================================================================== */
static Stats run_fifo(int num_frames, int *pages, int *addrs, int ref_len, int verbose) {
    Frame frames[MAX_FRAMES];
    frames_init(frames, num_frames);
    Stats stats = {0, 0};
    int tick = 0;

    if (verbose) {
        ui_section("FIFO -- step-by-step frame log");
        ui_hline('-');
        printf("| %-4s | %-6s | %-5s |", "Step", "VAddr", "Page");
        for (int f = 0; f < num_frames; f++) printf(" F%-2d |", f);
        printf(" %-6s | %-7s |\n", "Result", "Evicted");
        ui_hline('-');
    }

    for (int i = 0; i < ref_len; i++) {
        int page = pages[i];
        tick++;
        int found = -1;
        for (int f = 0; f < num_frames; f++)
            if (frames[f].page_id == page) { found = f; break; }

        int evicted = -1;
        const char *result;
        if (found != -1) {
            stats.hits++;
            result = "HIT";
        } else {
            stats.faults++;
            result = "FAULT";
            /* find an empty frame first, else the one loaded earliest */
            int target = -1;
            for (int f = 0; f < num_frames; f++)
                if (frames[f].page_id == -1) { target = f; break; }
            if (target == -1) {
                target = 0;
                for (int f = 1; f < num_frames; f++)
                    if (frames[f].loaded_at < frames[target].loaded_at) target = f;
                evicted = frames[target].page_id;
            }
            load_page(&frames[target], page, tick);
        }

        if (verbose) {
            printf("| %-4d | %-6d | %-5d |", i + 1, addrs[i], page);
            for (int f = 0; f < num_frames; f++) {
                if (frames[f].page_id == -1) printf("  .  |");
                else printf(" %-3d |", frames[f].page_id);
            }
            if (evicted != -1) printf(" %-6s | %-7d |\n", result, evicted);
            else printf(" %-6s | %-7s |\n", result, "-");
        }
    }
    if (verbose) {
        ui_hline('-');
        printf("  Final frame contents:\n");
        print_frame_boxes(frames, num_frames);
    }
    return stats;
}

/* =====================================================================
 * SECTION 5: LRU PAGE REPLACEMENT
 *
 * Evicts the frame with the smallest last_used (the page that has gone
 * the longest without being touched). Every HIT refreshes last_used
 * for that frame, which is exactly what protects recently-used pages
 * from eviction -- the property FIFO lacks. LRU is a "stack algorithm"
 * and is provably immune to Belady's Anomaly.
 * ===================================================================== */
static Stats run_lru(int num_frames, int *pages, int *addrs, int ref_len, int verbose) {
    Frame frames[MAX_FRAMES];
    frames_init(frames, num_frames);
    for (int i = 0; i < num_frames; i++) frames[i].last_used = -1;
    Stats stats = {0, 0};
    int tick = 0;

    if (verbose) {
        ui_section("LRU -- step-by-step frame log");
        ui_hline('-');
        printf("| %-4s | %-6s | %-5s |", "Step", "VAddr", "Page");
        for (int f = 0; f < num_frames; f++) printf(" F%-2d |", f);
        printf(" %-6s | %-7s |\n", "Result", "Evicted");
        ui_hline('-');
    }

    for (int i = 0; i < ref_len; i++) {
        int page = pages[i];
        int found = -1;
        for (int f = 0; f < num_frames; f++)
            if (frames[f].page_id == page) { found = f; break; }

        int evicted = -1;
        const char *result;
        if (found != -1) {
            stats.hits++;
            result = "HIT";
            frames[found].last_used = tick;   /* refresh recency on hit */
        } else {
            stats.faults++;
            result = "FAULT";
            int target = -1;
            for (int f = 0; f < num_frames; f++)
                if (frames[f].page_id == -1) { target = f; break; }
            if (target == -1) {
                target = 0;
                for (int f = 1; f < num_frames; f++)
                    if (frames[f].last_used < frames[target].last_used) target = f;
                evicted = frames[target].page_id;
            }
            load_page(&frames[target], page, tick);
        }
        tick++;

        if (verbose) {
            printf("| %-4d | %-6d | %-5d |", i + 1, addrs[i], page);
            for (int f = 0; f < num_frames; f++) {
                if (frames[f].page_id == -1) printf("  .  |");
                else printf(" %-3d |", frames[f].page_id);
            }
            if (evicted != -1) printf(" %-6s | %-7d |\n", result, evicted);
            else printf(" %-6s | %-7s |\n", result, "-");
        }
    }
    if (verbose) {
        ui_hline('-');
        printf("  Final frame contents:\n");
        print_frame_boxes(frames, num_frames);
    }
    return stats;
}

/* =====================================================================
 * SECTION 6: MENU ACTIONS
 * ===================================================================== */
static void configure_simulation(void) {
    ui_banner("CONFIGURE SIMULATION");
    print_config();
    printf("\n");

    g_page_size = ui_ask_int("Page size in bytes (must divide 65536)",
                              256, 16384, g_page_size);
    while (VIRTUAL_MEM_SIZE % g_page_size != 0) g_page_size /= 2;
    g_num_pages = VIRTUAL_MEM_SIZE / g_page_size;
    if (g_num_pages > MAX_PAGES) g_num_pages = MAX_PAGES;

    g_num_frames = ui_ask_int("Number of physical frames", 2, MAX_FRAMES, g_num_frames);
    g_ref_len = ui_ask_int("Reference string length", 5, MAX_REF_LEN, g_ref_len);

    printf("\n");
    print_config();
    printf("\n  Configuration saved.\n");
}

static void show_reference_string(void) {
    ui_section("Generated reference string (Virtual Address -> Page)");
    for (int i = 0; i < g_ref_len; i++)
        printf("  [%2d] addr=%-6d -> page %-3d\n", i + 1, g_addresses[i], g_pages[i]);
}

static void run_fifo_demo(void) {
    ui_banner("FIFO PAGE REPLACEMENT");
    print_config();
    ui_spinner("Generating reference string", 8);
    generate_reference_string();
    show_reference_string();

    Stats s = run_fifo(g_num_frames, g_pages, g_addresses, g_ref_len, 1);
    ui_section("FIFO summary");
    print_stats_table("FIFO", s);
}

static void run_lru_demo(void) {
    ui_banner("LRU PAGE REPLACEMENT");
    print_config();
    ui_spinner("Generating reference string", 8);
    generate_reference_string();
    show_reference_string();

    Stats s = run_lru(g_num_frames, g_pages, g_addresses, g_ref_len, 1);
    ui_section("LRU summary");
    print_stats_table("LRU", s);
}

static void print_comparison_table(Stats fifo, Stats lru) {
    double fifo_hit = fifo.hits + fifo.faults > 0
        ? (100.0 * fifo.hits) / (fifo.hits + fifo.faults) : 0.0;
    double lru_hit = lru.hits + lru.faults > 0
        ? (100.0 * lru.hits) / (lru.hits + lru.faults) : 0.0;
    char fifo_hit_str[16], lru_hit_str[16];
    snprintf(fifo_hit_str, sizeof(fifo_hit_str), "%.1f%%", fifo_hit);
    snprintf(lru_hit_str, sizeof(lru_hit_str), "%.1f%%", lru_hit);

    ui_section("Side-by-side results");
    ui_hline('-');
    printf("| %-22s | %-18s | %-18s |\n", "Metric", "FIFO", "LRU");
    ui_hline('-');
    printf("| %-22s | %-18d | %-18d |\n", "Page faults", fifo.faults, lru.faults);
    printf("| %-22s | %-18d | %-18d |\n", "Page hits", fifo.hits, lru.hits);
    printf("| %-22s | %-18s | %-18s |\n", "Hit ratio", fifo_hit_str, lru_hit_str);
    ui_hline('-');

    ui_section("Verdict");
    if (lru.faults < fifo.faults)
        printf("  LRU produced fewer page faults than FIFO (temporal locality: pages\n"
               "  used recently are protected from eviction; FIFO ignores recency).\n");
    else if (fifo.faults < lru.faults)
        printf("  FIFO produced fewer page faults than LRU on this run -- this can\n"
               "  happen on specific reference patterns, but LRU is generally the\n"
               "  stronger heuristic because it tracks actual usage recency.\n");
    else
        printf("  Both algorithms produced the same number of page faults here.\n");
}

static void run_comparison(void) {
    ui_banner("FIFO vs LRU COMPARISON");
    print_config();
    ui_spinner("Generating shared reference string", 8);
    generate_reference_string();  /* same string for both -> fair test */
    show_reference_string();

    Stats fifo = run_fifo(g_num_frames, g_pages, g_addresses, g_ref_len, 1);
    Stats lru  = run_lru(g_num_frames, g_pages, g_addresses, g_ref_len, 1);
    print_comparison_table(fifo, lru);
}

static void run_all(void) {
    configure_simulation();
    run_comparison();
}

/* Reproduces the exact worked example from task2_documentation.md so the
 * report's numbers and the program's numbers match one-to-one:
 * reference string P0 P1 P2 P3 P0 P1 P4 P0 P1 P2 P3 P4, 4 frames.
 * Expected: FIFO 2 hits / 10 faults (16.7%); LRU 4 hits / 8 faults (33.3%). */
static void run_classic_demo(void) {
    ui_banner("CLASSIC DEMONSTRATION (matches documentation example)");
    int classic_pages[12] = {0, 1, 2, 3, 0, 1, 4, 0, 1, 2, 3, 4};
    int classic_addrs[12];
    for (int i = 0; i < 12; i++) classic_addrs[i] = classic_pages[i]; /* addr == page id here */
    int frames = 4;

    printf("  Reference string: P0 P1 P2 P3 P0 P1 P4 P0 P1 P2 P3 P4\n");
    printf("  Physical frames : %d\n", frames);

    Stats fifo = run_fifo(frames, classic_pages, classic_addrs, 12, 1);
    Stats lru  = run_lru(frames, classic_pages, classic_addrs, 12, 1);
    print_comparison_table(fifo, lru);

    ui_section("Cross-check against documentation");
    printf("  Documentation claims: FIFO 2 hits/10 faults (16.7%%), LRU 4 hits/8\n");
    printf("  faults (33.3%%). Program measured: FIFO %d hits/%d faults, LRU %d\n",
           fifo.hits, fifo.faults, lru.hits);
    printf("  hits/%d faults -- %s\n", lru.faults,
           (fifo.hits == 2 && fifo.faults == 10 && lru.hits == 4 && lru.faults == 8)
               ? "MATCH." : "MISMATCH (check reference string / frame count).");
}

/* =====================================================================
 * SECTION 7: MAIN MENU
 * ===================================================================== */
static void print_main_menu(void) {
    ui_clear();
    ui_hline('=');
    const char *title = "ST5004CEM  -  TASK 2: MEMORY MANAGEMENT SIMULATOR";
    int len = (int)strlen(title);
    int pad_left = (UI_WIDTH - len) / 2, pad_right = UI_WIDTH - len - pad_left;
    printf("|");
    for (int i = 0; i < pad_left; i++) putchar(' ');
    printf("%s", title);
    for (int i = 0; i < pad_right; i++) putchar(' ');
    printf("|\n");
    ui_hline('=');
    printf("|                                                                    |\n");
    printf("|   [1] Configure Simulation   (page size, frames, ref. length)      |\n");
    printf("|   [2] Run FIFO Page Replacement                                    |\n");
    printf("|   [3] Run LRU Page Replacement                                     |\n");
    printf("|   [4] Compare FIFO vs LRU    (same reference string)               |\n");
    printf("|   [5] Run ALL (configure + compare)                                |\n");
    printf("|   [6] Classic demonstration  (matches documentation example)       |\n");
    printf("|   [0] Exit                                                         |\n");
    printf("|                                                                    |\n");
    ui_hline('=');
    print_config();
    printf("\n  Select an option: ");
    fflush(stdout);
}

int main(void) {
    srand((unsigned int)time(NULL));
    int choice = -1;
    char line[16];

    while (choice != 0) {
        print_main_menu();
        if (!fgets(line, sizeof(line), stdin)) break;
        choice = atoi(line);

        ui_clear();
        switch (choice) {
            case 1: configure_simulation(); ui_press_enter(); break;
            case 2: run_fifo_demo();        ui_press_enter(); break;
            case 3: run_lru_demo();         ui_press_enter(); break;
            case 4: run_comparison();       ui_press_enter(); break;
            case 5: run_all();              ui_press_enter(); break;
            case 6: run_classic_demo();     ui_press_enter(); break;
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
