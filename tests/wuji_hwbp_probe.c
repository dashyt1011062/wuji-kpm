// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile uint64_t g_sink;

/*
 * The current KPM handler uses break-and-skip semantics for user execute
 * breakpoints: it records the hit and advances PC by one arm64 instruction.
 * Keep the first instruction as a semantic no-op so this probe can continue
 * normally after each breakpoint hit.
 */
__attribute__((naked, noinline, aligned(4))) static void hwbp_probe_target(void)
{
    __asm__ __volatile__(
        "nop\n"
        "ret\n");
}

int main(void)
{
    int i;
    int wait_count;
    const char *go_path = "/data/local/tmp/wuji_hwbp_go";

    setbuf(stdout, NULL);
    unlink(go_path);
    printf("pid=%d target=%p\n", getpid(), (void *)hwbp_probe_target);
    printf("ready\n");
    printf("go_path=%s\n", go_path);

    for (wait_count = 0; wait_count < 300 && access(go_path, F_OK) != 0; ++wait_count) {
        usleep(100000);
    }

    printf("go\n");

    for (i = 0; i < 8; ++i) {
        hwbp_probe_target();
        g_sink += (uint64_t)i + 1;
        printf("tick=%d sink=%llu\n", i, (unsigned long long)g_sink);
        usleep(200000);
    }

    sleep(2);
    return 0;
}
