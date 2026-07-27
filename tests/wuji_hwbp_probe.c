// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile uint64_t g_sink;

/*
 * The first instruction is semantically meaningful.  A break-and-skip handler
 * would skip the add and return the original argument.  A real single-step
 * handler executes the add once, re-enables the breakpoint, then returns v + 1.
 */
__attribute__((naked, noinline, aligned(4))) static uint64_t hwbp_probe_target(uint64_t v)
{
    __asm__ __volatile__(
        "add x0, x0, #1\n"
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
        g_sink += hwbp_probe_target((uint64_t)i);
        printf("tick=%d sink=%llu\n", i, (unsigned long long)g_sink);
        usleep(200000);
    }

    sleep(2);
    return 0;
}
