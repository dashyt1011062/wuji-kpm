# wuji-kpm

First-stage WuJi KPM experiment for SukiSU-Ultra / KPatch-Next.

This version is a SukiSU-compatible hardware breakpoint probe:

- resolve `register_user_hw_breakpoint`, `unregister_hw_breakpoint`, and pid/task helpers lazily at runtime
- validate pid/address/symbol availability without registering a breakpoint
- queue hardware-breakpoint install/uninstall/clear work onto a short-lived kernel worker
- avoid calling perf hardware-breakpoint APIs directly from KPM `ctl0`
- count execute-breakpoint hits in the overflow handler with `sample_period=1`
- handle execute breakpoints with real user single-step/re-enable semantics
- expose a WuJi-compatible `/proc/<key>/<key>` binary request node for existing user programs
- report status through KPM `ctl0`

It now includes a first-pass compatibility layer for binaries that speak the old `/proc/<key>/<key>` + `struct ioctl_request` protocol. The compatibility node is:

```text
/proc/9c7e1a3b5d0f2c8e4a6b1d9f3e7c0a2b/9c7e1a3b5d0f2c8e4a6b1d9f3e7c0a2b
```

Implemented compatibility commands include open/close process, read/write process memory through direct physical page-table translation, read user instruction, install/uninstall execute or watchpoint hardware breakpoints, hit count/detail/detail-ex, clear hit ring, basic hit-session status, and AYCPU-oriented state snapshots for coordinate packets, direct HP objects, skill cooldowns, and buff timers. The AYCPU side reads `/proc/<pid>/maps` directly instead of asking the KPM to build a maps list.

Snapshot commands are built from the same hit ring as ordinary hit-detail reads. For coordinate packet mode, KPM reads the 12-byte packet pointed to by `x1` and also exposes it through `GET_HWBP_HIT_DETAIL_EX` aux fields. HP, skill, and buff snapshots derive their object pointers and raw values from the captured registers, then use the physical read path for small follow-up reads such as HP object actor, cooldown period, and buff coordinates.

The WuJi read/write commands no longer call or fall back to `access_process_vm()`. They resolve the target task's `mm`, read `mm->pgd` through KPatch's `mm_struct_offset`, translate the requested user virtual address to the currently mapped physical page, and copy through `memremap(MEMREMAP_WB)`. This means non-present/swapped pages fail instead of being faulted in, and writes modify the physical page currently referenced by the PTE rather than triggering normal COW/user fault behavior.

## Safety note

Do not call `register_user_hw_breakpoint()` or `unregister_hw_breakpoint()` synchronously from a KPM `ctl0` handler on the current SukiSU/KPatch loader. The loader calls `ctl0` while holding `rcu_read_lock()`, while perf hardware-breakpoint registration can call `synchronize_rcu()`. That combination can deadlock the `ksud` ioctl thread and trip the vendor hung-task watchdog.

This build therefore queues `install`, `uninstall`, and `clear` onto a one-shot worker thread. `ctl0` returns after the request is queued; use `status` and `dmesg | grep wuji-hwbp` to check completion.

Do not unload this KPM while a worker is busy or while any breakpoint slot is active. Run `clear`, wait until `status` shows `worker_busy=0`, `pending=0`, and no active slots, then unload if needed. The current SukiSU/KPatch unload path frees KPM text even if `exit` returns `-EBUSY`, so an unsafe unload cannot be reliably prevented inside the KPM.

Execute breakpoint hit handling uses a single-step/re-enable flow instead of `pc += 4`:

1. the perf overflow handler records the hit
2. the matched hardware breakpoint event is disabled with `perf_event_disable_inatomic()`
3. user single-step is enabled for the current task with `user_enable_single_step()`
4. a KPatch hook on `single_step_handler()` catches the next single-step exception
5. the hook disables user single-step, re-enables the original breakpoint with `perf_event_enable()`, then skips the kernel's original `single_step_handler()` return path so the target process does not receive an unwanted SIGTRAP

This means the trapped instruction is executed once and the breakpoint is armed again for the next execution.

## Build

Use KPatch-Next as `KP_DIR` and an `aarch64-none-elf-` bare-metal toolchain:

```sh
TARGET_COMPILE=/path/to/aarch64-none-elf- \
KP_DIR=/path/to/KPatch-Next \
make
```

The GitHub Actions workflow downloads the toolchain and checks out KPatch-Next automatically.

The Makefile forces `-fno-pic -fno-pie`; SukiSU/KPatch's KPM loader does not support GOT relocations such as `R_AARCH64_ADR_GOT_PAGE` / `R_AARCH64_LD64_GOT_LO12_NC`.

## Runtime control

After loading the KPM through SukiSU:

```sh
/data/adb/ksud kpm load /data/local/tmp/wuji-hwbp.kpm
/data/adb/ksud kpm list
/data/adb/ksud kpm info wuji-hwbp
/data/adb/ksud kpm control wuji-hwbp status
/data/adb/ksud kpm control wuji-hwbp 'prepare <pid> <hex_addr> [len]'
/data/adb/ksud kpm control wuji-hwbp 'install <pid> <hex_addr> [len]'
/data/adb/ksud kpm control wuji-hwbp uninstall <handle>
/data/adb/ksud kpm control wuji-hwbp clear
```

`len` defaults to `4`, which is the normal arm64 instruction size. `install`, `uninstall`, and `clear` return a queued message first; poll `status` for the final result.

SukiSU's `ksud kpm control` currently prints only the integer return code. Use `dmesg | grep wuji-hwbp` to read status/install messages.

## Local probe used for validation

`tests/wuji_hwbp_probe.c` contains a tiny Android user-mode probe. Its target function starts with `add x0, x0, #1; ret`, so successful output proves the trapped instruction executed. A break-and-skip implementation would skip the `add` and produce the wrong accumulated value.

Example device-side compile command used in this environment:

```sh
/data/data/com.termux/files/home/.codex/skills/android-ndk-local/scripts/compile-android-c.sh \
  /storage/emulated/0/work-pace/wuji-kpm/tests/wuji_hwbp_probe.c \
  /data/local/tmp/wuji_hwbp_probe
```

Observed successful validation on the current device:

- `install` registered slot 0 successfully through the async worker
- after triggering the probe, `status` reported `total_hits=8`, `unknown_hits=0`, `step_starts=8`, `step_completes=8`, `step_failures=0`
- the probe printed `tick=0` through `tick=7`; final `sink=36`, proving the trapped `add` executed each time
- the WuJi-compatible proc protocol was also validated with read/write self memory, read user instruction, synchronous install/uninstall, `hit_count`, and `hit_detail`; the same single-step probe produced `sink=36`
