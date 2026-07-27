# wuji-kpm

First-stage WuJi KPM experiment for SukiSU-Ultra / KPatch-Next.

This version is a SukiSU-compatible hardware breakpoint probe:

- resolve `register_user_hw_breakpoint`, `unregister_hw_breakpoint`, and pid/task helpers lazily at runtime
- validate pid/address/symbol availability without registering a breakpoint
- queue hardware-breakpoint install/uninstall/clear work onto a short-lived kernel worker
- avoid calling perf hardware-breakpoint APIs directly from KPM `ctl0`
- count execute-breakpoint hits in the overflow handler with `sample_period=1`
- report status through KPM `ctl0`

It is not ABI-compatible with `wuji-kernel` yet. Existing binaries that speak the old `/proc/<key>/<key>` + `struct ioctl_request` protocol still need a compatibility layer.

## Safety note

Do not call `register_user_hw_breakpoint()` or `unregister_hw_breakpoint()` synchronously from a KPM `ctl0` handler on the current SukiSU/KPatch loader. The loader calls `ctl0` while holding `rcu_read_lock()`, while perf hardware-breakpoint registration can call `synchronize_rcu()`. That combination can deadlock the `ksud` ioctl thread and trip the vendor hung-task watchdog.

This build therefore queues `install`, `uninstall`, and `clear` onto a one-shot worker thread. `ctl0` returns after the request is queued; use `status` and `dmesg | grep wuji-hwbp` to check completion.

Do not unload this KPM while a worker is busy or while any breakpoint slot is active. Run `clear`, wait until `status` shows `worker_busy=0`, `pending=0`, and no active slots, then unload if needed. The current SukiSU/KPatch unload path frees KPM text even if `exit` returns `-EBUSY`, so an unsafe unload cannot be reliably prevented inside the KPM.

Current hit handling is intentionally simple: execute breakpoints are handled as break-and-skip events. The handler records the hit and advances user PC by one arm64 instruction (`pc += 4`). Only place breakpoints on an instruction that is safe to skip, such as a deliberately inserted `nop`. Full debugger-style single-step/re-enable semantics are not implemented yet.

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

`tests/wuji_hwbp_probe.c` contains a tiny Android user-mode probe. Its target function starts with `nop; ret`, so the KPM's break-and-skip handler can skip the `nop` without corrupting program state.

Example device-side compile command used in this environment:

```sh
/data/data/com.termux/files/home/.codex/skills/android-ndk-local/scripts/compile-android-c.sh \
  /storage/emulated/0/work-pace/wuji-kpm/tests/wuji_hwbp_probe.c \
  /data/local/tmp/wuji_hwbp_probe
```

Observed successful validation on the current device:

- `install` registered slot 0 successfully through the async worker
- after triggering the probe, `status` reported `total_hits=8`, `unknown_hits=0`
- the probe printed `tick=0` through `tick=7` normally
