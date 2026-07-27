# wuji-kpm

First-stage WuJi KPM experiment for SukiSU-Ultra / KPatch-Next.

This version only implements a small hardware execution breakpoint manager:

- resolve `register_user_hw_breakpoint`, `unregister_hw_breakpoint`, and pid/task helpers lazily at runtime
- install one or more user execute breakpoints by pid and address
- count hits in the KPM overflow handler
- uninstall one handle or all handles
- report status through KPM `ctl0`

It is not ABI-compatible with `wuji-kernel` yet. Existing binaries that speak the old `/proc/<key>/<key>` + `struct ioctl_request` protocol still need a compatibility layer.

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
/data/adb/ksud kpm control wuji-hwbp install <pid> <hex_addr> [len]
/data/adb/ksud kpm control wuji-hwbp uninstall <handle>
/data/adb/ksud kpm control wuji-hwbp clear
```

`len` defaults to `4`, which is the normal arm64 instruction size. A handle is returned by `install` and is the kernel `struct perf_event *` value.

SukiSU's `ksud kpm control` currently prints only the integer return code. Use `dmesg | grep wuji-hwbp` to read status/install messages.
