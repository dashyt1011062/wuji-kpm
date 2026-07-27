# wuji-kpm

First-stage WuJi KPM experiment for KPatch-Next.

This version only implements a small hardware execution breakpoint manager:

- resolve `register_user_hw_breakpoint` and `unregister_hw_breakpoint` through `kallsyms_lookup_name`
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

## Runtime control

After loading the KPM through KPatch-Next:

```sh
kpatch kpm load /data/local/tmp/wuji-hwbp.kpm
kpatch kpm ctl0 wuji-hwbp status
kpatch kpm ctl0 wuji-hwbp install <pid> <hex_addr> [len]
kpatch kpm ctl0 wuji-hwbp uninstall <handle>
kpatch kpm ctl0 wuji-hwbp clear
```

`len` defaults to `4`, which is the normal arm64 instruction size. A handle is returned by `install` and is the kernel `struct perf_event *` value.
