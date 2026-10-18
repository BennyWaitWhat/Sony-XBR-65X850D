# 01 · Device & Recon

## The target

A 2016-era Sony Bravia that was later updated to Android 8 and then abandoned:

| Property | Value |
|---|---|
| Model / board | XBR-65X850D · **SVP-DTV15** |
| SoC | MediaTek **MT5890**, armv7 |
| Android | 8.0.0 · `OPR2.170623.027.S16` · build **6.827** |
| Kernel | **3.10.79** armv7l, built 2020-03-04 |
| SELinux | enforcing (`permissive=0` everywhere we looked) |
| SPL | **2020-01-01** |
| Props | `ro.secure=1`, `ro.debuggable=0`, `ro.boot.flash.locked=1` |
| Trust | dm-verity / locked bootloader |

The only interaction surface was **ADB over TCP**, which the user had enabled:
the shell lands as `uid 2000`, domain `u:r:shell:s0`, with groups including
`input`, `log`, `adb`, `sdcard`, `inet`.

## Attack surface actually reachable

Out of 647 entries in `/dev`, only eight were usable from `shell`:

```
/dev/mali0     (world rw, 10:51)  ← the GPU driver: this is the way in
/dev/ion
/dev/cli       (ioctl-only, no-op handler)
/dev/input
/dev/binder
null zero random urandom ptmx
```

Denied outright: `pvr`, `kmem2`, `gpio`, `eeprom_*`, `mtal`, `cb`, `fbm_*`, `ttyMT0`.

Readable binaries that mattered: `app_process`, `app_process32`, `dalvikvm`, `linker`,
`dex2oat`, `sh`, `toybox`, plus the big shared libraries (`libc`, `libart`, `libbinder`,
`libandroid_runtime`, …). **Not** readable: `logd`, `vold`, `installd`, `netd`,
`servicemanager`, `init`.

## Paths ruled out (with the reason)

These were all investigated and closed before attacking the GPU driver:

| Path | Why it failed |
|---|---|
| Firmware downgrade via USB | Packages are signed; the recovery only accepts Sony-signed updates |
| USB drive / WebApp installer | No path to code execution as a privileged uid |
| UART / opening the TV | Physically impossible for the user ("I cannot open the tv") |
| Android-7-era kernel CVEs (`binder`, `ION`, …) | SPL 2020-01 — long patched |
| ION `ION_IOC_CUSTOM` | `ENOTTY`: the `dmac_unmap_area` bug in Sony's published 3.10.27 sources is **not** in the shipping 3.10.79 kernel |
| `/dev/cli` | Ioctl-only, handler is a no-op |
| Enclave / vendor binder services | SELinux never-touch policy |
| GPU page-table crafting (Midgard PTEs) | r1p0 has **no immediate-value write** job; only Bifrost+ does |
| `/data/local/tmp` setuid binaries | `/data` is mounted `nosuid` |
| Killing/steering zygote from an app | `pidof` hidden (hidepid), `kill` blocked by SELinux, `setprop ctl.restart` denied |

The `nosuid` finding and the SELinux domain checks are what forced the design that
eventually worked: **modify code via the page cache**, then get a *privileged process*
to execute it.

## Permissions notes seen repeatedly

```
avc: denied { execute }  ... tcontext=u:object_r:shell_exec:s0  permissive=0
avc: denied { setexec }  scontext=u:r:zygote:s0                  permissive=0
avc: denied { search }   ... tcontext=u:object_r:shell_data_file:s0
avc: denied { write }    ... tcontext=u:object_r:system_data_file:s0
```

Everything interesting is gated by the LSM, not by uid — which is why the final artifact is
honest about being *framework* root. Next: **[02 · CVE-2022-22706](02-cve-2022-22706.md)**.
