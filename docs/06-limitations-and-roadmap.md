# 06 · Limitations & roadmap

## The wall: SELinux

The result documented in this repository is **Android framework-level root**. It is
`uid 0`, which is genuinely powerful:

* `ActivityManagerService.checkComponentPermission()` returns `GRANTED` for uid 0 →
  `settings`, `pm`, `cmd`, `am`, permission grants, installs, force-stops all work.
* `uid 0` also has **full capabilities** (the zygote child inherits init's cap set, because
  `capset()` is not part of the drop we neutralised).

…but the process still runs in **`u:r:untrusted_app:s0`**, so the *LSM* filters the
filesystem and the network stack regardless of the uid:

| Operation | Result |
|---|---|
| `settings put global …`, `pm grant`, `pm install` | ✅ |
| `/sdcard` read/write | ✅ |
| `/data/local/tmp` write | ❌ `shell_data_file` |
| read `/system/bin/logd`, `vold`, `installd`, `netd` | ❌ file-type based denial |
| `setenforce 0` | ❌ not permitted |
| `/dev/block/*`, remount `/system` | ❌ |

Because the patch lives only in the page cache, there is also nothing on disk to escalate
*from* after a reboot — which is precisely why the persistence design re-applies it rather
than trying to install something durable.

## Roadmap: kernel-level root

The remaining blocker is not uid, it is the policy. The only path that removes it entirely
is **kernel memory corruption → `selinux_state.enforcing = 0`**.

### CVE-2022-20186 — `kbase_mem_alias` integer overflow

Confirmed present on this exact device. `KBASE_IOCTL_MEM_ALIAS` multiplies `nents` by
`stride` in 64-bit arithmetic without a sufficient overflow check:

```
stride = 0x8000000000000001, nents = 2
  correct  : 2 * 0x8000000000000001  = 0x10000000000000002
  observed : va_pages = 2            ← the product wrapped
```

The kernel then sizes allocations from the wrapped value while still walking the full
`nents` list, giving an out-of-bounds write in the GPU region bookkeeping.

### Sketch of the next phase

1. Turn the `mem_alias` overflow into a controlled kernel heap write.
2. Aim at the GPU region/page-table structures to obtain a **page-table overlap**, i.e. a
   GPU VA that maps pages we can also reach through a CPU mapping (the classic kbase
   primitive).
3. With an overlap: read/write arbitrary physical pages → locate `init_task` /
   `selinux_state` → clear `enforcing` → SELinux becomes permissive system-wide.
4. At that point the existing app regains full filesystem access, `/system` can be
   remounted, and durable persistence (init script, service, or patched system app) becomes
   possible.

This is a substantial piece of kernel exploitation work (KASLR, no symbols, 32-bit ARM,
old 3.10 kernel) and is explicitly **not** part of what is verified here.

## Secondary improvements worth doing

* **Console hardening** — token auth exists, but bind to a VPN interface only, add rate
  limiting, and rotate the token. A root shell on a LAN is a liability.
* **`capset` patch** — neutralising `capset` as well as `setresuid` would preserve the
  app's inherited capabilities; untested in combination with the targeted approach.
* **Watchdog** — if `ConsoleService` dies, a periodic job could re-start it (currently
  `START_STICKY` only).
* **Recovery documentation** — a one-page "how to remove this and verify the TV is stock"
  guide (uninstall + reboot + `od` on `libc.so`).

## Safety notes

* Everything here is **page-cache only**; a reboot restores the device to stock.
* The only on-disk change is the installed APK — removable with `adb uninstall`.
* The untargeted `setresuid` patch *did* destabilise the TV once (soft reboot, brief loss of
  network). The targeted version has been stable across multiple clean reboots. If you
  adapt this, keep the targeting.
