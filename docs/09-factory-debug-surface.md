# Sony factory debug surface (XBR-65X850D)

Everything below is from the shipping image (2020-03-04 build). All of it is world-readable /
world-executable, and several pieces run as **root** via init property triggers.

## `/system/vendor/bin` — factory tool chest

| tool | notes |
|---|---|
| `cli_shell` | opens `/dev/cli`, sends framed commands (`ioctl`) |
| `ttyman_shell` | same device; usage `ttyman_shell [_CTRL_I\|_CTRL_A] "cmd"`; daemon prints `TTY_MNGR>` |
| `debugshcmd` | `fork` + `execvp`, scripts under `/3rd_rw/tombstone/bugreport/shell/`, "Command Timeout" |
| `b2bcmd` | 96 KB B2B factory tool: EEPROM read/write, `filewrite_prepare`, `fwwrite_prepare`, `fileread_prepare`, `export/import`, `decrypt_phrase` (RSA) |
| `debugsettings` | `-d <dir>`, reads `<dir>/<name>`, sets `persist.svp.dbg.*` / `persist.sys.svp.dbg.*` |
| `dtdumpstate` | `-p A\|-p B`, writes `/tmp/odm/dtbugreport`, runs `/3rd/sony/arib/bin/logdump` (absent on this model) |
| `eepserver`, `dumpecsserver`, `MtkRmServer`, `telepathydaemon`, `gatord`, `modprobe` | root daemons/tools |
| `switch_fbm`, `hdmi_cec_test`, `mhl_test`, `tvinputhal_test` | hardware test tools |

## `/dev/cli` — MTK CLI device (char 241: mtal, cli, cb, gpio)

`/dev/cli` -> `/linux_rootfs/dev/cli`. `/system/bin/cli` and `/system/bin/ttyman` are the
daemons that own it. **`ttyman` provides an interactive root console** (`TTY_MNGR>`), and
`<Ctrl-I>` switches to `mw_cli`/`drv_cli`.

Access from our domains:
* adb shell (`u:r:shell`): open denied
* our uid-0 app (`u:r:untrusted_app`): open denied ("Cannot open /dev/cli")
* **`/dev/kmem2` (char 244, group drmrpc) *is* openable from `u:r:zygote:s0`** but `read()`
  fails and `mmap()` faults on access (secure/DRM memory).

## Property-triggered root services (the real surface)

From `/vendor/etc/init/*.rc`. None of these specify `user`, so they run as **root**:

```
on property:sys.svp.b2bcmd.state=eeprom_read        -> b2bcmd eeprom_read
on property:sys.svp.b2bcmd.state=fwwrite_prepare    -> b2bcmd fwwrite_prepare
on property:sys.svp.b2bcmd.state=filewrite_prepare  -> b2bcmd filewrite_prepare
on property:sys.svp.b2bcmd.state=fileread_prepare   -> b2bcmd fileread_prepare
on property:sys.svp.b2bcmd.state=export_start       -> b2bcmd export_start
on property:sys.svp.b2bcmd.state=import_start       -> b2bcmd import_start
on property:sys.svp.b2bcmd.state=decrypt_phrase     -> b2bcmd decrypt_phrase
on property:sys.svp.dbg.dtdumpstate.a=*             -> dtdumpstate -p A
on property:sys.svp.dbg.dtdumpstate.b=*             -> dtdumpstate -p B
on property:sys.svp.dbg.3rd.settings=*              -> debugsettings -d /storage/
on property:sys.svp.reverseproxy.enable=1|0         -> nginx -c /vendor/etc/nginxconf/nginx.conf
on property:persist.svp.dbg.irq_debug=1 (at boot)   -> /system/bin/sh /odm/etc/service/setup_irq_debug.sh
on property:sys.boot_completed=1                    -> /system/bin/sh /odm/etc/service/bind_watchdog.sh
```

`debugsettings -d /storage/` is the most interesting: `/storage/` is writable by us, and the
service runs as root.

## Storage layout

```
/dev/block/mmcblk0p15 on /3rd_rw  ext4 rw       (writable)
/dev/block/dm-1        on /3rd     squashfs ro  (read-only, /*/hdr/)
tmpfs                  on /3rd_rw/tombstone/tmp
mkdir /3rd_rw/tombstone 777 root root           (from dtbugreport.rc)
```

`/3rd_rw/tombstone` (and `/3rd_rw/tombstone/bugreport/shell/`, where `debugshcmd` execs from)
is 777 but **SELinux denies** shell and `untrusted_app`; the zygote domain is the candidate.

## What blocks us today

| attempt | result |
|---|---|
| `setprop sys.svp.b2bcmd.state ...` from uid-0 app | **denied**: `avc: denied { write } ... property_socket` by `u:r:untrusted_app:s0` |
| `setprop` from adb shell | denied (shell whitelist) |
| open `/dev/cli` from shell / untrusted_app | Permission denied |
| write `/3rd_rw/tombstone` | Permission denied (DAC 777, so SELinux) |
| `mknod` (/dev/mem) from shell | EPERM |
| `/proc/self/pagemap` | app domain: EPERM; shell: no output |

So the remaining question is whether **`u:r:zygote:s0`** is allowed to set `sys.svp.*`
properties (or open `/dev/cli` / write `/3rd_rw/tombstone`). A zygote payload that execs
`/system/bin/setprop` was built and armed; the result was inconclusive because the trigger
(`am start`) hung, which is itself expected: the payload hijacks the forked system-app child,
so the app being started never runs.

## Re-arm note

The zygote payload hooks `setresuid`. It is installed by the page-cache primitive; the clean
console-only payload is restored after each experiment. `setresuid` is patched at libc
`0x4a990` -> payload at libc `0x25a90`.

---

## Measured: every reachable domain is denied (zygote test, safe methodology)

The zygote domain was tested **without touching the TV's own apps**: the payload was keyed to
uid 10014 only (our console app), forking so the app still gets uid 0, while every other uid
(including 1000 / system apps) falls through to the real `setresuid`. This was the mistake in
the earlier run, which hijacked system-app launches and froze the UI.

Payload result from `u:r:zygote:s0`, uid 0:

```
ctx=u:r:zygote:s0 uid=0
  write /3rd_rw/tombstone/.zw            -> -13  EACCES
  open  /dev/cli                         -> -13  EACCES
  write /data/local/tmp/zw               -> -13  EACCES
  open  /3rd_rw/tombstone/bugreport/shell-> -13  EACCES
  SystemProperties.set(sys.svp.bugreport.output) -> InvocationTargetException (denied)
  SystemProperties.get(...)              -> empty
```

So the complete privesc chain is **closed at the second step**:

1. write a script into `/3rd_rw/tombstone/bugreport/shell/`  — **denied in every domain we can
   reach** (shell, untrusted_app, zygote)
2. `setprop sys.svp.bugreport.output=...` -> `dumpstatedt3` runs `dumpstate -t 1` as **root**
   and executes that script — **property write denied in every domain we can reach**
3. root script could then write `/sys/fs/selinux/enforce` -> permissive -> real root

Same story for `/dev/cli` (the `ttyman` root console) and for `sys.svp.b2bcmd.state`
(b2bcmd EEPROM/file write): both need a property write or a device open that none of our three
domains is allowed.

### Access matrix (measured, not inferred)

| target | shell `u:r:shell` | uid-0 app `u:r:untrusted_app` | `u:r:zygote` |
|---|---|---|---|
| `setprop sys.svp.*` | denied | denied (`avc: property_socket`) | denied |
| `/dev/cli` open | denied | denied | **EACCES** |
| write `/3rd_rw/tombstone` | denied | denied | **EACCES** |
| write `/data/local/tmp` | allowed | denied | **EACCES** |
| `mknod` | EPERM | — | — |
| `init_module` | EPERM | — | EPERM (`avc: capability sys_module`) |
| `/dev/kmem2` | denied | denied | **opens**, but read fails / mmap faults |
| `/proc/self/pagemap` | no data | EPERM | — |

Conclusion: the factory debug surface is real and does contain root execution paths, but every
one of them requires SELinux permission that the three domains reachable from a sideloaded app
do not have. Remaining route is the GPU/Mali one (docs/07).

---

## Attempted: patch /system/bin/sh in the page cache (round 6) — partial success, then broke sh

What worked, verified on the device:

```
[*] primitive ready (event gpu_va=0x102000000)
[*] patching /system/bin/sh page cache (2 regions)
  /system/bin/sh @0x18 : alias_ok=1 file_ok=1        <-- e_entry write SUCCEEDED
```

So the page-cache write primitive **does work on `/system/bin/sh`**, not just on `libc.so` — the
e_entry word was written and verified read-back (`file_ok=1`). That is the important new fact:
`sh` is patchable.

What went wrong (two mistakes, both mine):

1. **Wrong order.** I patched `e_entry` (0x2680 -> 0x2c900) *before* writing the stub into the
   cave. The program then hung on the second `pc_patch` call, so the cave still contained zeros
   while the entry already pointed at it: every new `sh` jumped into zeroed memory and crashed
   (`Segmentation fault`). Correct order is **stub first (it is dead data, always safe), verify
   it, and only then move e_entry.**
2. **Cave choice was outside the loadable image.** The cave at file offset 0x2c900 is past the RX
   segment's `filesz` (0x2c8c8); the primitive's mremap trick hangs on that page. The injection
   site must be **inside** a loadable segment, so the next attempt needs an unused/padding region
   within `[0, 0x2c8c8)`, or a different file.

Recovery: `adb reboot` — it works without `sh` (adbd handles it), the page cache is dropped, and
`sh` is byte-identical to stock again (verified: `e_entry = 0x2680`, `sh -c 'echo SH_OK'` works).

### Lessons for the next attempt

* Order: write the stub, read it back, only then patch `e_entry`; patch `e_entry` last and
  self-test immediately after.
* Injection site must be inside a PT_LOAD segment whose pages the primitive can already touch
  (`pc_patch` demonstrably handles `libc.so` and works for the `sh` file offset 0x18).
* `pc_patch()` returns 0 on success — my first generated main had the test inverted (`!pc_patch`),
  which silently turned failures into "success".
* Recovery without `sh`: `adb reboot` is the only reachable lever, because adb shell, am, pm-based
  launch paths and the root console all go through `/system/bin/sh`.
