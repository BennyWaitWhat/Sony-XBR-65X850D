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
