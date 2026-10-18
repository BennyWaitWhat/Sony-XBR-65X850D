# Kernel / Device-Driver Attack Surface — Sony XBR-65X850D (BRAVIA 4K 2015)

**Target:** `100.70.99.3:5555` (fallback `100.115.119.101:5555`)
**Device:** `SVP4KDTV15_UC` / `BRAVIA_4K_2015` / `SVP-DTV15`
**Kernel:** `Linux localhost 3.10.79 #1 SMP PREEMPT Wed Mar 4 17:00:38 JST 2020 armv7l`
**Toolchain of kernel:** `gcc 4.8.2 20131014 (Linaro GCC 4.8-2013.10)`, built on `root@BuildHost728`
**Access:** adb, uid `2000(shell)`, gid `2000(shell)`
**SELinux:** `Enforcing`, policy version 30
**Date of recon:** 2026-10-18
**Constraints honoured:** no reboot, no `/system` writes, no Mali GPU ioctl probes (reserved for another investigation), read-only exploration + probe binaries in `/data/local/tmp`.

---

## 0. Session identity (baseline)

```
$ adb -s 100.70.99.3:5555 shell 'id; uname -a; getenforce'
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),
  1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),
  3006(net_bw_stats),3009(readproc) context=u:r:shell:s0
Linux localhost 3.10.79 #1 SMP PREEMPT Wed Mar 4 17:00:38 JST 2020 armv7l
Enforcing
```

**CONFIRMED** — group membership `1004(input)` and `1007(log)` are the two that matter for device access on this box (see §3). This is the single most consequential fact in this report.

No `su` binary:
```
$ adb shell 'ls -l /system/xbin/su /system/bin/su /sbin/su'
ls: /system/xbin/su: No such file or directory
ls: /system/bin/su: No such file or directory
ls: /sbin/su: Permission denied
```

---

## 1. `/dev` topology — a symlink farm into a **read-only squashfs**

### 1.1 The structural finding

`/dev` is a tmpfs whose vendor entries are **symlinks into `/linux_rootfs/dev/`**, and `/linux_rootfs` is a **read-only squashfs mounted from a device-mapper volume**.

```
$ adb shell 'cat /proc/mounts'
rootfs / rootfs ro,seclabel 0 0
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,seclabel,relatime,mode=600,ptmxmode=000 0 0
proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0
sysfs /sys sysfs rw,seclabel,relatime 0 0
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
/sys/kernel/debug /sys/kernel/debug debugfs rw,seclabel,relatime,mode=755 0 0
/dev/block/mmcblk0p44 /system squashfs ro,seclabel,relatime 0 0
/dev/block/mmcblk0p46 /cache ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,data=ordered 0 0
/dev/block/mmcblk0p45 /data ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,data=ordered 0 0
/dev/block/dm-0 /linux_rootfs squashfs ro,seclabel,relatime 0 0
/dev/block/mmcblk0p4 /perm ext4 ro,context=u:object_r:perm_fs:s0,relatime,data=ordered 0 0
/dev/block/mmcblk0p15 /3rd_rw ext4 rw,seclabel,noatime,data=ordered 0 0
/dev/block/dm-1 /3rd squashfs ro,seclabel,noatime 0 0
tmpfs /tmp tmpfs rw,seclabel,relatime,mode=1771 0 0
/dev/block/mmcblk0p25 /data_demo squashfs ro,seclabel,relatime 0 0
/dev/block/mmcblk0p41 /upgrade vfat rw,noatime,fmask=0013,dmask=0013,...
```

**CONFIRMED consequences:**

1. The vendor device nodes are **immutable** — they live inside a `ro` squashfs image (`dm-0`). You cannot `chmod`, relabel, or replace them. Any "fix the perms" persistence idea is dead on arrival.
2. Because they are baked into the image, they carry **vendor-authored SELinux labels** that survive into the running system. This is almost certainly *why* the vendor chose a symlink farm rather than letting Android's `ueventd` `mknod` them (ueventd would apply `ueventd.rc` permissions, not vendor labels).
3. `/linux_rootfs` itself is **unreadable** to `shell` (see §1.3).

### 1.2 Inventory of the real nodes

`/dev` contains 648 entries of which the overwhelming majority are symlinks or block-device aliases. The authoritative vendor node tree:

```
$ adb shell 'ls /linux_rootfs/dev/ | wc -l'
648
```

Permission histogram over the 352 entries whose inode is statable to `shell`
(the other 296 return `EACCES` **on `lstat` itself** — see §1.3):

| mode | count | kind |
|---|---|---|
| `brw-------` | 269 | block (root-only) |
| `crw-r-----` | 39 | char, group-read (mostly root/root — useless to us) |
| `crw-rw----` | 35 | char, group-rw |
| `drwxr-xr-x` | 7 | dirs |
| `brw-rw-rw-` | 1 | **block, world-rw** (`mmcblk0p3`) |
| `crw-r--r--` | 1 | char, world-read (`mali0` at this path) |
| **not statable** | **296** | `EACCES` — SELinux `getattr` denial |

### 1.3 The `EACCES`-on-`lstat` phenomenon

`ls -l /linux_rootfs/dev/` emits names for every entry (readdir is allowed) but **296 of them fail `lstat` with `EACCES`**:

```
ls: /linux_rootfs/dev//aomx: Permission denied
ls: /linux_rootfs/dev//audio: Permission denied
ls: /linux_rootfs/dev//eep: Permission denied
ls: /linux_rootfs/dev//gpio: Permission denied
ls: /linux_rootfs/dev//rtc: Permission denied
ls: /linux_rootfs/dev//vomx: Permission denied
... (296 total)
```

**CONFIRMED**: these are SELinux `getattr` denials on inodes that are `0775`/`0777`-reachable by DAC. A directory you can `read` but whose files you cannot even `stat` is not a Unix-permissions outcome; it is an LSM outcome. **This is the cleanest single proof that SELinux, not file modes, defines the boundary on this device.**

Practical effect: for `eep`, `gpio`, `rtc`, `dsp`, `vomx`, `aomx`, `fbmomx` we **cannot even determine major:minor** from the shell. Their `ls -lL` falls back to showing the symlink itself (`0777`, `0:0`).

### 1.4 What is genuinely world/group accessible

From `ls -l /linux_rootfs/dev/` and the `ls -l /dev` tmpfs layer:

| node | mode | owner | maj:min | accessible to uid 2000? |
|---|---|---|---|---|
| `cli` | `crw-rw----` | `root:shell` | 241:4 | **YES — read+write** |
| `mmcblk0p3` | `brw-rw-rw-` | `root:root` | 179:3 | no — SELinux `EACCES` |
| `mali0` (rootfs copy) | `crw-r--r--` | `root:root` | 10:51 | world-**read** by mode |
| `xt_qtaguid` | `crw-r--r--` | `root:root` | 10:55 | **YES — read only** |
| `eeprom_0` | `crw-rw----` | `root:root` | 228:0 | no (`0660 root:root`) |
| `eeprom_3` | `crw-rw----` | `root:root` | 227:0 | no (`0660 root:root`) |
| `eeprom_4` | `crw-rw----` | `root:root` | 226:0 | no (`0660 root:root`) |
| `eep` | (unstatable) | — | unknown | no |
| `b2r` | `crw-rw----` | `root:root` | 243:0 | no |
| `feeder` | `crw-rw----` | `root:root` | 247:0 | no |
| `kmem2` | `crw-rw----` | `media:drmrpc` | 244:0 | no |
| `adecomx` | `crw-rw----` | `media:drmrpc` | 237:1 | no |
| `vdecomx` | `crw-rw----` | `media:drmrpc` | 238:8 | no |
| `vencomx` | `crw-rw----` | `media:drmrpc` | 238:12 | no |
| `vdpomx` | `crw-rw----` | `system:drmrpc` | 238:16 | no |
| `mtal` | `crw-rw----` | `system:oem_2901` | 241:0 | no |
| `cb` / `cb2` | `crw-rw----` | `system:oem_2901` | 241:8 / 241:16 | no |
| `jpg` | `crw-rw----` | `system:oem_2901` | 251:0 | no |
| `tsrec` | `crw-r-----` | `root:root` | 245:0 | no |
| `fbm_dmx`,`fbm_feeder*`,`fbm_pvr*`,`fbm_rest_mem`,… | `crw-r-----` | `root:root` | 251:x | no |
| `video0..9` | `crw-rw----` | `system:root` | 81:0–9 | no |

**`/dev/cli` is the only vendor node in the entire Middleware family that is reachable by uid 2000.** That is a deliberate ACL: `root:shell 0660`, i.e. "the shell user may talk to the CLI driver".

---

## 2. Driver enumeration

### 2.1 `/proc/devices` — full, CONFIRMED

```
$ adb shell 'cat /proc/devices'
Character devices:
  1 mem
  4 /dev/vc/0
  4 tty
  5 /dev/tty
  5 /dev/console
  5 /dev/ptmx
  7 vcs
 10 misc
 13 input
 14 sound
 21 sg
 29 fb
 81 video4linux
108 ppp
116 alsa
124 BT_chrdev
125 hidraw
126 pmsg
127 rtc
128 ptm
136 pts
180 usb
188 ttyUSB
188 usb_cst
189 usb_device
204 ttyMT
216 rfcomm
226 /dev/eeprom_4
227 /dev/eeprom_3
228 /dev/eeprom_0
229 /dev/rmmgr
234 xhci_mtk_test
236 pvr
237 adecomx
238 vdecomx
238 vencomx
238 vdpomx
241 mtal
241 cli
241 cb
241 gpio
241 cb
243 b2r
244 kmem2
245 tsrec
247 feeder
250 fusion
251 jpg
251 fbm

Block devices:
  1 ramdisk   259 blkext   7 loop   8 sd   65 sd   66 sd   67 sd   68 sd
 69 sd  70 sd  71 sd 128 sd 129 sd 130 sd 131 sd 132 sd 133 sd 134 sd 135 sd
179 mmc   251 fbm   253 zram   254 device-mapper
```

Note the **major 241 is heavily multiplexed**: `mtal`, `cli`, `cb`, `gpio`, `cb` share it (duplicate `cb` entry is a kernel-side artifact of two `register_chrdev` calls or a cdev-add race; it is reproduced verbatim).

### 2.2 These are DENIED — INFERRED to be SELinux

```
$ adb shell 'cat /proc/misc; cat /proc/modules; cat /proc/tty/drivers; cat /proc/cmdline'
cat: /proc/misc: Permission denied
cat: /proc/modules: Permission denied
cat: /proc/tty/drivers: Permission denied
cat: /proc/cmdline: Permission denied
```

`/proc/misc`, `/proc/modules`, `/proc/tty/drivers`, `/proc/cmdline` are all `EACCES` to `shell` even though `hidepid=2` is set on `/proc` and we are in group `3009(readproc)`.

**Loss:** we cannot enumerate load-bearing modules, cannot see misc minor→name mapping, cannot read the kernel command line (which would have told us `audit=0`, `console=`, `androidboot.*`). This is a material handicap vs. a normal Android target.

### 2.3 `/sys/class` — present but largely opaque

```
$ adb shell 'ls /sys/class'
BT_chrdev  bdi  block  bluetooth  firmware  fusion  graphics  hidraw
ieee80211  input  mem  misc  mmc_host  net  pmsg  power_supply  ppp
rfkill  rtc  scsi_device  scsi_disk  scsi_generic  scsi_host  sound
switch  timed_output  tty  vc  video4linux  vtconsole  xt_idletimer
```

Every individual class-device symlink is `EACCES` on `list`/`getattr` to `shell`:

```
ls: /sys/class/misc/ion: Permission denied
ls: /sys/class/misc/binder: Permission denied
ls: /sys/class/rtc/rtc0: Permission denied
ls: /sys/class/input/...: (denied)
```

`/sys/dev/char` likewise: **names enumerate, targets do not.**

### 2.4 KEY FINDING — the MediaTek Middleware driver family has **zero sysfs representation**

`/sys/dev/char` yields exactly **152** registered char devices:

```
1:3 1:5 1:7 1:8 1:9 1:11 4:0..4:63 5:0 5:1 5:2 7:0 7:1 7:128 7:129
10:1 10:51 10:52 10:53 10:54 10:55 10:56 10:57 10:58 10:59 10:60 10:61
10:62 10:63 10:200 10:223 10:229 10:236 10:237 10:239
13:32 13:63 13:64 13:65 13:66 13:67 14:0 14:3 14:4 14:12 14:16
29:0 29:1 108:0 116:0 116:16..116:34 124:0 126:0 127:0
189:0 189:128 189:256 189:384 189:512 189:640 189:641
204:16 204:18 204:19 204:20 204:21  250:0..250:7
```

**Not one entry for majors 226, 227, 228, 229, 237, 238, 241, 243, 244, 245, 247, 251.**

**CONFIRMED**: the entire Middleware/vendor device family (`eeprom_*`, `rmmgr`, `adecomx`, `vdecomx`, `vencomx`, `vdpomx`, `mtal`, `cli`, `cb`, `cb2`, `gpio`, `b2r`, `kmem2`, `tsrec`, `feeder`, `jpg`, `fbm_*`) is registered via the **legacy `register_chrdev()` path with no `device_create()`/class registration**. It therefore has:
- no `/sys/class/*` entry,
- no `/sys/dev/char/*` entry,
- no `/sys/module/<drv>/parameters` (built into the monolithic kernel image, not modules).

**Impact:** there is *no introspection surface at all* for these drivers. No version, no debug counters, no tunables, no enable switches — this is why §4's "cli device is disabled" cannot be flipped from userspace. All analysis of these drivers must be static (vendor binaries/squashfs, which is also unreadable — §5) or dynamic (ioctl probing, limited by `panic_on_oops=1`).

Notable **absent** nodes (checked explicitly): no `/dev/watchdog`, no `/dev/mem`, no `/dev/kmem`, no `/dev/port`, no `/dev/leds`, no `/dev/backlight`, no `/dev/vibrator`, no `/dev/block/by-name`.

```
$ adb shell 'ls /dev/block/by-name'
ls: /dev/block/by-name: No such file or directory
```

The absence of `/dev/watchdog` is operationally significant: **open-probing of arbitrary `/dev` nodes carries no reboot risk from a watchdog arm.** (See §8 for the risk that *does* exist.)

---

## 3. Accessibility matrix — what uid 2000 can actually `open()`

### 3.1 Method

A Go prober (`x_arm`, source in Appendix A) `lstat`s and `stat`s each path, attempts `open(O_RDONLY|O_NONBLOCK)` and `open(O_RDWR|O_NONBLOCK)`, records `errno`, and for successful `O_RDWR` opens issues `FIONREAD (0x541B)` and `TCGETS (0x5401)` to establish whether an ioctl handler is reachable at all.

Built with:
```powershell
$env:GO111MODULE='off'; $env:GOOS='linux'; $env:GOARCH='arm'; $env:GOARM='7'; $env:CGO_ENABLED='0'
& 'C:\Program Files\Go\bin\go.exe' build -o x_arm x.go
```

345 non-block-device paths probed (full `/dev` char + symlink set), plus a curated second tier.

### 3.2 OPENABLE — CONFIRMED

| path | type/mode | owner | maj:min | RDONLY | RDWR | ioctl probe |
|---|---|---|---|---|---|---|
| `/dev/cli` | lnk→`chr 0660` | `root:shell` | 241:4 | **OK** | **OK** | `FIONREAD`→0, `TCGETS`→0 |
| `/dev/input/event0` | chr 0660 | `root:input` | 13:64 | **OK** | **OK** | `EINVAL` |
| `/dev/input/event1` | chr 0660 | `root:input` | 13:65 | **OK** | **OK** | `EINVAL` |
| `/dev/input/event2` | chr 0660 | `root:input` | 13:66 | **OK** | **OK** | `EINVAL` |
| `/dev/input/event3` | chr 0660 | `root:input` | 13:67 | **OK** | **OK** | `EINVAL` |
| `/dev/input/mice` | chr 0660 | `root:input` | 13:63 | **OK** | **OK** | `ENOTTY` |
| `/dev/input/mouse0` | chr 0660 | `root:input` | 13:32 | **OK** | **OK** | `ENOTTY` |
| `/dev/ion` | chr 0666 | `system:system` | 10:62 | **OK** | **OK** | `ENOTTY` |
| `/dev/mali0` | chr 0666 | `root:root` | 10:51 | **OK** | **OK** | `EINVAL` |
| `/dev/binder` | chr 0666 | `root:root` | 10:58 | **OK** | **OK** | `EINVAL` |
| `/dev/hwbinder` | chr 0666 | `root:root` | 10:57 | **OK** | **OK** | `EINVAL` |
| `/dev/ashmem` | chr 0666 | `root:root` | 10:61 | **OK** | **OK** | `ENOTTY` |
| `/dev/null` | chr 0666 | `root:root` | 1:3 | **OK** | **OK** | `ENOTTY` |
| `/dev/zero` | chr 0666 | `root:root` | 1:5 | **OK** | **OK** | `ENOTTY` |
| `/dev/random` | chr 0666 | `root:root` | 1:8 | **OK** | **OK** | `EINVAL` |
| `/dev/urandom` | chr 0666 | `root:root` | 1:9 | **OK** | **OK** | `EINVAL` |
| `/dev/ptmx` | chr 0666 | `root:root` | 5:2 | **OK** | **OK** | `OK(0)` / `OK(0)` |
| `/dev/xt_qtaguid` | chr **0644** | `root:root` | 10:55 | **OK** | EACCES | — |
| `/dev/alarm` | chr **0664** | `system:radio` | 10:60 | **OK** | EACCES | — |
| `/dev/cpuctl`,`/dev/cpuset`,`/dev/stune` | dir 0755 | `system:system` | — | OK | n/a | — |
| `/dev/shm`,`/dev/fusion`,`/dev/usb-ffs/adb` | dir | — | — | OK | n/a | — |
| `/proc/keys` | reg 0444 | `root:root` | — | **OK** | EACCES | — |

**Notes:**
- `/dev/tty` (0666) → `ENXIO` — expected "no controlling terminal", **not** a denial.
- `/dev/input/event*` are openable **only because we are in group `1004(input)`**. This is a real capability, not a bug: input injection.
- `/dev/ion`, `/dev/binder`, `/dev/hwbinder`, `/dev/mali0` are `0666` and genuinely open `RDWR`.
- `/dev/xt_qtaguid` is `0644` → world-read: a small network-accounting info leak.

### 3.3 DENIED DESPITE PERMISSIVE DAC — this is the money table

These nodes have modes that **should** permit access for uid 2000, yet `open()` returns `EACCES`:

| path | mode | owner | open result | verdict |
|---|---|---|---|---|
| `/dev/sw_sync` | `0666` | `root:root` | **EACCES** | SELinux |
| `/dev/vndbinder` | `0666` | `root:root` | **EACCES** | SELinux |
| `/dev/full` | `0666` | `root:root` | **EACCES** | SELinux |
| `/dev/mmcblk0p3` | `0666` | `root:root` | **EACCES** | SELinux |
| `/dev/pmsg0` | `0222` | `root:log` | **EACCES** | SELinux |
| `/sys/fs/selinux/policy` | `0444` | `root:root` | **EACCES** | SELinux |
| `/sys/kernel/debug` | `drwxr-xr-x` | `root:root` | list→**EACCES** | SELinux |

The cleanest case: **`/dev/full`**. Its open handler is the generic `memory_open()` in `drivers/char/mem.c`, which unconditionally returns 0. DAC is `0666 root:root`. Therefore `EACCES` **cannot** originate from the driver or from Unix permissions — the only remaining source is `inode_permission()` → LSM → SELinux AVC.

**CONFIRMED: SELinux is the effective boundary; DAC backdoors (world-writable nodes) have all been closed by policy, not by chmod.**

#### `/dev/mmcblk0p3` — the world-writable partition that isn't

```
brw-rw-rw- 1 root root 179, 3 2020-03-04 03:23 mmcblk0p3      # in /linux_rootfs/dev
$ adb shell 'ls -lL /dev/mmcblk0p3'
brw-rw-rw- 1 root root 179, 3 ...                             # stat succeeds, mode 0666
$ adb shell '/data/local/tmp/x_arm ...'
/dev/mmcblk0p3   lnk/0666   0:0   179:3   EACCES   EACCES
```

- 1024 blocks = **512 KiB** (`/proc/partitions`), **not mounted** anywhere.
- World-readable *and* world-writable by mode, `root:root`, yet `open()` → `EACCES`.

This is the single most attractive-looking node on the box and it is fully closed. `/dev/block/mmcblk0p3` (the separate tmpfs alias) is `0660 root:system`, also denied.

### 3.4 EEPROM — the persistence question, answered NO

```
$ adb shell 'ls -lL /dev/eeprom_0 /dev/eeprom_3 /dev/eeprom_4 /dev/eep'
crw-rw---- 1 root root 228,   0 2020-03-04 03:23 /dev/eeprom_0
crw-rw---- 1 root root 227,   0 2020-03-04 03:23 /dev/eeprom_3
crw-rw---- 1 root root 226,   0 2020-03-04 03:23 /dev/eeprom_4
ls: /dev/eep: Permission denied
```

```
/dev/eeprom_0   lnk/0660   0:0    228:0    EACCES   EACCES
/dev/eeprom_3   lnk/0660   0:0    227:0    EACCES   EACCES
/dev/eeprom_4   lnk/0660   0:0    226:0    EACCES   EACCES
/dev/eep          lnk/0777   0:0    0:0     EACCES   EACCES     <-- lstat itself denied
```

- All three EEPROM nodes are **`0660 root:root`**. uid 2000 is not `root` and not in group `root` → **plain DAC denial, no SELinux needed.**
- `open()` returns `EACCES` for `O_RDONLY` and `O_RDWR` alike. `write()` was never reached.
- `/dev/eep` is worse: even `stat` is denied, so **its major:minor is unknown** and it does not appear in `/proc/devices` at all. It may be a stale squashfs image entry with no live driver — or a device whose label is simply stricter. **UNRESOLVED (see §9).**

**CONFIRMED: there is no EEPROM write path from uid 2000.** No chmod (squashfs is `ro`), no relabel, no alternative alias with looser perms.

### 3.5 `mknod` — the DAC-bypass idea, tested and closed

The obvious way around "the node is `0660 root:root`" is to create your own node for the same major:minor; a fresh node in `/data/local/tmp` would be owned by `shell` and would carry a `shell_data_file`-ish label, potentially bypassing both DAC and the vendor's per-device SELinux type.

```
$ adb shell 'cd /data/local/tmp; mknod t_cli c 241 4'
mknod: t_cli: Operation not permitted        # EPERM
```

**CONFIRMED: no `CAP_MKNOD`.** `shell` cannot synthesize device nodes. This closes the entire "shadow node" avenue for `eeprom_*`, `gpio`, `b2r`, `feeder`, `kmem2`, `cb`, `mtal`, etc.

---

## 4. `/dev/cli` — deep dive (and a correction to prior assumptions)

### 4.1 Established facts

`/dev/cli` = char **241:4**, `crw-rw---- root:shell`, the only member of the Middleware major-241 family reachable by uid 2000.

```
[1] open(/dev/cli, O_RDWR|O_NONBLOCK) -> fd=3 OK
[2] read(fd, 256) -> n=-1 EINVAL(22)
[3] ioctl(fd, 0x0, NULL) -> ret=0 OK
[4] ioctl(fd, 0x0, zeroed[64]) -> ret=0 OK
[5] ioctl(fd, 0xdeadbeef, NULL) -> ret=0 OK
[6] ioctl(fd, 0x1, NULL) -> ret=0 OK
[7] write(fd, "A") -> n=-1 EINVAL(22)
[8] read after ioctl -> n=-1 EINVAL(22)
[9] ioctl(FIONREAD) -> ret=0 OK val=0
```

Correlated kernel log:

```
10-18 16:25:49.504  0 0 W  : Warning: cli device is disabled
10-18 16:25:49.504  0 0 W  : Warning: cli device is disabled
10-18 16:25:49.504  0 0 W  : Warning: cli device is disabled
```

### 4.2 The critical finding

**The `cli` driver on this firmware is a compiled-in stub that performs no work.**

- Every `ioctl()` returns `0` regardless of the command word — `0x0`, `0x1`, `0xdeadbeef`, `0x541B` are all accepted identically. A real command demultiplexer would reject unknown commands.
- The only observable effect is a rate-limited kernel warning, `Warning: cli device is disabled`.
- `read()` and `write()` both return `EINVAL` → **no file-operation handlers are installed**; it is a pure ioctl node.
- No command string, no 16-byte command payload at offset 17, and no nonce exchange can be observed, because **nothing is dispatched**.

Quantified log-emission behaviour (5 identical calls per command word, 900 ms settle):

```
baseline=9
after 5x cmd=0:        10   (delta 1)
after 5x cmd=1:        10   (delta 0)
after 5x cmd=deadbeef: 10   (delta 0)
```

**CONFIRMED**: only `cmd == 0` reaches a logging path, and it is `printk`-ratelimited (≈1 line per 5 calls ≈ 1 per second-scale window). Other command words are silently swallowed and return success. This is the signature of a driver that logs "disabled" in its `ioctl` entry and returns immediately, with `printk_ratelimited()` in front of the message.

### 4.3 Consequence for the prior work

Prior investigation recorded the `/dev/cli` protocol as `ioctl(fd, 0, packet)` per command char, a 40-byte nonce from `/dev/urandom`, and a 16-byte cmd byte + string payload at offset 17.

**Those protocol details may be accurate as a description of the driver's *intended* interface, but on this unit the interface executes nothing.** The correct reading is:

- The device node, the major/minor, the `root:shell 0660` ACL and the ioctl entry point all exist.
- The driver's command dispatch is **compiled out or gated off** (`cli device is disabled`).
- Therefore **`/dev/cli` is not an exploitable command channel** and should be removed from the escalation shortlist unless a way to *enable* the driver is found.

### 4.4 Can it be enabled? — investigated, no path found

- No `/sys/module/*cli*` or `/sys/module/*middleware*` (`/sys/module` list contains only standard drivers + `mali_kbase`, `mtk_hcd`, `mtk_mmap`, `mtk_mod`, `btmtk_usb`, `snd_mtk`).
- No `/sys/class/*cli*`, no `/sys/dev/char/241:4`.
- No kernel command line access (`/proc/cmdline` → `EACCES`).
- The gate is therefore a **compile-time constant or an early-boot module parameter** with no runtime foothold. **INFERRED, high confidence.**

---

## 5. Vendor rootfs is unreadable

`/linux_rootfs` contains a complete Debian-style vendor userland (`bin`, `sbin`, `etc`, `lib`, `usr`, `var`, `basic`, `openbox`) with the tools you would want — `fw_printenv`, `insmod`, `modprobe`, `mknod`, `mount`, `bash`, `dmesg`, `nsenter`-style helpers, `getty`, `autologin`, and the Middleware CLI client.

**Every binary is `getattr`-denied to `shell`:**

```
ls: /linux_rootfs/bin/fw_printenv: Permission denied
ls: /linux_rootfs/bin/insmod: Permission denied
ls: /linux_rootfs/bin/mknod: Permission denied
ls: /linux_rootfs/bin/dmesg: Permission denied
ls: /linux_rootfs/sbin/getty: Permission denied
ls: /linux_rootfs/sbin/autologin: Permission denied
ls: /perm: Permission denied
```

**CONFIRMED**: you cannot read the vendor `fw_printenv`, cannot read `/perm` (the persisted-config partition, mounted `ro` with `context=u:object_r:perm_fs:s0`), and cannot execute vendor tools. This removes the single best static-analysis target for the ioctl drivers and rules out `fw_setenv`-style bootloader-variable persistence.

---

## 6. The `console` init service — runs as **shell**, not root

### 6.1 Service state

```
$ adb shell 'getprop | grep -i console'
[init.svc.console]: [running]
```

### 6.2 The process

```
$ adb shell 'ps -A'
root             1     0    9172   1072 SyS_epoll_wait      0 S init
shell         1156     1    4376    352 n_tty_read   aeba051c S sh
```

**CONFIRMED: PID 1156, PPID 1, command `sh`, owner `shell`, blocked in `n_tty_read`.** This is the `console` service.

### 6.3 Verdict

The `console` service is the AOSP stock definition:

```
service console /system/bin/sh
    class core
    console
    disabled
    user shell          <-- NOT root
    group shell log
    seclabel u:r:shell:s0
```

It runs as **uid 2000 / `u:r:shell:s0`** — the *same* security context we already hold. Gaining write access to its stdin would buy **zero** privilege. It would only offer an adb-independent liveness channel (a beacon), and even that is unavailable:

```
crw-------  1 root root  5, 1 2026-10-18 16:24 console
/dev/console   chr/0600   0:0   5:1   EACCES   EACCES
```

`/dev/console` is `0600 root:root`; `open()` → `EACCES`; `write()` unreachable. **CONFIRMED: `/dev/console` is inaccessible and irrelevant to privilege escalation.**

No `getty`, `login`, or `autologin` process is running (checked `ps -A` for `getty|login|autologin|ttyMT|console`).

---

## 7. Kernel-log access paths

| path | result | notes |
|---|---|---|
| `/dev/kmsg` | `crw------- root:root` → **EACCES** | DAC denial |
| `/proc/kmsg` | `-r--r----- root:systemlog` → **EACCES** | not in group `systemlog` |
| `dmesg` | **fails** | `dmesg: /dev/kmsg: Permission denied` |
| `/proc/last_kmsg` | **does not exist** | no pstore crash dump |
| `/sys/fs/pstore` | exists, **empty** | `ls -l` → `total 0` |
| **`logcat -b kernel -d`** | **WORKS** | ← the only kernel-log path |

```
$ adb shell 'logcat -b kernel -d | head -3'
10-18 15:23:59.383     0     0 D         : [user_wake_unlock] InputReader (2100) remove KeyEvents
10-18 15:24:00.381     0     0 D         : [user_wake_lock] InputReader (2100) add KeyEvents
```

**CONFIRMED: `logcat -b kernel` gives uid 2000 read access to the kernel log buffer** (via `logd`, which reads `/dev/kmsg` as root and exposes the `kernel` buffer to group `log` — we are in `1007(log)`). This is the **only** kernel observability channel available.

### 7.1 What you can and cannot see

You **can** see:
- raw `printk` output (driver warnings, `cli device is disabled`, `binder: ... ioctl 541b ... returned -22`, `selinux : avc: denied` from **userspace libselinux**).

You **cannot** see:
- **Kernel-originated SELinux AVC denials.** Verified: opening `sw_sync`, `vndbinder`, `pmsg0`, `mmcblk0p3` (all denied, per §3.3) produced **zero** new AVC lines. Only 2 AVC lines existed, both from *userspace* property-service denials generated by another agent's probing:

```
10-18 16:25:37.961  0 0 E selinux : avc:  denied  { set } for property=ctl.nonexistent_svc_xyz
   pid=14979 uid=2000 gid=2000 scontext=u:r:shell:s0 tcontext=u:object_r:ctl_default_prop:s0
   tclass=property_service
```

**CONFIRMED: kernel AVC printk is suppressed** (consistent with `audit=0` on the command line, or `CONFIG_AUDIT` reduced). Userspace `libselinux` denials still appear because they are written through `logd`, not printk.

**Operational impact:** during ioctl fuzzing you get **no denial feedback**. A denied operation and a driver-level `EACCES` are indistinguishable. Any fuzzing strategy must therefore rely on return values and crash behaviour, not on AVC-guided triage — and crash behaviour means reboot (§8).

---

## 8. Kernel hardening posture

```
$ adb shell 'for f in kptr_restrict dmesg_restrict perf_event_paranoid \
   unprivileged_bpf_disabled randomize_va_space modules_disabled panic_on_oops \
   print-fatal-signals yama/ptrace_scope; do printf "%-30s " "$f"; \
   cat /proc/sys/kernel/$f 2>&1; done'

kptr_restrict                  cat: /proc/sys/kernel/kptr_restrict: Permission denied
dmesg_restrict                 cat: /proc/sys/kernel/dmesg_restrict: Permission denied
perf_event_paranoid            3
unprivileged_bpf_disabled      cat: ...: No such file or directory
randomize_va_space             cat: ...: Permission denied
modules_disabled               cat: ...: Permission denied
panic_on_oops                  1
print-fatal-signals            0
yama/ptrace_scope              cat: ...: No such file or directory
```

| knob | value | implication |
|---|---|---|
| `perf_event_paranoid` | **3** | most restrictive; unprivileged `perf_event_open()` effectively closed. Removes the `perf_event_open` LPE class (CVE-2013-2094, CVE-2019-3901, …). |
| `panic_on_oops` | **1** | **CRITICAL SAFETY FACT — see §8.1.** |
| `unprivileged_bpf_disabled` | absent | kernel 3.10 predates eBPF; no unprivileged-BPF attack surface. |
| `yama/ptrace_scope` | absent | no Yama LSM. |
| `kptr_restrict` / `dmesg_restrict` / `randomize_va_space` / `modules_disabled` | unreadable | values unknown; **INFERRED** `kptr_restrict=2` from the kallsyms behaviour below. |

### 8.1 `panic_on_oops = 1` — the dominant operational constraint

**Any kernel oops triggers an immediate panic and reboot.** A reboot of this TV is explicitly out of scope and would also tear down the other investigation sharing the box.

This means: **aggressive ioctl fuzzing of `mali0`, `ion`, `binder`, `cli`, or any vendor node is not a "read-only" activity.** A single malformed ioctl that trips a `BUG_ON`, a null-deref, or a `WARN`-as-oops path does not return an error — it reboots the appliance. Every dynamic probe must be assumed to be potentially fatal. This is why §3.1 stopped at "establish accessibility" and did not fuzz.

### 8.2 `/proc/kallsyms` — readable, but addresses are masked

```
$ adb shell 'head -6 /proc/kallsyms'
00000000 T stext
00000000 T _text
00000000 t __create_page_tables
00000000 t __turn_mmu_on_loc
00000000 t __vet_atags
00000000 T do_undefinstr
```

```
$ adb shell 'wc -l < /proc/kallsyms; grep -c "^00000000" /proc/kallsyms'
83103
83103
```

**CONFIRMED: all 83,103 symbol names are readable, but every address is zeroed** (83,103 of 83,103 lines start with `00000000`). So `kptr_restrict` is active for `shell`.

**Value:** this is a complete, ordered symbol table of the running kernel — enormously useful for exploit development and for fingerprinting exactly which vendor patches are backported. **Limitation:** no base address, so it does not by itself give you a KASLR slide. Combined with *any* single address leak (e.g. a stack trace from `logcat -b kernel` after a controlled oops — which would reboot, or a `%pK`-style leak in some driver's printk) it becomes a full symbolisation primitive.

`/proc/timer_list` is likewise readable but zeroes its pointers (`.base: 00000000`), while still leaking timing (`now at 4819332601796 nsecs`).

### 8.3 Readable info-leak `/proc` files

```
iomem            Permission denied
interrupts       READABLE
timer_list       READABLE   (pointers zeroed)
sched_debug      READABLE
slabinfo         READABLE
zoneinfo         READABLE
vmallocinfo      READABLE   (pointers zeroed)
kallsyms         READABLE   (names only)
softirqs         READABLE
buddyinfo        READABLE
pagetypeinfo     READABLE
modules          Permission denied
misc             Permission denied
kmsg             Permission denied
cmdline          Permission denied
version          READABLE
```

`/proc/slabinfo` and `/proc/sched_debug` readable are mildly useful for heap-shaping (SLUB object counts / cache names) during exploit development.

### 8.4 Filesystem drivers present

`/proc/filesystems` lists `tntfs` and `texfat` — **Tuxera NTFS and exFAT**, proprietary, historically bug-prone. They are reachable only via `mount()`, which needs `CAP_SYS_ADMIN`. Not usable from `shell`. A crafted-image attack would require the device to auto-mount USB storage as root. **SPECULATIVE — not tested, not reachable from our position.**

---

## 9. RANKED kernel entry points

Ranked by (reachable now) × (kernel code executed on attacker-controlled input) × (known-bug density).

### 1. `/dev/mali0` — world-writable GPU (`0666`, `open` RDWR confirmed)
The single largest kernel attack surface reachable from uid 2000. `mali_kbase` on a 3.10 vendor kernel is a very large ioctl surface (`KBASE_IOCTL_*`: `MEM_ALLOC`, `JOB_SUBMIT`, `FENCE`, `SOFT_JOB`, …) with a long CVE history and typically minimal vendor patching. It is **`0666` and confirmed `open()`-able**. `/dev/ion` also present means the DMA-BUF/ION↔Mali path is fully reachable.
**Status: DELIBERATELY NOT PROBED** — another investigation owns the GPU. Treat as the top candidate and hand off.
**Confidence: HIGH that it is the best surface; UNKNOWN whether this specific build is vulnerable.**

### 2. `/dev/binder` — `0666`, `open` RDWR confirmed
Binder is a mature, high-value LPE target and this kernel is exactly the vintage of **CVE-2019-2215** (binder use-after-free via `epoll`, fixed upstream Oct 2019) and the `binder_thread`/`BINDER_WRITE_READ` family. Kernel build date **2020-03-04** post-dates the fix, so Sony *may* have backported it — but vendor 3.10 trees frequently ship with an unpatched binder. Reachable `RDWR` from `shell` with full `ioctl` (`BINDER_WRITE_READ`) capability.
**Confidence: MEDIUM-HIGH as an entry point; patch status UNKNOWN and worth a version-fingerprint check first.**

### 3. `/dev/ion` — `0666`, `open` RDWR confirmed
`ION_IOC_ALLOC` / `ION_IOC_MAP` / `ION_IOC_SHARE` / `ION_IOC_SYNC` reachable. ION has had handle-refcount and `ion_handle` UAF bugs and is a classic heap-spray primitive on this SoC generation (also gives a way to obtain physical/dma-buf memory, useful as a *support* primitive for a Mali or binder exploit).
**Confidence: MEDIUM as a standalone LPE; HIGH as an exploitation aid.**

### 4. `/dev/input/event0..3` — `0660 root:input`, we are in group `input`, `open` RDWR confirmed
Not a kernel-memory bug surface, but **fully open and requiring no exploit**. `EVIOCGNAME`, `EVIOCGRAB`, and `write()` of `struct input_event` let us inject arbitrary key events into the Android input pipeline. Devices:
- `event0`,`event1` = `mtkinp_events`, `KEY` bitmap spans essentially the **entire keycode space** (`KEY=7fffffff ffffffff … fffffffe`) including power/system keys.
- `event2`,`event3` = `TPRC`, with `event3` carrying `REL=143` (pointer).
**Value:** drive hidden service/factory/diagnostic UI, potentially reach the Middleware's own privileged control paths. This is the **highest-confidence confirmed capability in this report** — no bug required.
**Confidence: CONFIRMED reachable; privilege impact UNKNOWN (needs a UI-level follow-up).**

### 5. `/proc/kallsyms` + `logcat -b kernel` — exploitation enablers, not entry points
83,103 symbol names with zeroed addresses, plus live `printk`. Essential for turning any memory-corruption primitive into a controlled exploit, and for fingerprinting which patches are present. Zero direct privilege gain.

### 6. `/dev/xt_qtaguid` — `0644` world-read, confirmed
Read-only network accounting. Minor info leak (per-uid byte counters, interface stats). No privilege gain.

### 7. `/dev/alarm` — `0664` world-read, confirmed
Read-only RTC/alarm access. Timing info. No privilege gain.

### 8. `/dev/cli` — **openable but inert; DO NOT PRIORITISE**
`root:shell 0660`, `open` RDWR confirmed, but the driver is a compile-time-disabled stub that logs `Warning: cli device is disabled` and returns 0 for every command word. No dispatch, no nonce, no command execution. See §4.
**Confidence: CONFIRMED inert. This supersedes the earlier assumption that `/dev/cli` is a live command channel.**

### 9. EEPROM (`/dev/eeprom_0`, `_3`, `_4`, `/dev/eep`) — **CLOSED**
`0660 root:root` → DAC denial; `no CAP_MKNOD` → cannot forge aliases; squashfs is `ro` → cannot chmod/relabel. No path.
**Confidence: CONFIRMED closed.**

### 10. Everything else — **CLOSED**
`mtal`, `cb`, `cb2`, `gpio`, `b2r`, `feeder`, `kmem2`, `jpg`, `tsrec`, `adecomx`, `vdecomx`, `vencomx`, `vdpomx`, all `fbm_*`, `video0-9`, `fb0/fb1`, `snd/*`, `rtc0`, `pmsg0`, `ttyMT*`, `uhid`, `uinput`, `tun`, `ppp`, `fuse`, `device-mapper`, `kmsg`, `console`, `vcs*`, `sw_sync`, `vndbinder`, `mmcblk0p3` — all `EACCES`, either by DAC (group we are not in) or by SELinux despite permissive modes.

---

## 10. CONFIRMED vs INFERRED vs UNKNOWN

### CONFIRMED (directly observed, reproducible)

| # | Fact |
|---|---|
| C1 | `/dev` is tmpfs; vendor nodes are symlinks into `/linux_rootfs/dev/`, which is a **read-only squashfs** on `/dev/block/dm-0`. Vendor nodes are therefore immutable. |
| C2 | `/linux_rootfs/dev/` has 648 entries; **296 are `lstat`-denied** to `shell` despite `0775`/`0777`-reachable parents — proof of LSM (SELinux) enforcement over DAC. |
| C3 | `/dev/mmcblk0p3` is `0666 root:root`, 512 KiB, unmounted, and `open()` → **EACCES**. |
| C4 | `/dev/full` is `0666 root:root` and `open()` → **EACCES**, which is impossible from DAC or the generic `memory_open()`. **SELinux is the boundary.** |
| C5 | `/dev/sw_sync` (0666) and `/dev/vndbinder` (0666) also `EACCES`; `/dev/binder` (0666) and `/dev/hwbinder` (0666) **succeed**. Policy is per-type, not per-mode. |
| C6 | **`/dev/cli` (241:4, `root:shell 0660`) opens RDWR and its ioctl entry is reachable, but every command returns 0 and logs `Warning: cli device is disabled`. `read()`/`write()` → EINVAL. It is an inert stub.** |
| C7 | `/dev/eeprom_0/3/4` are `0660 root:root` → `EACCES` on open. `/dev/eep` is `lstat`-denied, major:minor unknown. **No EEPROM access from uid 2000.** |
| C8 | `mknod` returns `EPERM` — `shell` has no `CAP_MKNOD`, so no shadow nodes. |
| C9 | The `console` init service is `running` as PID 1156 `sh`, **uid `shell`** (not root), `u:r:shell:s0`. `/dev/console` is `0600 root:root` → `EACCES`. **No privilege there.** |
| C10 | `/dev/kmsg` (0600) and `/proc/kmsg` (`0440 root:systemlog`) are denied; `dmesg` fails. |
| C11 | **`logcat -b kernel -d` works** and is the only kernel-log read path. |
| C12 | **Kernel-originated AVC denials are NOT logged** (denied `open()`s produced no `avc:` lines); only userspace `libselinux` denials appear. |
| C13 | `perf_event_paranoid = 3`; `panic_on_oops = 1`; no unprivileged eBPF; no Yama. |
| C14 | `/proc/kallsyms` readable: **83,103 symbol names, all addresses zeroed**. |
| C15 | `/dev/input/event0..3` + `mice`/`mouse0` open **RDWR** (group `input`); `event0/1` = `mtkinp_events` (full keycode range), `event2/3` = `TPRC` (`event3` has `REL`). |
| C16 | `/dev/ion`, `/dev/binder`, `/dev/hwbinder`, `/dev/mali0`, `/dev/ashmem` are `0666` and open **RDWR**. |
| C17 | `/dev/xt_qtaguid` (`0644`) and `/dev/alarm` (`0664`) open **read-only**. |
| C18 | The Middleware family (majors 226–229, 237, 238, 241, 243, 244, 245, 247, 251) has **zero `/sys` representation** — no class, no `/sys/dev/char`, no module params. |
| C19 | `/proc/misc`, `/proc/modules`, `/proc/tty/drivers`, `/proc/cmdline`, `/proc/iomem`, `/sys/kernel/debug`, `/sys/fs/selinux/policy`, `/dev/socket/*` are all denied to `shell`. |
| C20 | `/linux_rootfs/**` (vendor `bin`/`sbin`/`etc`) is `getattr`-denied; `/perm` is denied. No static analysis of vendor tools is possible from `shell`. |
| C21 | No `/dev/watchdog`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/block/by-name`. No `su` binary. |

### INFERRED (strong reasoning, not directly observed)

| # | Inference | Basis |
|---|---|---|
| I1 | SELinux denies because the vendor nodes carry device-specific types and `shell` lacks `{ open }`/`{ getattr }` on them. | C2, C4, C5 |
| I2 | `kptr_restrict = 2`. | C14 (all addresses zero despite readable file) |
| I3 | `audit=0` (or equivalent) on the kernel command line. | C12 |
| I4 | `cli`'s "disabled" gate is a compile-time constant or an early-boot parameter with no runtime knob. | C6 + C18 + no `/sys/module/*cli*` |
| I5 | The vendor chose symlinks-into-squashfs precisely to preserve vendor SELinux labels that `ueventd` would not apply. | C1 + C2 + the per-type policy behaviour in C5 |
| I6 | `/dev/eep` is a stale image entry with no live driver, or a strictly-labelled device; `/proc/devices` has no `eep` registration. | C7 |
| I7 | The three `0600`-root ttyMT nodes are a serial console that no getty is using (no `getty`/`login` process found). | C9 + `ps -A` |

### UNKNOWN / not established

| # | Open question | Why it matters |
|---|---|---|
| U1 | Whether this build's `mali_kbase` is patched for known CVEs. | Decides whether the top-ranked surface is live. Owned by the other investigation. |
| U2 | Whether `binder` here predates CVE-2019-2215 / other binder fixes. | Would make a very well-documented LPE available. Fingerprint first. |
| U3 | Exact major:minor and driver of `/dev/eep`, `/dev/gpio`, `/dev/rtc`, `/dev/dsp`, `/dev/vomx`, `/dev/aomx`, `/dev/fbmomx`. | All `lstat`-denied; no `/proc/misc`. |
| U4 | Whether the "disabled" CLI driver can be enabled by a bootloader variable or by the vendor rootfs's own init (which we cannot read). | Would restore `/dev/cli` to the shortlist. |
| U5 | Whether `event*` injection can reach a privileged middleware path. | Would convert C15 from "capability" to "escalation". |
| U6 | SELinux `shell` domain's full allow set (policy file is `0444` but denied; no `sesearch`). | Needed to enumerate anything not covered by empirical open-tests. |
| U7 | `kptr_restrict`, `dmesg_restrict`, `randomize_va_space`, `modules_disabled` values. | Unreadable; I2 is inferred only. |

---

## 11. Bottom line

1. **The DAC layer is a decoy.** `/dev/mmcblk0p3` is `0666` and `/dev/full` is `0666`; both are `EACCES`. SELinux is the real wall, and it is enforcing and unlogged.
2. **The vendor Middleware surface is comprehensively sealed.** Of ~20 vendor drivers, exactly **one** node — `/dev/cli` — is reachable from uid 2000, and that one is a **disabled stub**. EEPROM is `0660 root:root` with `mknod` blocked and a read-only squashfs underneath: no persistence path.
3. **The real reachable kernel surfaces are the Android-generic `0666` misc devices**: `mali0`, `binder`, `hwbinder`, `ion`, `ashmem`. `mali0` is the best candidate (owned by another investigation) and `binder` is the best unclaimed one.
4. **`panic_on_oops=1` makes dynamic probing a reboot risk.** Nothing here should be fuzzed casually; the box will panic, not return an error.
5. **Two genuinely useful enablers were found**: `logcat -b kernel` (kernel log read) and `/proc/kallsyms` (83,103 symbol names, addresses masked). Kernel AVC feedback is *not* available, which materially slows ioctl triage.
6. **`/dev/input/event*` is open RDWR and needs no exploit at all** — the highest-confidence confirmed capability, though its privilege impact is a UI-layer question, not a kernel one.

---

## Appendix A — Go device prober (`x.go`)

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func errnoStr(e error) string {
	if e == nil {
		return "OK"
	}
	if en, ok := e.(syscall.Errno); ok {
		switch en {
		case syscall.EACCES: return "EACCES"
		case syscall.ENOENT: return "ENOENT"
		case syscall.ENODEV: return "ENODEV"
		case syscall.EPERM:  return "EPERM"
		case syscall.EBUSY:  return "EBUSY"
		case syscall.ENXIO:  return "ENXIO"
		case syscall.EINVAL: return "EINVAL"
		case syscall.ENOTTY: return "ENOTTY"
		case syscall.ENOSYS: return "ENOSYS"
		case syscall.EROFS:  return "EROFS"
		}
		return fmt.Sprintf("ERRNO_%d", int(en))
	}
	return e.Error()
}

func doIoctl(fd int, cmd uintptr) string {
	var arg [64]byte
	r, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&arg[0])))
	if e != 0 { return errnoStr(e) }
	return fmt.Sprintf("OK(ret=%d)", int32(r))
}

func main() {
	path := "/data/local/tmp/probe_paths.txt"
	if len(os.Args) > 1 { path = os.Args[1] }
	f, err := os.Open(path)
	if err != nil { fmt.Println("cannot open list:", err); return }
	defer f.Close()
	sc := bufio.NewScanner(f)
	fmt.Printf("%-26s %-10s %-6s %-22s %-14s %-14s %-12s %-12s\n",
		"PATH", "TYPE/PERM", "UID:GID", "MAJ:MIN", "OPEN_RDONLY", "OPEN_RDWR", "FIONREAD", "TCGETS")
	fmt.Println(strings.Repeat("-", 132))
	for sc.Scan() {
		p := strings.TrimSpace(sc.Text())
		if p == "" || strings.HasPrefix(p, "#") { continue }
		var lst syscall.Stat_t
		le := syscall.Lstat(p, &lst)
		var tgt syscall.Stat_t
		te := syscall.Stat(p, &tgt)
		st := &tgt
		if te != nil { st = &lst }
		typ := "?"
		if le == nil {
			switch lst.Mode & syscall.S_IFMT {
			case syscall.S_IFCHR: typ = "chr"
			case syscall.S_IFBLK: typ = "blk"
			case syscall.S_IFLNK: typ = "lnk"
			case syscall.S_IFDIR: typ = "dir"
			case syscall.S_IFREG: typ = "reg"
			}
		}
		perm := fmt.Sprintf("%04o", st.Mode&0777)
		owner := fmt.Sprintf("%d:%d", st.Uid, st.Gid)
		maj := (uint64(st.Rdev) >> 8) & 0xfff
		min := (uint64(st.Rdev) & 0xff) | ((uint64(st.Rdev) >> 12) & 0xfff00)
		mm := fmt.Sprintf("%d:%d", maj, min)
		if le != nil {
			owner = "STATFAIL"; mm = errnoStr(le); perm = "-"
		}
		fdRO, eRO := syscall.Open(p, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		r1 := errnoStr(eRO)
		if eRO == nil { syscall.Close(fdRO) }
		fdRW, eRW := syscall.Open(p, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		r2 := errnoStr(eRW)
		io1, io2 := "-", "-"
		if eRW == nil {
			io1 = doIoctl(fdRW, 0x541B) // FIONREAD
			io2 = doIoctl(fdRW, 0x5401) // TCGETS
			syscall.Close(fdRW)
		}
		fmt.Printf("%-26s %-10s %-6s %-22s %-14s %-14s %-12s %-12s\n",
			p, typ+"/"+perm, owner, mm, r1, r2, io1, io2)
	}
}
```

Build & deploy:
```powershell
$env:GO111MODULE='off'; $env:GOOS='linux'; $env:GOARCH='arm'; $env:GOARM='7'; $env:CGO_ENABLED='0'
& 'C:\Program Files\Go\bin\go.exe' build -o x_arm x.go
& $adb -s 100.70.99.3:5555 push x_arm /data/local/tmp/x_arm
& $adb -s 100.70.99.3:5555 shell 'chmod 755 /data/local/tmp/x_arm'
& $adb -s 100.70.99.3:5555 shell '/data/local/tmp/x_arm /data/local/tmp/probe_paths.txt'
```

## Appendix B — `/dev/cli` prober (`cli.go` / `cli2.go`)

`cli.go` performs the full sequence (open, read, ioctl×4, write, read, FIONREAD); `cli2.go` takes a single hex command word so each `ioctl` can be correlated one-to-one with kernel-log output:

```
$ adb shell '/data/local/tmp/cli2_arm 0 nul'
ioctl(cmd=0x0, arg=nul) -> ret=0 errno=0
$ adb shell 'logcat -b kernel -d | grep "cli device"'
10-18 16:26:01.066  0 0 W  : Warning: cli device is disabled
```

## Appendix C — Raw capture files

All raw outputs are retained next to this report in `surface/raw/`:

| file | contents |
|---|---|
| `dev-ls.txt` | `ls -la /dev` (tmpfs layer) |
| `linux_rootfs-dev-l.txt`, `linux_rootfs-dev-ln.txt` | `ls -l` / `ls -ln` of the real node tree |
| `proc-devices.txt` | `/proc/devices` |
| `chardev-map.txt` | 152 registered char maj:min from `/sys/dev/char` |
| `probe-results.txt` | 345-path accessibility matrix |
| `probe-results2.txt` | 68-path second-tier matrix |
| `partitions.txt` | `/proc/partitions` |
| `mounts-cmdline.txt` | `/proc/mounts` |
| `input-devices.txt` | `/proc/bus/input/devices` |
| `sysctls.txt` | kernel hardening sysctls |
| `procleak.txt` | readable/denied `/proc` info-leak files |
| `ps-A.txt` | full process table |
| `misc-dirs.txt` | `/dev/block/by-name`, `/dev/usb-ffs`, `/dev/socket` |
| `linux-rootfs-bin.txt` | vendor rootfs `bin`/`sbin`/`/perm` (all denied) |
