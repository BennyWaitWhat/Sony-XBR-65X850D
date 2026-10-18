# remap-surface — device/kernel/filesystem/network attack-surface sweep (gaps + confirmations)

Device: Sony BRAVIA **XBR-65X850D** (`SVP-DTV15`, `SVP4KDTV15_UC`)
OS: Android 8.0.0, build `OPR2.170623.027.S16` / 6.827, fingerprint `Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/OPR2.170623.027.S16/6.827:user/release-keys`
Kernel: Linux 3.10.79 armv7l, `#1 SMP PREEMPT Wed Mar 4 17:00:38 JST 2020` (root@BuildHost728)
SELinux: **Enforcing**, policyvers 30, mls=1, deny_unknown=1, **no booleans defined** (`/sys/fs/selinux/booleans` empty)
Access: adb `100.70.99.3:5555` → `uid=2000(shell) gid=2000(shell) groups=2000,1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc) context=u:r:shell:s0`
Shell process limits: `CapEff=0`, `CapBnd=0x00000000000000c0` (CAP_SETGID|CAP_SETUID only), `Seccomp=0`, `ro.debuggable=0`, `ro.secure=1`.
Measured: 2026‑10‑18 ~16:00–17:00 device time, all commands read-only (`ls/stat/cat/dd/od/mount/getprop//proc//sysfs`, open-only probes, one-shot SOAP GETs from the host).

**Scope note.** Prior work already captured mounts, `/dev` inventory and DLNA SCPD documents:
`tv-research/surface/kernel-devices.md`, `kernel-cve-research.md`, `binder-services.md`,
`surface/raw/` (dev-ls, linux_rootfs-dev-l, mounts-cmdline, …) and `surface/*SCPD.xml`.
Those were cross-read, not repeated. This report contains (a) the four requested gaps, (b) fresh
confirmations/refutations of the device matrix, and (c) everything newly measured this pass.

---

## 1. GAP: setuid / setgid sweep (with labels)

### Method
`find <tree> -perm -4000 -o -perm -2000 2>/dev/null` (toybox `find`, leading-dash `-perm` verified
working on this device with a `-perm -0002` control that matched the known 0666 files), plus
`ls -l ... | grep -E '^-..[sS]|^-.{5}[sS]'` on stat-readable trees, plus existence oracle
(`ls` returns **ENOENT** for absent, **EACCES** for present-but-SELinux-hidden) for `su`-like names.

### Result: **0 setuid / 0 setgid found** — and the reason is structural
| tree | coverage | hits |
|---|---|---|
| `/system` (squashfs, ro) | 244 names; **60 files deny `getattr` to shell** (see A.1) → skipped by find; everything else checked | 0 |
| `/system/vendor` = `/vendor` (symlink) | 36 names, 19 deny `getattr`; `/vendor/bin/hw` 16 entries fully visible | 0 |
| `/linux_rootfs` (squashfs, ro) | **all files deny `getattr`** (`mt_rootfs_exec`) → no coverage; names enumerated only (`bin/` ~60, `sbin/` 8, `basic/` ~13) | 0 |
| `/3rd` (squashfs) | 1 file (`bin/cifs.ko`, 0640 root:root) | 0 |
| `/perm`, `/sbin`, `/cache`, `/root`, `/tmp`, `/3rd_rw`, `/data` (except subdirs below), `/config` | readdir denied to shell → **no coverage** | n/a |
| `/data/local/tmp`, `/data/anr`, `/data/user_de/0/com.android.shell`, `/data_demo`, `/dev`, `/mnt`, `/storage`, `/acct`, `/upgrade` | readable, checked | 0 |

Additional facts:
* `su` binaries absent: `/system/bin/su`, `/system/xbin/su`, `/vendor/bin/su`, `/sbin/su`, `/system/bin/sudo`, `/system/bin/busybox` → **ENOENT** (not merely denied). `/system/bin/run-as`, `/system/bin/ping`, `/system/bin/ping6` exist.
* `run-as` only switches to *debuggable* app uids; build is `user` (no debuggable system apps expected).
* Mount flags kill most of the theoretical value anyway: `/data` and `/cache` are mounted **`nosuid`**, and shell's only writable+executable directory `/data/local/tmp` lives on `/data` → **a setuid binary dropped there cannot elevate**. `/3rd_rw` is rw ext4 **without** `nosuid`, but is `root:root 0755` and SELinux-denied to shell (see A.1/§2), so it is not writable by us.
* Setuid bits on the 60 metadata-hidden files cannot be measured from uid 2000. They are all AOSP/vendor daemon executables launched by `init` as root (`audioserver_exec`, `netd_exec`, `telephony_exec`, `nginx_exec`, …), where a setuid bit would be unusual — but **this is the one part of the sweep that still needs a root context or an offline squashfs read**. Recommended command once any root context exists: `find /system /vendor /linux_rootfs /3rd /perm -perm -4000 -o -perm -2000`.

Labels of the hidden set are tabulated in **Appendix A.1** (60 rows, labels recovered from AVC `tcontext`).

---

## 2. GAP: world-/group-writable and world-readable *regular files* that matter

RW mounts are only: `/cache`, `/data`, `/3rd_rw`, `/tmp`, `/upgrade`, `/dev`, `/mnt`, `/storage`, `/config`, cgroup mounts, `/sys`, `/proc`.
`/system`, `/vendor`, `/odm`, `/linux_rootfs`, `/3rd`, `/perm`, `/data_demo` are **read-only** mounts,
so mode bits there are moot for writes (and `/system` scan found 0 world-writable and 0 group-writable
regular files anyway: `ww=0 gw=0`).

### 2.1 The one genuinely interesting result: `/data/anr` is world-readable
| path | mode | owner:group | SELinux label | shell read? | shell write? |
|---|---|---|---|---|---|
| `/data/anr` | `0775 drwxrwxr-x` | `system:system` | `u:object_r:anr_data_file:s0` | **YES** (list+read) | no (dir others r-x) |
| `/data/anr/bugreport-traces.txt` | `-rw-rw-rw-` 1.45 MB | `root:root` | `anr_data_file` | **YES** | **NO — SELinux AVC `denied { write }`** |
| `/data/anr/traces.txt` | `-rw-rw-rw-` 191 KB | `system:system` | `anr_data_file` | **YES** | **NO — same AVC** |
| `/data/anr/traces.txt.bugreport` | `-rw-rw-rw-` 1.36 MB | `root:root` | `anr_data_file` | **YES** | **NO — same AVC** |

Proof of read (uid 2000):
```
# head -n 6 /data/anr/traces.txt
----- pid 5205 at 2026-10-18 15:10:43 -----
Cmd line: com.tailscale.ipn
Build fingerprint: 'Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/...:user/release-keys'
ABI: 'arm'
Build type: optimized
```
`bugreport-traces.txt` contains native/Java thread dumps of **63 processes** (system_server, HAL
services, vendor daemons, apps) with library paths, symbols and `pc` offsets:
`#00 pc 00049678 /system/lib/libc.so (__ioctl+8)`.
→ **Information-leak primitive (recon/ASLR/offset assist), not a write primitive.** Writes are SELinux-denied:
`avc: denied { write } for name="traces.txt" ... scontext=u:r:shell:s0 tcontext=u:object_r:anr_data_file:s0 tclass=file`
The other two files are `root`-owned 0666 but the same denial applies; no root process was observed reading them in a way that would turn the file into a root-read/exec primitive.

### 2.2 Other writable regular files/dirs reachable from shell
| path | mode | owner:group | label | note |
|---|---|---|---|---|
| `/data/local/tmp` | `0771 drwxrwx--x` | `shell:shell` | `shell_data_file` | **only shell-writable exec dir** (`test -w` = W); on `nosuid` mount |
| `/data/local/tmp/dalvik-cache` | `0777 drwxrwxrwx` | `shell:shell` | `shell_data_file` | world-writable dir (shell-owned) |
| `/data/local/tmp/*.xml`, `probe_paths*.txt` | `-rw-rw-rw-` ×6 | `shell:shell` | `shell_data_file` | team artifacts from earlier sessions, not a primitive |
| `/data/local/tmp/*_arm`, `cve28663`, `devopen`, `qflag`, … | `-rwxr-xr-x` | `shell:shell` | `shell_data_file` | prior-session binaries (see task‑3) |
| `/data/user_de/0/com.android.shell/{cache,code_cache}` | `drwxrws--x` | `shell:shell` | `shell_data_file` | shell-private |
| `/storage/emulated/0` (sdcardfs) | dirs `0771`-ish | `root:sdcard_rw` | `sdcardfs` | `test -w` = W; mounted `nosuid,nodev,noexec`; no world-writable regular files found (maxdepth 2) |
| `/dev/usb-ffs` and `/dev/usb-ffs/adb` | `0770 drwxrwx---` | `shell:shell` | `device` | shell-writable ffs dir, empty — no file primitive observed |
| `/upgrade` (vfat) | `0764 drwxrw-r--` | `root:root` | `vfat` | **no write** (others r); empty |
| `/acct/cgroup.event_control` | `--w--w--w-` | `root:root` | `cgroup` | world-writable DAC, but open() denied by SELinux |
| `/tmp` | `0771` (mount opts `mode=1771`) | `root:system` | `tmpfs` | not writable by shell; known-path lookups still work (see §5) |

`/cache` (`0770 system:cache`) and all of `/data` except the three subdirs above
(`/data/app`, `/data/misc`, `/data/system`, `/data/user*`, `/data/media`, `/data/property`, …)
are `ls: Permission denied` for shell — **their contents could not be enumerated**, so a world-writable
file under `/data` proper cannot be ruled out from uid 2000. A root-side `find /data /cache -type f -perm -0002` is the only way to close this.

Unsettled side note: `test -w` on this device reflects SELinux as well as DAC (`test -w /dev/full` → false although its DAC is 0666), so it was not used to claim writability beyond the cases above.

---

## 3. GAP: network-exposed services that actually accept connections

All listeners bind wildcard (`0.0.0.0`/`[::]`) on the TV; the TV is reachable at **100.70.99.3**
(the adb address) and advertises a second address **100.115.119.101** inside SSDP `LOCATION`
(see the SSDP capture in `surface/udp.log`) — the TV is on the tailnet, so "network-exposed" here
means reachable from the team's tailnet, not necessarily from the TV's LAN.

Fresh host-side checks (2026‑10‑18):
```
TCP connect 100.70.99.3: 8008 OPEN, 8443 OPEN, 9000 OPEN, 36266 OPEN, 36792 OPEN, 6466 OPEN, 6467 OPEN
HTTP  GET  :52323/MediaRenderer.xml           -> 200, 4089 bytes, Server: Android/1.6 UPnP/1.0 Huey Sample DMR/0.1
SOAP  POST :52323/upnp/control/AVTransport    -> 200, GetTransportInfoResponse (no auth, no session)
HTTP  GET  :8008/                             -> 404 (DIAL paths all 404: YouTube/Netflix/…/BogusApp123)
HTTP  GET  :9080/                             -> connection refused at this moment (was live earlier, see below)
```

### 3.1 UPnP/DLNA MediaRenderer — `com.sony.huey.dlna.module` (the real find)
| property | measurement |
|---|---|
| serving process | `com.sony.huey.dlna.module` + `:dmr` process, **uid 10102** (`u0_a2`), domain **`u:r:sony_platform_app:s0:c512,c768`** |
| package | `/system/app/HueyModule/HueyModule.apk` — **preinstalled SYSTEM app**, `versionName=2.0`, `versionCode=2`, `targetSdk=26`, flags `SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP` |
| device description | `http://100.70.99.3:52323/MediaRenderer.xml` (also reachable via `/RenderingControlSCPD.xml`, `/ConnectionManagerSCPD.xml`, `/AVTransportSCPD.xml`, `/StreamSplicingSCPD.xml`, `/dlna_tv_*.png|jpg` icons) |
| UDN | `uuid:23456789-1234-1010-8000-045D4B2C59FD`, DLNA doc `DMR-1.51`, model "Sony 2017 4K RVU TV" |
| control endpoints | `POST /upnp/control/AVTransport`, `/upnp/control/RenderingControl`, `/upnp/control/ConnectionManager`, `/upnp/control/StreamSplicing` |
| event endpoints | `SUBSCRIBE /upnp/event/{AVTransport,RenderingControl,ConnectionManager,StreamSplicing}` (returned 400 without proper headers) |
| own transport | answers `SUBSCRIBE` / malformed requests with `X-AV-Client-Info: av=5.0; cn="Sony Corporation"; mn="BRAVIA XBR-65X850D"; mv="3.0"` |
| TCP listeners | 52323 (description/control), 41824 and 55839 (HTTP, `/` → 400 Bad Request) on `100.70.99.3` |
| UDP listeners | 52323, 1900 SSDP ×2 (`239.255.255.250:1900`), plus ephemeral 49036/46833 |
| authored/tested by | previous pass already captured the 4 SCPDs into `surface/*.xml`; this report adds the exact URLs, package identity, SELinux domain and live unauthenticated confirmation |

**Authentication: none observed.** A SOAP envelope with no auth headers, no session, no `PAIRING` state
returned `200 OK` with a valid `GetTransportInfoResponse`. Actions exposed by the SCPDs (all on the
same unauthenticated endpoints; the read-only ones below were verified with actual SOAP calls,
state-changing ones were **not** executed because this task is read-only):
* AVTransport — **read**: `GetTransportInfo`, `GetMediaInfo`, `GetPositionInfo`, `GetDeviceCapabilities`, `GetCurrentTransportActions`, `GetCurrentConnectionIDs`; **state-changing (exposed, untested)**: `SetAVTransportURI`, `SetNextAVTransportURI`, `Play`, `Stop`, `Pause`, `Seek`, `Next`, `Previous`, `X_PlayURI`, `X_DLNA_GetBytePositionInfo`.
* RenderingControl — **read**: `GetVolume` (returned `36`), `GetMute`, `ListPresets`, `X_GetAudioSelection`, `X_GetVideoSelection`; **state-changing**: `SetVolume`, `SetMute`, `SelectPreset`, `X_UpdateAudioSelection`, `X_UpdateVideoSelection`.
* ConnectionManager — **read**: `GetProtocolInfo` (7.9 KB sink protocol list), `GetCurrentConnectionIDs`, `GetCurrentConnectionInfo`; **state-changing**: `PrepareForConnection`, `ConnectionComplete`, **`X_StartWFD`** (Wi‑Fi Display start), `X_DLNADOC`.
* StreamSplicing (RVU) — `SetBreakAuxStreamPlaylist`, `SetBreakAuxStreamTrigger` (both state-changing, exposed).
* The write actions that matter strategically: `SetAVTransportURI` (cast an attacker-chosen URL to the TV), `X_StartWFD` (screen-mirroring/session takeover), `SetVolume`/`SetMute` (nuisance) and StreamSplicing (ad-insertion splice control).

Why this ranks above the other network services: the daemon runs in **`sony_platform_app`**, i.e. a
Sony-privileged platform domain (broader than `priv_app`), and it parses multiple rich XML/SOAP
attack surfaces over the network without authentication. A memory-safety bug here is an app-domain
foothold in a privileged Sony process — not root, but a materially better starting point than Netflix/Tailscale.

### 3.2 `com.google.android.apps.mediashell` — correction of the "AID_SYSTEM" assumption
The previous assumption "mediashell on uid 10000 (AID_SYSTEM)" is wrong:
* `uid 10000` is an **application uid** (`u0_a0`), not `AID_SYSTEM`; `AID_SYSTEM` is **1000** (measured: `servicemanager` runs uid 1000).
* measured domain: **`u:r:priv_app:s0:c512,c768`** (`/proc/13567/attr/current`), package `com.google.android.apps.mediashell`, apk `/data/app/.../base.apk`.
→ code execution there is **priv_app**, not system-level. It is still a preinstalled priv-app, but it should not be prioritised as "system".

Ports (all fresh-confirmed TCP-reachable from the network): **8008** (HTTP: `/` and DIAL app paths → 404/empty; no unauthenticated API found), **8443** (TLS-ish; all handshakes fail), **9000** (accepts, sends nothing, TLS handshake fails), **36266 / 36792** (accept then close on any byte; prior `pathprobe2.log` same), **10042** loopback-only. Prior work already probed these (`surface/banners.log`, `pathprobe2.log`, `probe4.log`) — result: no unauthenticated HTTP surface found; protocols on 9000/36266/36792/8443 remain unidentified. **Deprioritise.**

### 3.3 Other network listeners
| listener | uid | package | domain | note |
|---|---|---|---|---|
| TCP 62323? no — **52323 / 41824 / 55839** | 10102 | `com.sony.huey.dlna.module` | sony_platform_app | DLNA (above) |
| UDP 1900, UDP 52323, 46833, 49036 | 10102 | same | sony_platform_app | SSDP / UPnP |
| TCP 6466, 6467 | 10002 | `com.google.android.tv.remote.service` (`/system/priv-app/AtvRemoteService`) | not sampled | Android-TV remote protocol; mDNS `_androidtvremote._tcp` advertises **port 6466**; TLS handshakes fail (protocol version) — pairing protocol |
| TCP 8008/8443/9000/36266/36792/10042 | 10000 | `com.google.android.apps.mediashell` | priv_app | see 3.2 |
| TCP 9080 | 10143 | `com.netflix.ninja` (untrusted_app) | untrusted_app | **transient**: earlier in same session a GET returned `HTTP/1.1 200` + `Server: NRDP/2020.1.3.1` + body `status=ok`; minutes later connection refused → app opens/closes the listener (NRDP). App-domain only. |
| UDP 1900 (+5353 via mdns) | 10143 / 1020 | netflix / mdnsd | untrusted_app / — | SSDP as client |
| TCP 5555 | 2000 | adbd | shell | our access path |
| UDP 68 | 1000 | DHCP client | — | |
| UDP 58321 / 56167, TCP tailnet | 10170 | `com.tailscale.ipn` | untrusted_app | VPN client (explains 100.x addresses) |
| 5353 UDP | 1020 | mDNS responder | — | advertises `_adb._tcp:5555`, `_androidtvremote._tcp:6466` |

Unix-domain sockets (control channels of root daemons): `/tmp/DTVService` (mt_dtv-svc), `/tmp/MTKRMService` (mt_mtk_rm), `/tmp/DTCP_server`, `/tmp/DFBInput`, `@/tmp/audio-output-service`, `@/tmp/mixer-service`, `@jdwp-control`, `/data/system/ndebugsocket`, 18 entries in `/dev/socket/` — shell can `readdir` the directories but is SELinux-denied every `lstat`/connect; no unix-socket client exists in the shell toolset (`toybox nc` is IP-only), so connectability was not exercised. Full path list in Appendix A.4.

---

## 4. GAP: confirm/refute the open-only device matrix (fresh measurement)

Method: per the Lead's instruction, `e=$( ( exec 3<>"$p" ) 2>&1 ); rc=$?` for O_RDWR and `( exec 3<"$p" )` for O_RDONLY; exact shell error text recorded. `head -c` was confirmed unusable on this toybox (`head: not integer: c`, rc=1).

**Confirmed exactly as previously reported:** `/dev/mali0`, `/dev/binder`, `/dev/hwbinder`, `/dev/ion`, `/dev/ashmem`, `/dev/cli` = `OPEN_RW`; `/dev/xt_qtaguid` = `OPEN_RO`; and the DENIED list `/dev/vndbinder`, `/dev/kmem2`, `/dev/sw_sync`, `/dev/pmsg0`, `/dev/mixer`, `/dev/ir`, `/dev/tsrec`, `/dev/fusion0/1`, `/dev/eeprom_0/3/4`, `/dev/ttyMT0/2/3/4/5`, `/dev/graphics/fb0`, `/dev/video0`, `/dev/uhid`, `/dev/uinput`, `/dev/tun`, `/dev/ppp`, `/dev/rfkill`, `/dev/rtc0`, `/dev/loop-control`, `/dev/cpu_dma_latency` — all re-measured **DENIED** with `Permission denied`.

**Corrections / additions to that matrix (new measurements):**
| path | measured | comment |
|---|---|---|
| `/dev/cli` | **OPEN_RW** | confirmed; symlink → `/linux_rootfs/dev/cli` (chr 241,4, `crw-rw---- root:shell`, `cli_device`). Earlier "denied" note is definitively wrong; the denial seen earlier belongs to `untrusted_app` context (`scontext=u:r:untrusted_app:s0:c512,c768` in AVC, from the probe APK), not to adb shell |
| `/dev/input/event0`, `/dev/input/event1` | **OPEN_RW** | *not* in the previous matrix. `crw-rw---- root:input`, `input_device`; shell is in group `input(1004)` → evdev read/write (+ `getevent`, `sendevent`/`input` binaries exist) |
| `/dev/alarm` | **OPEN_RO** | `crw-rw-r-- system:radio`, `alarm_device`, world-readable RTC/alarm interface |
| `/dev/xt_qtaguid` | OPEN_RO | as reported; `qtaguid_device` |
| `/linux_rootfs/dev/mali0` | **OPEN_RO** | second mali node, chr **10,60** (vs `/dev/mali0` 10,51); `crw-r--r-- root:root` so RO only; `gpu_device` |
| `/dev/full` | **DENIED** | DAC 0666 but SELinux denies `full_device` — good proof that DAC≠reachability on this box |
| `/dev/kmsg` | DENIED | `crw------- root:root`, `kmsg_device`; `dmesg` also fails on it |
| `/dev/cb`, `/dev/cb2`, `/dev/cb_system` | DENIED | `crw-rw---- system:oem_2901 241,8/16`, `cb_device` |
| `/dev/block/mmcblk0p3` (eeprom, 179,3) | DENIED | `brw-rw---- root:system` + `eeprom_device` AVC; the `/linux_rootfs/dev` copy is 0666 root:root but the `/dev/block` copy is 0660 — either way unusable |
| `/dev/block/mmcblk0p15` (`/3rd_rw` backing), `mmcblk0p45/46`, `mmcblk0` | DENIED | `brw------- root:root` |
| `/dev/console`, `/dev/vcs`, `/dev/vcsa`, `/dev/tty1-63`, `/dev/ptmx` | ptmx OPEN_RW, console/vcs locked | console `crw------- root:root` |
| `/dev/ptmx` | OPEN_RW | expected (pty allocation) |
| `/dev/__properties__` | DENIED | `properties_device` dir; `ls` and open denied |
| `/dev/socket/<name>` | lstat DENIED | 18 socket names visible in readdir errors: `adbd, cryptd, dnsproxyd, fwmarkd, lmkd, logd, logdr, logdw, mdns, mdnsd, netd, property_service, tombstoned_crash, tombstoned_intercept, vold, webview_zygote, wpa_wlan0, zygote` |
| `/dev/graphics/fb0`, `/dev/snd/controlC0`, `/dev/usb_cst` | DENIED | |

Full machine-generated matrix (every measured node with the exact error string) is **Appendix A.2**.

---

## 5. New primitives / findings this pass (not previously documented)

1. **`/dev/cli` is shell-openable — refutation confirmed and characterised.** `O_RDWR` open succeeds
   (twice, independent commands). A `read()` is *not* supported by the driver:
   `timeout 3 dd if=/dev/cli bs=1 count=8` → `dd: /dev/cli: Invalid argument` / `0+0 records in`.
   `ioctl` behaviour could **not** be characterised from the shell: the shell toolset has **no ioctl
   primitive** (toybox applets present exclude `stty`, `ioctl`, `devmem`; `stty` is `not found`;
   `nc` applet exists but is IP-only). This is a hard gap that needs a purpose-built helper (the
   existing `cli_arm` / `cli2_arm` in `/data/local/tmp`, or the pulled `cli`/`cli_shell` binaries in
   `tv-research/cli-re/`). What *is* measured: DAC allows shell rw by group, SELinux `cli_device`
   allows shell open (no AVC on our opens), and a root process named **`CLI` (pid 1032, uid 0)** is
   running — the daemon side exists.
2. **`fifo_dtv_write` located.** Path is **`/tmp/fifo_dtv_write`** (`dev="tmpfs"`, inode 10300,
   label `u:object_r:tmpfs:s0`, `tclass=fifo_file`). Existence was proven with a stat oracle on the
   execute-only `/tmp` (mode 1771, shell has `--x` not `r`): `ls /tmp/fifo_dtv_write` → EACCES
   (exists, getattr denied) while `ls /tmp/fifo_dtv_read`, `/dev/fifo_dtv_write`,
   `/dev/shm/fifo_dtv_write`, `/tmp/zzz_nonexistent` → ENOENT. All opens from shell are denied:
   `read`, `read write`, `write` AVCs (`sh` process, `scontext=u:r:shell:s0`). Same for
   `untrusted_app` (Lead's earlier AVC matches this inbound). The readers are root daemons started
   with `-input_fifo`: **`/basic/app_man -c /basic/am_config -s /basic/am_start.ini -input_fifo`**
   (pid 1484) and **`/basic/dtv_svc --am -input_fifo`** (pid 1499), both uid 0 in domain
   `u:r:mt_dtv-svc:s0`. It exists continuously (not only while a transient `ttyman` runs); `ttyman`
   itself was observed only transiently (pid 22406 cmdline match, gone seconds later).
   → direct shell→fifo write is a dead end, but the FIFO is the command channel of two root daemons —
   the payoff target after any domain pivot.
3. **`/data/anr` world-readable root/system traces** — see §2.1 (info leak, not write).
4. **`/dev/input/event0/1` are shell-RW** — new local primitive not in the earlier matrix:
   raw evdev access (read TV-remote/IR key events; ioctls like `EVIOCGRAB`/`EVIOCSKEYCODE` would
   need a helper). Low privesc value, useful for UI automation/keystroke capture.
5. **`/dev/alarm` and the second `/dev/mali0`-class node are RO-readable** (see §4) — minor.
6. **Root-daemon / domain inventory** (via `/proc/*/cmdline` + `/proc/*/attr/current`; `ps` itself hangs,
   so this was enumerated by reading `/proc` directly — 112 visible processes):
   `init` (u:r:init:s0), `vold`, `netd`, `zygote`, `healthd`, `lmkd`, `installd`, `storaged`,
   `/vendor/bin/k2logcat`, `MtkRmServer` (u:r:mt_mtk_rm:s0), `dmsdeweydaemon`, `telepathydaemon`
   (u:r:telepathy:s0), `magicpacketseek` (u:r:magicpacketseek:s0), `itdplatformdaemon`
   (u:r:itdplatformdaemon:s0), `/basic/app_man` + `/basic/dtv_svc` (u:r:mt_dtv-svc:s0),
   `/system/bin/vndservicemanager`, HAL services. Also `com.pwn.probe` (pid 21158) runs with
   **uid 0 but domain `u:r:untrusted_app:s0:c512,c768`** — i.e. the existing exploit payload has
   uid-0 but *not* a privileged SELinux domain; permissive-domain escalation is still required for
   file/device access. `mt_dtv-svc` itself was denied `module_load` at boot
   (`avc: denied { module_load } scontext=u:r:mt_dtv-svc:s0 tclass=system`) — module-loading is not
   an available path even for that vendor domain.
7. **SELinux fs**: only world-writable files on the whole sysfs are
   `/sys/fs/selinux/{access,context,create,member,relabel,user}` (0666); writing the query interface
   `/sys/fs/selinux/access` as shell returns EACCES (no `security_check_context` capability), so it
   cannot be used to test allow rules. `/sys/kernel/debug` (debugfs, mode 755) is **`ls: Permission denied`**
   to shell; `/proc/sys` contains no world-writable control at depth ≤3; `/proc/sys/kernel/{kptr_restrict,dmesg_restrict,randomize_va_space}` reads are DENIED, `perf_event_paranoid=3`, `panic_on_oops=1`.
   `/proc/kallsyms` is readable but all symbols are 0 (`00000000 T stext`) — kptr_restrict effective.
8. **`/proc` info leaks**: mount is `hidepid=2,gid=3009` and shell is in `readproc` → `/proc/<pid>/cmdline`
   and `/proc/<pid>/status` are readable for *all* processes (this is how the process inventory above
   was built; `ps` hangs and is unusable). `/proc/<pid>/{environ,maps,fd}` are DENIED even for our own
   uid shell (SELinux), so no environment/maps/fd leaks.
9. **`/dev/mem` / `/dev/kmem` confirmed absent** (`ENOENT` for `/dev/mem`, `/dev/kmem`, `/dev/kcore`,
   `/linux_rootfs/dev/mem`, `/linux_rootfs/dev/kmem`); **`mknod` confirmed EPERM** without writing
   anything: `mknod /data/local/tmp/__dsh_probe_node__ c 1 3` → `Operation not permitted`, and
   `ls` of the path afterwards → ENOENT (capability check precedes path creation, so nothing was
   created; `CapEff=0`, `CapBnd=0xc0` — no CAP_MKNOD). In non-writable dirs the error is EACCES first,
   which is why the writable-dir probe is the correct one. **`/proc/self/pagemap`** open is denied:
   `od: /proc/self/pagemap: Operation not permitted` (`dd: … Operation not permitted`), i.e. it is not
   "returns zeros" but "cannot be opened".

---

## 6. Corrections to prior assumptions

| prior assumption | corrected measurement |
|---|---|
| "shell is denied `/dev/cli`" | **wrong** — `OPEN_RW` works; the denial came from `untrusted_app` (probe APK) / from `ttyman_shell` failing later on a different object |
| "mediashell runs as AID_SYSTEM (uid 10000)" | **wrong** — `uid 10000` = app uid `u0_a0`; `AID_SYSTEM` = **1000**. mediashell domain is `priv_app`, not system. But note the DLNA module is **`sony_platform_app`** — a *more* privileged domain than both. |
| "`fifo_dtv_write` may be runtime-only / not found" | **located**: `/tmp/fifo_dtv_write`, exists now (persistent tmpfs inode 10300); transient processes are `ttyman`, not the FIFO |
| "/data/local/tmp is writable" | **confirmed** (`test -w`=W, `shell:shell 0771 shell_data_file`, on `nosuid` mount) |
| "/3rd_rw/tombstone is 0777 but SELinux-denied" | denial **confirmed** (`stat`→EACCES; AVC `denied { write } … tcontext=u:object_r:sony_tombstone_data_file:s0 tclass=dir`); the 0777 mode itself is **unverifiable from shell** because getattr is denied. DAC is not the blocker anyway. |
| "`/dev/mem`, `/dev/kmem` have no nodes" | **confirmed** (ENOENT, incl `/proc/kcore`) |
| "`mknod` is EPERM" | **confirmed** by a zero-side-effect capability probe (see §5.9) |
| "`/proc/self/pagemap` gives no data" | **refined**: `open()` itself is denied with `EPERM`/`Operation not permitted` (SELinux `ptrace`-class permission) |
| "`/dev/mali0` reachable, everything else mostly locked" | reachability set is slightly larger than listed: `+ /dev/input/event0,event1` (RW), `+ /dev/alarm`, `+ /linux_rootfs/dev/mali0` (RO). Everything vendor-specific remains denied. |

---

## 7. Ranked entry points (updated after this sweep)

1. **`/dev/mali0` (chr 10,51, 0666, `gpu_device`) — `OPEN_RW` from shell.** Already the project's
   working kernel primitive (KBASE ioctls verified — see `MALI-STATUS.md`); unchanged top rank.
   Siblings reachable with the same syscall surface, all `OPEN_RW`: **`/dev/ion`** (SELinux even logs
   `granted { write }` for shell→ion), **`/dev/ashmem`**, **`/dev/binder`**, **`/dev/hwbinder`**;
   `Seccomp=0` for shell, so raw syscalls are available. Kernel-CVE research already exists in
   `surface/kernel-cve-research.md`; `/dev/mali0` remains the best-supported bug.
2. **`/dev/cli` — shell-openable root CLI channel (chr 241,4, group shell → DAC rw, SELinux allows).**
   The only newly-confirmed *vendor-crafted* interface where shell was clearly intended to have
   access (group `shell`). Blocks: no ioctl tool in shell; protocol unknown → requires the `cli_arm`/
   `cli2_arm`/`cli`/`cli_shell` RE work (task‑3 / `tv-research/cli-re`). If the framing can be
   reconstructed, this is a direct path to a root `CLI` daemon; highest-value local remaining item.
3. **`/tmp/fifo_dtv_write`** — command FIFO of two root daemons (`/basic/app_man`, `/basic/dtv_svc`).
   All opens from shell/app are SELinux-denied today (read, write, rdwr AVCs recorded). Dead end from
   `shell`, but the payoff after any domain pivot (init/mt_* domain, or a root-uid+SELinux bypass). Keep
   as the post-exploitation command channel rather than an initial vector.
4. **Sony HueyModule UPnP/DLNA daemon (`sony_platform_app`, uid 10102), unauthenticated control
   endpoints** — the best *remote* surface found: preinstalled SYSTEM app, 4 exposed SOAP services,
   no auth, rich parsers (`AVTransport`, `RenderingControl`, `ConnectionManager` incl. `X_StartWFD`,
   `StreamSplicing`). State-changing actions exist (`SetAVTransportURI`, `Play/Stop/Seek`, …); no
   fuzzing was done (read-only mandate) — this is a Lead decision. A bug here yields
   `sony_platform_app` code execution, not root.
5. **`/data/anr` readable traces** — recon/ASLR/offset leak (63 process dumps incl. system_server and
   HALs). No write primitive (SELinux denies).
6. **`/dev/input/event0,event1` (RW)** — raw input read/injection with `getevent`/`input`; useful for
   UI automation/keystroke capture; low privesc value.
7. **`com.google.android.tv.remote.service` 6466/6467** (priv-app, `_androidtvremote._tcp`) — pairing
   protocol; unauthenticated TCP accept confirmed, TLS/handshake not standard; needs protocol work.
8. **`com.google.android.apps.mediashell` 8008/8443/9000/36266/36792** (priv_app, corrected from
   "AID_SYSTEM") — no unauthenticated HTTP API found; deprioritise.
9. **`/dev/xt_qtaguid` (RO), `/dev/alarm` (RO), `/dev/block/*` (locked), `/dev/cb*`, `/dev/eeprom*`** —
   read-only or fully denied; ioctl probing blocked by lack of a helper binary.
10. **Staging-only**: `/data/local/tmp` (writable but `nosuid`), `/sdcard` (`nosuid,nodev,noexec`),
    `/dev/usb-ffs` (shell-writable empty ffs dir).

---

## 8. Residual gaps / recommended next measurements

* **Definitive setuid sweep** needs a root context or offline squashfs mount: 60 `/system{,/vendor}/bin`
  entries + all `/linux_rootfs/{bin,sbin,basic}` files deny `getattr` to shell; `/perm`,`/sbin`,`/cache`,`/tmp`,`/3rd_rw`,`/data`(most) are unreadable entirely. (Appendix A.1 lists the 60 known-hidden paths with labels.)
* **`/dev/cli` ioctl matrix** (numbers, struct layouts, read/write semantics, blocking behaviour) —
  must be done with a helper binary; the `cli_arm`/`cli2_arm` + pulled `cli`/`cli_shell` artifacts
  already in the workspace are the right starting point (task‑3).
* **`/data`/`/cache` world-writable regular files** cannot be enumerated as shell; same root-side fix.
* **Unix-socket connectability/authorization** (`/tmp/DTVService`, `/tmp/MTKRMService`, `@jdwp-control`,
  `/dev/socket/*`) — needs a unix-socket client; shell toolset cannot connect.
* **UPnP state-changing actions** and any SOAP parser fuzzing — deliberately not exercised (read-only);
  `X_StartWFD` and `SetAVTransportURI` are the actions worth studying first.
* **`/dev/input` evdev ioctls** (`EVIOCGRAB`, keycode mapping) — helper needed.
* Host-side note: unicast SSDP M-SEARCH from the tailnet host got no reply this pass (multicast does not
  cross the tailnet); the DLNA description URL was confirmed over plain HTTP instead. If the exact
  SSDP `LOCATION` header is needed, capture it on the TV's LAN side or from the TV's own SSDP traffic
  (prior `surface/udp.log` has a Netflix `LOCATION: http://100.115.119.101:9080`).

---

## Appendix A — machine-generated tables

### A.1  Binaries whose metadata (mode/owner) shell cannot read (`getattr` denied by SELinux)

Measured via AVC capture while running `ls -la` / `find -perm` as uid 2000. Any `find -perm -4000` sweep silently skips these paths, so they are the blind spot of a shell-only setuid sweep. **60** such paths:

| path | SELinux label (from AVC tcontext) |
|---|---|
| /system/bin/audioserver | u:object_r:audioserver_exec:s0 |
| /system/bin/blkid | u:object_r:blkid_exec:s0 |
| /system/bin/bootanimation | u:object_r:bootanim_exec:s0 |
| /system/bin/bootstat | u:object_r:bootstat_exec:s0 |
| /system/bin/cameraserver | u:object_r:cameraserver_exec:s0 |
| /system/bin/clatd | u:object_r:clatd_exec:s0 |
| /system/bin/dexoptanalyzer | u:object_r:dexoptanalyzer_exec:s0 |
| /system/bin/dnsmasq | u:object_r:dnsmasq_exec:s0 |
| /system/bin/drmserver | u:object_r:drmserver_exec:s0 |
| /system/bin/dumpstate | u:object_r:dumpstate_exec:s0 |
| /system/bin/e2fsck | u:object_r:fsck_exec:s0 |
| /system/bin/fsck_msdos | u:object_r:fsck_exec:s0 |
| /system/bin/fsck.f2fs | u:object_r:fsck_exec:s0 |
| /system/bin/gatekeeperd | u:object_r:gatekeeperd_exec:s0 |
| /system/bin/healthd | u:object_r:healthd_exec:s0 |
| /system/bin/hw/android.hidl.allocator@1.0-service | u:object_r:hal_allocator_default_exec:s0 |
| /system/bin/hwservicemanager | u:object_r:hwservicemanager_exec:s0 |
| /system/bin/idmap | u:object_r:idmap_exec:s0 |
| /system/bin/incidentd | u:object_r:incidentd_exec:s0 |
| /system/bin/installd | u:object_r:installd_exec:s0 |
| /system/bin/interactivetvutil | u:object_r:interactivetvutil_exec:s0 |
| /system/bin/keystore | u:object_r:keystore_exec:s0 |
| /system/bin/lmkd | u:object_r:lmkd_exec:s0 |
| /system/bin/logd | u:object_r:logd_exec:s0 |
| /system/bin/mdnsd | u:object_r:mdnsd_exec:s0 |
| /system/bin/mediadrmserver | u:object_r:mediadrmserver_exec:s0 |
| /system/bin/mediaextractor | u:object_r:mediaextractor_exec:s0 |
| /system/bin/mediametrics | u:object_r:mediametrics_exec:s0 |
| /system/bin/mediaserver | u:object_r:mediaserver_exec:s0 |
| /system/bin/mtpd | u:object_r:mtp_exec:s0 |
| /system/bin/netd | u:object_r:netd_exec:s0 |
| /system/bin/pppd | u:object_r:ppp_exec:s0 |
| /system/bin/profman | u:object_r:profman_exec:s0 |
| /system/bin/racoon | u:object_r:racoon_exec:s0 |
| /system/bin/sdcard | u:object_r:sdcardd_exec:s0 |
| /system/bin/servicemanager | u:object_r:servicemanager_exec:s0 |
| /system/bin/sgdisk | u:object_r:sgdisk_exec:s0 |
| /system/bin/storaged | u:object_r:storaged_exec:s0 |
| /system/bin/surfaceflinger | u:object_r:surfaceflinger_exec:s0 |
| /system/bin/tombstoned | u:object_r:tombstoned_exec:s0 |
| /system/bin/tune2fs | u:object_r:fsck_exec:s0 |
| /system/vendor/bin/camera_recognition_daemon | u:object_r:camera_recognition_exec:s0 |
| /system/vendor/bin/dmsdeweydaemon | u:object_r:dtcp_exec:s0 |
| /system/vendor/bin/init_sony_ko.sh | u:object_r:sony_ko_exec:s0 |
| /system/vendor/bin/itdplatformdaemon | u:object_r:itdplatformdaemon_exec:s0 |
| /system/vendor/bin/iwpriv | u:object_r:mt_wifi_set_exec:s0 |
| /system/vendor/bin/iwpriv_wifi_operation | u:object_r:mt_iwpriv_wifi_oper_exec:s0 |
| /system/vendor/bin/kyildm | u:object_r:kyil_exec:s0 |
| /system/vendor/bin/magicpacketseek | u:object_r:magicpacketseek_exec:s0 |
| /system/vendor/bin/MtkRmServer | u:object_r:mt_mtk_rm_exec:s0 |
| /system/vendor/bin/nginx | u:object_r:nginx_exec:s0 |
| /system/vendor/bin/restart_wifi.sh | u:object_r:mt_restart_wifi_exec:s0 |
| /system/vendor/bin/sony_input_manager | u:object_r:sony_input_manager_exec:s0 |
| /system/vendor/bin/telepathydaemon | u:object_r:telepathy_exec:s0 |
| /system/vendor/bin/update_linux_network | u:object_r:mt_updatedns_exec:s0 |
| /system/vendor/bin/updown_wlan.sh | u:object_r:mt_updown_wlan_exec:s0 |
| /system/vendor/bin/wifi_fw_check | u:object_r:mt_wifi_fw_check_exec:s0 |
| /system/vendor/bin/wifi_set.sh | u:object_r:mt_wifi_set_exec:s0 |
| /system/vendor/bin/wowl_off.sh | u:object_r:mt_wowl_exec:s0 |
| /system/vendor/bin/wowl_on.sh | u:object_r:mt_wowl_exec:s0 |

### A.2  Measured open() reachability matrix (uid 2000 shell, SELinux Enforcing)

Method: subshell `( exec 3<>"$p" ) 2>&1` for O_RDWR, then `( exec 3<"$p" )` for O_RDONLY; failure text captured. OPEN_RW = O_RDWR open succeeded; OPEN_RO = O_RDONLY open succeeded; DENIED = both failed.

| path | result | error/notes |
|---|---|---|
| /dev/null | OPEN_RW |  |
| /dev/zero | OPEN_RW |  |
| /dev/full | DENIED | [/system/bin/sh: can't create /dev/full: Permission denied] / [/system/bin/sh: can't open /dev/full: Permission denied] |
| /dev/random | OPEN_RW |  |
| /dev/urandom | OPEN_RW |  |
| /dev/ptmx | OPEN_RW |  |
| /dev/tty | DENIED | [/system/bin/sh: can't create /dev/tty: No such device or address] / [/system/bin/sh: can't open /dev/tty: No such device or address] |
| /dev/console | DENIED | [/system/bin/sh: can't create /dev/console: Permission denied] / [/system/bin/sh: can't open /dev/console: Permission denied] |
| /dev/kmsg | DENIED | [/system/bin/sh: can't create /dev/kmsg: Permission denied] / [/system/bin/sh: can't open /dev/kmsg: Permission denied] |
| /dev/pmsg0 | DENIED | [/system/bin/sh: can't create /dev/pmsg0: Permission denied] / [/system/bin/sh: can't open /dev/pmsg0: Permission denied] |
| /dev/ashmem | OPEN_RW |  |
| /dev/binder | OPEN_RW |  |
| /dev/hwbinder | OPEN_RW |  |
| /dev/vndbinder | DENIED | [/system/bin/sh: can't create /dev/vndbinder: Permission denied] / [/system/bin/sh: can't open /dev/vndbinder: Permission denied] |
| /dev/ion | OPEN_RW |  |
| /dev/mali0 | OPEN_RW |  |
| /dev/kmem2 | DENIED | [/system/bin/sh: can't create /dev/kmem2: Permission denied] / [/system/bin/sh: can't open /dev/kmem2: Permission denied] |
| /dev/cli | OPEN_RW |  |
| /dev/cb | DENIED | [/system/bin/sh: can't create /dev/cb: Permission denied] / [/system/bin/sh: can't open /dev/cb: Permission denied] |
| /dev/cb2 | DENIED | [/system/bin/sh: can't create /dev/cb2: Permission denied] / [/system/bin/sh: can't open /dev/cb2: Permission denied] |
| /dev/cb_system | DENIED | [/system/bin/sh: can't create /dev/cb_system: Permission denied] / [/system/bin/sh: can't open /dev/cb_system: Permission denied] |
| /dev/xt_qtaguid | OPEN_RO |  |
| /dev/alarm | OPEN_RO |  |
| /dev/rtc0 | DENIED | [/system/bin/sh: can't create /dev/rtc0: Permission denied] / [/system/bin/sh: can't open /dev/rtc0: Permission denied] |
| /dev/tun | DENIED | [/system/bin/sh: can't create /dev/tun: Permission denied] / [/system/bin/sh: can't open /dev/tun: Permission denied] |
| /dev/ppp | DENIED | [/system/bin/sh: can't create /dev/ppp: Permission denied] / [/system/bin/sh: can't open /dev/ppp: Permission denied] |
| /dev/uhid | DENIED | [/system/bin/sh: can't create /dev/uhid: Permission denied] / [/system/bin/sh: can't open /dev/uhid: Permission denied] |
| /dev/uinput | DENIED | [/system/bin/sh: can't create /dev/uinput: Permission denied] / [/system/bin/sh: can't open /dev/uinput: Permission denied] |
| /dev/rfkill | DENIED | [/system/bin/sh: can't create /dev/rfkill: Permission denied] / [/system/bin/sh: can't open /dev/rfkill: Permission denied] |
| /dev/cpu_dma_latency | DENIED | [/system/bin/sh: can't create /dev/cpu_dma_latency: Permission denied] / [/system/bin/sh: can't open /dev/cpu_dma_latency: Permission denied] |
| /dev/network_latency | DENIED | [/system/bin/sh: can't create /dev/network_latency: Permission denied] / [/system/bin/sh: can't open /dev/network_latency: Permission denied] |
| /dev/network_throughput | DENIED | [/system/bin/sh: can't create /dev/network_throughput: Permission denied] / [/system/bin/sh: can't open /dev/network_throughput: Permission denied] |
| /dev/loop-control | DENIED | [/system/bin/sh: can't create /dev/loop-control: Permission denied] / [/system/bin/sh: can't open /dev/loop-control: Permission denied] |
| /dev/device-mapper | DENIED | [/system/bin/sh: can't create /dev/device-mapper: Permission denied] / [/system/bin/sh: can't open /dev/device-mapper: Permission denied] |
| /dev/fuse | DENIED | [/system/bin/sh: can't create /dev/fuse: Permission denied] / [/system/bin/sh: can't open /dev/fuse: Permission denied] |
| /dev/psaux | DENIED | [/system/bin/sh: can't create /dev/psaux: Permission denied] / [/system/bin/sh: can't open /dev/psaux: Permission denied] |
| /dev/vcs | DENIED | [/system/bin/sh: can't create /dev/vcs: Permission denied] / [/system/bin/sh: can't open /dev/vcs: Permission denied] |
| /dev/vcsa | DENIED | [/system/bin/sh: can't create /dev/vcsa: Permission denied] / [/system/bin/sh: can't open /dev/vcsa: Permission denied] |
| /dev/sw_sync | DENIED | [/system/bin/sh: can't create /dev/sw_sync: Permission denied] / [/system/bin/sh: can't open /dev/sw_sync: Permission denied] |
| /dev/stpbt | DENIED | [/system/bin/sh: can't create /dev/stpbt: Permission denied] / [/system/bin/sh: can't open /dev/stpbt: Permission denied] |
| /dev/graphics/fb0 | DENIED | [/system/bin/sh: can't create /dev/graphics/fb0: Permission denied] |
| /dev/graphics/fb1 | DENIED | [/system/bin/sh: can't create /dev/graphics/fb1: Permission denied] |
| /linux_rootfs/dev/b2r | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/b2r: Permission denied] |
| /linux_rootfs/dev/feeder | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/feeder: Permission denied] |
| /linux_rootfs/dev/mtal | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mtal: Permission denied] |
| /linux_rootfs/dev/mtal_system | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mtal_system: Permission denied] |
| /linux_rootfs/dev/rmmgr | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/rmmgr: Permission denied] |
| /linux_rootfs/dev/jpg | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/jpg: Permission denied] |
| /linux_rootfs/dev/tsrec | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/tsrec: Permission denied] |
| /linux_rootfs/dev/usb_cst | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/usb_cst: Permission denied] |
| /linux_rootfs/dev/eeprom_0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/eeprom_0: Permission denied] |
| /linux_rootfs/dev/eeprom_3 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/eeprom_3: Permission denied] |
| /linux_rootfs/dev/eeprom_4 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/eeprom_4: Permission denied] |
| /linux_rootfs/dev/video0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/video0: Permission denied] |
| /linux_rootfs/dev/video1 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/video1: Permission denied] |
| /linux_rootfs/dev/ttyGS0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/ttyGS0: Permission denied] |
| /linux_rootfs/dev/ttyMT0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/ttyMT0: Permission denied] |
| /linux_rootfs/dev/fb0_system | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fb0_system: Permission denied] |
| /linux_rootfs/dev/adecomx | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/adecomx: Permission denied] |
| /linux_rootfs/dev/vdecomx | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/vdecomx: Permission denied] |
| /linux_rootfs/dev/vdpomx | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/vdpomx: Permission denied] |
| /linux_rootfs/dev/vencomx | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/vencomx: Permission denied] |
| /linux_rootfs/dev/fbm_rest_mem | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_rest_mem: Permission denied] |
| /linux_rootfs/dev/fbm_b2r | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_b2r: Permission denied] |
| /linux_rootfs/dev/fbm_dmx | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_dmx: Permission denied] |
| /linux_rootfs/dev/fbm_feeder | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_feeder: Permission denied] |
| /linux_rootfs/dev/fbm_mpeg | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_mpeg: Permission denied] |
| /linux_rootfs/dev/fbm_mpeg_c | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_mpeg_c: Permission denied] |
| /linux_rootfs/dev/fbm_venc | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_venc: Permission denied] |
| /linux_rootfs/dev/fbm_jpg_vdp | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/fbm_jpg_vdp: Permission denied] |
| /linux_rootfs/dev/mali0 | OPEN_RO |  |
| /linux_rootfs/dev/mmcblk0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0: Permission denied] |
| /linux_rootfs/dev/mmcblk0p3 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p3: Permission denied] |
| /linux_rootfs/dev/mmcblk0p15 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p15: Permission denied] |
| /linux_rootfs/dev/mmcblk0p18 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p18: Permission denied] |
| /linux_rootfs/dev/mmcblk0p41 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p41: Permission denied] |
| /linux_rootfs/dev/mmcblk0p44 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p44: Permission denied] |
| /linux_rootfs/dev/mmcblk0p45 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p45: Permission denied] |
| /linux_rootfs/dev/mmcblk0p46 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/mmcblk0p46: Permission denied] |
| /linux_rootfs/dev/zram0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/zram0: Permission denied] |
| /linux_rootfs/dev/loop0 | DENIED | [/system/bin/sh: can't create /linux_rootfs/dev/loop0: Permission denied] |
| /dev/block/mmcblk0p3 | DENIED | [/system/bin/sh: can't create /dev/block/mmcblk0p3: Permission denied] |
| /dev/block/mmcblk0p15 | DENIED | [/system/bin/sh: can't create /dev/block/mmcblk0p15: Permission denied] |
| /dev/block/mmcblk0 | DENIED | [/system/bin/sh: can't create /dev/block/mmcblk0: Permission denied] |
| /dev/block/dm-0 | DENIED | [/system/bin/sh: can't create /dev/block/dm-0: Permission denied] |

Extra single-node probes (same method): /dev/mixer DENIED; /dev/ir DENIED; /dev/fusion0,/dev/fusion1 DENIED; /dev/tsrec DENIED; /dev/graphics/fb0 DENIED; /dev/snd/controlC0 DENIED; /dev/usb_cst DENIED; /dev/input/event0 OPEN_RW; /dev/input/event1 OPEN_RW; /dev/full DENIED (mode 0666, `full_device`); /linux_rootfs/dev/mali0 OPEN_RO.

### A.3  TCP/UDP sockets (uid -> package, SELinux domain)

Source: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` decoded from hex; uid mapped via ``pm list packages -U``; domain from ``/proc/<pid>/attr/current``.

| proto | local address | state | uid | package(s) | domain |
|---|---|---|---|---|---|
| TCP | 100.70.99.3:41824 | LISTEN | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| TCP | 100.70.99.3:52323 | LISTEN | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| TCP | 0.0.0.0:9080 | LISTEN | 10143 | com.netflix.ninja | untrusted_app |
| TCP | 100.70.99.3:55839 | LISTEN | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| TCP6 | 00000000000000000000000000000000:6466 | LISTEN | 10002 | com.google.android.tv.remote.service | n/a |
| TCP6 | 00000000000000000000000000000000:6467 | LISTEN | 10002 | com.google.android.tv.remote.service | n/a |
| TCP6 | 00000000000000000000000000000000:8008 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 00000000000000000000000000000000:9000 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 00000000000000000000000000000000:36266 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 00000000000000000000000000000000:5555 | LISTEN | 2000 | com.google.android.tv.bugreportsender, com.android.shell | shell (adbd) |
| TCP6 | 00000000000000000000000000000000:36792 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 0000000000000000FFFF00000100007F:10042 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 0000000000000000FFFF00000100007F:10042 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| TCP6 | 00000000000000000000000000000000:8443 | LISTEN | 10000 | com.google.android.apps.mediashell | priv_app |
| UDP | 0.0.0.0:55299 | bound | 10000 | com.google.android.apps.mediashell | priv_app |
| UDP | 100.70.99.3:68 | bound | 1000 | com.android.tv.settings, com.sony.dtv.audiooutput, com.sony.dtv.uinputservice, com.sony.dtv.usbmsgservice, com.mediatek.agent, com.sony.dtv.preinappfiltering, com.sony.dtv.broadcasttimezonereceiver, android, com.sony.dtv.networkapp.wifidirect, com.sony.dtv.netproxyservice, com.sony.dtv.browser.webappservice, com.sony.dtv.interactivetvutil.output, com.sony.dtv.magicpacketnotifyservice, com.android.providers.settings, com.android.inputdevices, com.sony.dtv.countrysetting, com.android.keychain, com.sony.dtv.base.basicosd, com.sony.dtv.configsettings, com.sony.dtv.b2b.prosettings, com.sony.dtv.b2b.importexport, com.sony.dtv.keepsleepserviceforwolna, com.sony.dtv.ledservice, com.sony.dtv.braviabluetoothservice, com.sony.dtv.settingsprovider, com.mediatek.dmagent, com.android.wallpaperbackup, com.sony.dtv.remotecontrolsettings, com.sony.dtv.da.service, com.android.location.fused, com.sony.dtv.networksettings | system-ish |
| UDP | 0.0.0.0:57434 | bound | 1020 |  | n/a (mdnsd) |
| UDP | 100.70.99.3:52323 | bound | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| UDP | 127.0.0.1:38763 | bound | 10000 | com.google.android.apps.mediashell | priv_app |
| UDP | 0.0.0.0:1900 | bound | 10143 | com.netflix.ninja | untrusted_app |
| UDP | 0.0.0.0:1900 | bound | 10000 | com.google.android.apps.mediashell | priv_app |
| UDP | 239.255.255.250:1900 | bound | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| UDP | 239.255.255.250:1900 | bound | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| UDP | 100.70.99.3:58242 | bound | 10143 | com.netflix.ninja | untrusted_app |
| UDP | 100.70.99.3:49036 | bound | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| UDP | 100.115.119.101:44703 | bound | 10143 | com.netflix.ninja | untrusted_app |
| UDP | 0.0.0.0:58321 | bound | 10170 | com.tailscale.ipn | untrusted_app |
| UDP | 0.0.0.0:5353 | bound | 1020 |  | n/a (mdnsd) |
| UDP | 0.0.0.0:46833 | bound | 10102 | com.sony.huey.dlna.module | sony_platform_app |
| UDP6 | 00000000000000000000000000000000:56167 | bound | 10170 | com.tailscale.ipn | untrusted_app |
| UDP6 | 00000000000000000000000000000000:1900 | bound | 10000 | com.google.android.apps.mediashell | priv_app |
| UDP6 | 00000000000000000000000000000000:56552 | bound | 1020 |  | n/a (mdnsd) |
| UDP6 | 00000000000000000000000000000000:5353 | bound | 1020 |  | n/a (mdnsd) |
| UDP6 | 00000000000000000000000000000000:5353 | bound | 1020 |  | n/a (mdnsd) |

### A.4  Unix-domain sockets (paths present in /proc/net/unix)

`/tmp/DTVService`, `/tmp/MTKRMService`, `/tmp/DFBInput`, `/tmp/dtcp_server`, `/tmp/audio-output-service` (abstract: displayed as @/tmp/audio-output-service), `/tmp/mixer-service` (abstract), `@jdwp-control` (abstract), `/data/system/ndebugsocket`, and `/dev/socket/{logd,logdr,logdw,adbd,webview_zygote,mdnsd,tombstoned_crash,tombstoned_intercept,property_service,vold,cryptd,netd,dnsproxyd,mdns,fwmarkd,zygote,lmkd,wpa_wlan0}` + wifi sockets `/data/misc/wifi/sockets/{wlan0,p2p0}`. Readdir of `/dev/socket` succeeds (18 names) but every `lstat` is SELinux-denied to shell; connect() was not tested (no unix-socket client available to shell; `toybox nc` supports only IP).

