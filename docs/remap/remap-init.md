# Init / service remap — Sony XBR-65X850D (`SVP-DTV15`, MediaTek MT5890, Android 8.0.0)

**Target:** `adb -s 100.70.99.3:5555` — `uid=2000(shell)`, context `u:r:shell:s0`, SELinux `Enforcing`,
`ro.build.type=user`, `ro.debuggable=0`, `ro.secure=1`.
**Build:** `Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/OPR2.170623.027.S16/6.827:user/release-keys`.
**Kernel:** `3.10.79 #1 SMP PREEMPT Wed Mar 4 17:00:38 JST 2020 armv7l`.
**Access rules honoured:** read-only on device (`ls/cat/grep/stat/getprop/mount/logcat -d/ps` only).
No property set, no service start/stop, no reboot, no writes to `/data`, `/cache`, `/tmp` or anywhere else.
**Everything below was re-derived from this device in this session.** Prior reports were read only as
pointers to what to check, then verified/refuted against fresh output. Where a fact is inherited rather
than re-measured it is explicitly marked *(inherited, not re-measured)*.

---

## 0. Executive summary

1. The **readable init graph is fully mapped**: 78 service definitions live in
   `/vendor/etc/init/*.rc` (= `/odm/etc/init/*.rc`, same directory via symlink) and
   `/system/etc/init/*.rc`. **36 of them run as uid 0** — **23 with no `user=` line at all**
   (`b2bcmd_exp`, `b2bcmd_imp`, `bind_watchdog`, `dbgset3rd_set`, `dtdumpstate_a/b`, `mlog`,
   `setup_irq_debug`, `boottrace`, all 7 `dumpstate*`, `installd`, `lmkd`, `netd`, `uncrypt`,
   `setup-bcb`, `clear-bcb`, `vold`) **plus 13 with explicit `user root`** (`b2bcmd_er/fwwrite/
   fwcleanup/filewrite/fileread/td/te/dp`, `multiramoops`, `reverseproxy`, `telepathydaemon`,
   `dmsdeweydaemon`, `storaged`).
2. The **root `/init.rc` family (14 files) is not readable from uid 2000** (mode `0750 root:root`);
   21 additional services only exist in that unreadable graph. Their exec paths are recovered here
   from live processes, `/proc/*/cmdline`, SELinux contexts, `/proc/boottime` and the readable
   vendor scripts — each row carries a confidence marker.
3. **Five root-context executors read or execute from writable media** (the payload that matters):
   - **`dtv-svc` → `/vendor/bin/dtv_svc.sh` conditionally executes `/3rd_rw/sony/arib/etc/aribinit.sh`**
     — an executable on the **rw ext4 `/3rd_rw`** partition (dir owned by `system`, so uid 1000 can
     plant it). This is the one *root executable on writable storage* found in the init graph.
   - **`dtdumpstate_a/b` → `/vendor/bin/dtdumpstate` → `debugshcmd` `fork()`+`execvp()`** with work
     material under **`/3rd_rw/tombstone/bugreport/shell/`** (DAC `0777`, SELinux
     `sony_tombstone_data_file`).
   - **`b2bcmd_*` (10 root services)** consume **`/data/vendor/b2b/`** — directory `0755 system:system`,
     i.e. **writable by uid 1000** — and **`/tmp/odm/b2b/` (DAC 0777)**.
   - **`sony_version` (root sh script)** uses `/3rd_rw/sony/version/pkg_info.txt` (dir `system`-owned).
   - **`multiramoops` / `telepathydaemon`** use `/data/odm/*` (parent `0755 system:system`, replaceable
     by uid 1000) and **`dmsdeweydaemon`** uses `/3rd_rw/sony/dtcp` (`0770 root:oem_2902`).
4. **The only root service reachable from plain `adb shell` today is the dumpstate family**
   (`dumpstate`, `dumpstatez`, `dumpstatedt1`–`dt5`, `/system/etc/init/dumpstate.rc`). Its socket is
   `0660 shell log` and init's kernel log shows it being created; `dumpstate` runs `/system/bin/sh`
   as root. That is the chain already used by this project (sh page-cache patch + `adb bugreport`).
5. **No property trigger in the readable graph can be fired by shell or an ordinary app.** Every
   Sony trigger is on `sys.svp.*` / `persist.svp.*` → SELinux type `svp_prop`; prior work measured
   `u:r:shell`, `untrusted_app` and `zygote` all denied `property_service set`. One trigger is on a
   softer label (`persist.debug.atrace.boottrace=1`, `persist_debug_prop`) and is worth one cheap
   measurement.
6. **The 14 unreadable root `.rc` files can be reconstructed after the next reboot, read-only**:
   Android 8 init logs every command it runs together with the action name and `file:line`. Proven
   live on this device:

   ```
   10-18 16:24:44.704  0 0 I init : Command 'start dtdumpstate_a' action=sys.svp.dbg.dtdumpstate.a=*
                                      (/vendor/etc/init/dtdumpstate.rc:2) returned 0 took 7.69567ms.
   10-18 16:24:44.704  0 0 I init : Command 'start dtdumpstate_a' action=sys.svp.dbg.dtdumpstate.a=*
                                      (/odm/etc/init/dtdumpstate.rc:2) returned -1 took 0.016291ms.
   ```

   `logcat -b kernel -d | grep 'init    :'` captures this (it is the same channel the kernel-devices
   report already uses). The current buffer starts at 15:28 while boot was 15:08, so the boot-time
   actions have already rotated out — **grab it in the first minutes after the next boot** (see §12).

---

## 1. Sources, and what is / is not readable

### 1.1 Init configuration files present (complete inventory)

Root of the ramdisk (parsed by init as `init.rc` + imports):

| file | mode | readable by uid 2000 | note |
|---|---|---|---|
| `/init.rc` | `0750 root:root` | **no** (`cat: Permission denied`) | main graph |
| `/init.mt5890.rc` | `0750` | **no** | MT5890 platform graph |
| `/init.mtk_common.rc` | `0750` | **no** | MTK common (pre/post-init, mknod_util…) |
| `/init.mkn.rc` | `0750` | **no** | Sony "MKN" middleware graph (22.8 KB, largest custom file) |
| `/init.sakura.common.rc` | `0750` | **no** | Sakura/BE control |
| `/init.sakura.rc` | `0750` | **no** | |
| `/init.mt5890.usb.rc` | `0750` | **no** | |
| `/init.usb.rc`, `/init.usb.configfs.rc` | `0750` | **no** | AOSP usb |
| `/init.zygote32.rc` | `0750` | **no** | AOSP zygote |
| `/init.environ.rc` | `0750` | **no** | |
| `/init.recovery.mt5890.rc` | `0750` | **no** | recovery only |
| `/ueventd.rc`, `/ueventd.mt5890.rc` | `0754`/`0744` | **no** | ueventd rules |
| `/default.prop` | `0600 root:root` | **no** | |

Readable, fully captured in this session:

- `/vendor/etc/init/*.rc` — 32 files (this is also `/odm/etc/init/*.rc`; `/odm -> /vendor -> /system/vendor`)
- `/system/etc/init/*.rc` — 34 files
- `/vendor/etc/service/*.sh` (7 scripts), `/vendor/etc/script/*.sh` (6 scripts),
  `/vendor/etc/boot.conf`, `/vendor/etc/nginxconf/**`
- `/proc/boottime` (`0666`, world-readable **and writable**), `/proc/mounts`, `/plat_file_contexts`,
  `/nonplat_file_contexts`, `/plat_property_contexts`, `/nonplat_property_contexts`,
  `/plat_service_contexts`, `/nonplat_service_contexts`, `ps -Z`, `/proc/*/status|cmdline`
  (shell is in gid 3009 `readproc`, so `hidepid=2` does not hide pids), `logcat -b kernel -d`.

**No `hw/` sub-directory exists anywhere:** `/vendor/etc/init/hw`, `/odm/etc/init/hw`,
`/system/etc/init/hw` → `No such file or directory` (this is not an Android 11+ layout).
**No `exec_start` exists** — that verb was introduced in Android 9; Android 8.0 init only has
`exec - [seclabel] [user] [group] -- <cmd>` one-shots inside `on` actions (§7).

### 1.2 Readability limitation and how it is compensated

14 root `.rc` files and both `ueventd*.rc` are DAC-denied to uid 2000, so **the triggers and
services declared there cannot be enumerated statically from shell**. Compensation used here:

| evidence source | what it gives |
|---|---|
| `getprop \| grep init\.svc\.` | 72 service names + current state (`running`/`stopped`) |
| `ps -Z` | pid, uid, SELinux domain, name of every running service process |
| `/proc/<pid>/cmdline` | exact exec + argv of every running service |
| `/proc/boottime` | ordered boot log written by the vendor root scripts themselves |
| readable `/vendor/bin/*.sh`, `/vendor/etc/service/*.sh` | exact exec lines of several unreadable-graph services |
| `logcat -b kernel -d`, grep `init    :` | action→command mapping with rc `file:line` (works, but boot entries already rotated) |
| prior-session measurements *(inherited, not re-measured)* | `sys.svp.*` property write denials, `/3rd_rw/tombstone` write denials from shell/app/zygote |

### 1.3 Quirk discovered: every `/vendor/etc/init/*.rc` is parsed **twice**

`/odm` is a symlink to `/vendor`, so init loads the same 32 files once under
`/vendor/etc/init/` and once under `/odm/etc/init/`. Live init log proof (the second copy's command
returns `-1` because the service is already starting):

```
Command 'start dtdumpstate_a' action=sys.svp.dbg.dtdumpstate.a=* (/vendor/etc/init/dtdumpstate.rc:2) returned 0
Command 'start dtdumpstate_a' action=sys.svp.dbg.dtdumpstate.a=* (/odm/etc/init/dtdumpstate.rc:2)  returned -1
```

Consequences: all `on` actions from vendor rc are registered twice (second execution is a no-op
because `mkdir`/`start` target exists/already running), and duplicate service declarations are
rejected by init on the second pass. No security impact was found, but it means the vendor graph is
effectively "2× actions"; do not treat the duplicate `-1` as errors in future kernel-log analysis.

---

## 2. Boot graph

### 2.1 Ordered boot evidence (`/proc/boottime`, written by the scripts themselves)

```
10154 ms  ==> mknod_util start          10187 ms  ==> mknod_util end
10396 ms  insmod_dtv_driver_ko_start   10910 ms  insmod_dtv_driver_ko_end
10996 ms  insmod_fusion_ko_start       11011 ms  insmod_fusion_ko_end
11631 ms  mtk_rm_start !!!!            11631 ms  mtk_rm_end !!!!
11656 ms  ==> dtv_svc start            16727 ms  ==> dtv_svc end
15401 ms  pre-init: end
15482 ms  rc.local begin               15860 ms  rc.local.partial done
16305 ms  fusion.ko done               16321 ms  mount_3rd_ro.sh
16331 ms  mount_3rd.sh                 16496 ms  autorun.sh
16543 ms  rc.local done
27302 ms  dtv_svc_is_ready
111240 ms [JJ] c_svctx_select_svc
```

This chain is the **Linux/"two-worlds" TV middleware start-up**, all as uid 0, and mostly declared in
the unreadable `/init.mtk_common.rc` / `/init.mkn.rc`:

- `mknod_util` — creates device nodes in `/dev`, then `touch /tmp/mknod_util_end`
  (`/tmp/mknod_util_end` has its own SELinux type `mt_tmp`, evidence it is an inter-service flag).
- `insmod_dtv_driver_ko`, `insmod_fusion_ko` — `insmod` of `/basic/*.ko` (squashfs ro).
- `mtk-rm` — `/vendor/bin/mtk_rm.sh` (readable) → launches `/vendor/bin/MtkRmServer &`,
  `echo $! > /tmp/rm_pid`, `touch /tmp/mtk_rm_end`.
- `dtv-svc` — `/vendor/bin/dtv_svc.sh` (readable) → `sh /etc/rc.d/rc.local` (resolves through
  `/system/etc/rc.d -> /linux_rootfs/etc/rc.d`, ro), `setup_zram.sh`, then the **ARIB branch** (§5.4).
- `pre-init` — `/vendor/etc/service/pre-init.sh`; `post-init` — `post-init.sh`.
- `rc.local` (Linux rootfs, ro) runs `rc.local.partial`, `fusion.ko`, `mount_3rd_ro.sh`,
  `mount_3rd.sh`, `autorun.sh` — this is what launches the root TV stack processes
  **outside init's supervision** (§4.3).

### 2.2 Root processes that are **not** init services (important)

`app_man` (pid 1484), its child `dtv_svc` (pid 1499) and `MtkRmServer` (pid 1187) all have **ppid 1
but no `init.svc.<name>` property**: they are forked and backgrounded from `dtv_svc.sh` /
`mtk_rm.sh` / Linux `rc.local`, then orphaned. init does not supervise or respawn them.

| process | pid | uid/gid | domain | evidence |
|---|---|---|---|---|
| `/basic/app_man -c /basic/am_config -s /basic/am_start.ini -input_fifo` | 1484 | 0 / 0 | `u:r:mt_dtv-svc:s0` | cmdline, `/proc/1484/new/status`=uid 0 |
| `/basic/dtv_svc --am -input_fifo` | 1499 | 0 / 0 | `u:r:mt_dtv-svc:s0` | child of 1484 |
| `/vendor/bin/MtkRmServer` | 1187 | 0 / gid 3009 | `u:r:mt_mtk_rm:s0` | started by `mtk_rm.sh` |

They consume unix sockets/FIFOs in `/tmp` (`/tmp/DTVService`, `/tmp/dtv_svc_application_ipc`,
`/tmp/fifo_dtv_write`, `/tmp/MTKRMService` — from `/proc/net/unix` + AVC) and are root with full
capability sets *(capability values inherited from docs/08, not re-measured)*.

---

## 3. Complete service map

### 3.1 Services declared in the **readable** rc files (78 definitions)

Legend: `user` column `**root**` = **uid 0** — either the `user=` line is absent (the critical case:
absent `user=` means root) or it reads `user root`. `state` = runtime state from `init.svc.*`.
Full exec paths unchanged. All are `disabled` only where noted.

#### `/vendor/etc/init/` (39 definitions)

| service | exec (+args) | user | group / class / flags | runtime domain | state |
|---|---|---|---|---|---|
| audio-hal-2-0 | `/vendor/bin/hw/android.hardware.audio@2.0-service-mediatek` | audioserver | audio camera drmrpc inet media mediadrm net_bt net_bt_admin net_bw_acct system; class hal; oneshot; ioprio rt 4 | `hal_audio_mediatek_tv` | running |
| bluetooth-1-0 | `/vendor/bin/hw/android.hardware.bluetooth@1.0-service` | bluetooth | bluetooth; class hal | `hal_bluetooth_default` | running |
| camera-provider-2-4 | `/vendor/bin/hw/android.hardware.camera.provider@2.4-service` | cameraserver | audio camera input drmrpc oem_2901; class hal; capabilities SYS_NICE | `hal_camera_default` | running |
| configstore-hal-1-0 | `…/android.hardware.configstore@1.0-service` | system | system; class hal animation | `hal_configstore_default` | running |
| drm-hal-1-0 | `…/android.hardware.drm@1.0-service` | media | mediadrm drmrpc oem_2901; hal | `hal_drm_default` | running |
| drm-widevine-hal-1-0 | `…/android.hardware.drm@1.0-service.widevine` | media | media mediadrm drmrpc oem_2901; hal | `hal_drm_widevine` | running |
| gralloc-2-0 | `…/graphics.allocator@2.0-service` | system | graphics drmrpc; SYS_NICE; onrestart restart surfaceflinger | `hal_graphics_allocator_default` | running |
| hwcomposer-2-1 | `…/graphics.composer@2.1-service` | system | graphics drmrpc; SYS_NICE | `hal_graphics_composer_default` | running |
| health-hal-1-0 | `…/android.hardware.health@1.0-service` | system | system; hal | `hal_health_default` | running |
| keymaster-3-0 | `…/android.hardware.keymaster@3.0-service` | system | system drmrpc; class early_hal | `hal_keymaster_default` | running |
| mediacodec | `…/android.hardware.media.omx@1.0-service` | mediacodec | camera drmrpc mediadrm oem_2901; class main; ioprio rt | `mediacodec` | running |
| power-hal-1-0 | `…/android.hardware.power@1.0-service` | system | system; hal | `hal_power_default` | running |
| cec-hal-1-0 | `…/android.hardware.tv.cec@1.0-service` | system | system; hal | `hal_tv_cec_default` | running |
| tv-input-1-0 | `/vendor/bin/hw/android.hardware.tv.input@1.0-service-mediatek` | system | system; hal | — | no `init.svc` prop (not started; `ITvInput/default` is served from pid 1463 `system_server`) |
| **b2bcmd_er** | `/system/vendor/bin/b2bcmd eeprom_read` | **root** | system oem_2901 media_rw log; class main; disabled; oneshot | `b2bcmd` (never observed running) | stopped |
| **b2bcmd_fwwrite** | `b2bcmd fwwrite_prepare` | **root** | same | `b2bcmd` | stopped |
| **b2bcmd_fwcleanup** | `b2bcmd filewrite_cleanup` | **root** | same | `b2bcmd` | stopped |
| **b2bcmd_filewrite** | `b2bcmd filewrite_prepare` | **root** | same | `b2bcmd` | stopped |
| **b2bcmd_fileread** | `b2bcmd fileread_prepare` | **root** | same | `b2bcmd` | stopped |
| **b2bcmd_exp** | `b2bcmd export_start` | **root** (no `user=`) | system sdcard_rw oem_2901 media_rw log; disabled; oneshot | `b2bcmd` | stopped |
| **b2bcmd_imp** | `b2bcmd import_start` | **root** (no `user=`) | same | `b2bcmd` | stopped |
| **b2bcmd_td** | `b2bcmd tuner_disable` | **root** | system sdcard_r sdcard_rw oem_2901 media_rw log | `b2bcmd` | stopped |
| **b2bcmd_te** | `b2bcmd tuner_enable` | **root** | same | `b2bcmd` | stopped |
| **b2bcmd_dp** | `b2bcmd decrypt_phrase` | **root** | system oem_2901 media_rw log | `b2bcmd` | stopped |
| **bind_watchdog** | `/system/bin/sh /odm/etc/service/bind_watchdog.sh` | **root** | root readproc; console; oneshot; **seclabel `u:r:irq_debug:s0`** | `irq_debug` | stopped |
| **dbgset3rd_set** | `/odm/bin/debugsettings -d /storage/` | **root** | class main; disabled; oneshot; **seclabel `u:r:debugsettings:s0`** | `debugsettings` | stopped |
| **dtdumpstate_a** | `/vendor/bin/dtdumpstate -p A` | **root** | root shell log; class main; disabled; oneshot | `dtdumpstate` | stopped |
| **dtdumpstate_b** | `/vendor/bin/dtdumpstate -p B` | **root** | root shell log; class main; disabled; oneshot | `dtdumpstate` | stopped |
| dumpecsserver | `/odm/bin/dumpecsserver` | system | system oem_2901; class core | `dumpecsserver` | running |
| eepserver | `/system/vendor/bin/eepserver` | system | —; class core | `eepserver` | running |
| **mlog** | `/sbin/mlog -v printable` | **root** | class main; console; seclabel `u:r:mlog:s0` | `mlog` | no `init.svc.mlog` prop (never started this boot) |
| **multiramoops** | `/system/bin/sh /odm/etc/service/multiramoops.sh` | root | root log; class main; oneshot; seclabel `u:r:multiramoops:s0` | `multiramoops` | stopped |
| **reverseproxy** | `/vendor/bin/nginx -c /vendor/etc/nginxconf/nginx.conf` | root | oem_2900; class main; disabled | `nginx` | stopped (only on `sys.svp.reverseproxy.enable`) |
| setmviprop | `/system/vendor/bin/setmviprop` | system | class core; oneshot | `setmviprop` | stopped |
| **setup_irq_debug** | `/system/bin/sh /odm/etc/service/setup_irq_debug.sh` | **root** | root readproc; console; oneshot; seclabel `u:r:irq_debug:s0` | `irq_debug` | stopped |
| **telepathydaemon** | `/odm/bin/telepathydaemon` | root | oem_2901 system; class main | `telepathy` | running |
| pppoeproxy-hal-1-0 | `/vendor/bin/hw/vendor.mediatek.hardware.pppoeproxy@1.0-service` | system | system inet net_admin net_raw; hal animation | `hal_pppoeproxy_mediatek` | running |
| vndservicemanager | `/vendor/bin/vndservicemanager /dev/vndbinder` | system | system readproc; class core | `vndservicemanager` | running |

#### `/system/etc/init/` (39 definitions)

| service | exec (+args) | user | group / class / flags | runtime domain | state |
|---|---|---|---|---|---|
| hidl_memory | `/system/bin/hw/android.hidl.allocator@1.0-service` | system | system; hal | `hal_allocator_default` | running |
| **boottrace** | `/system/bin/atrace --async_start -f /data/misc/boottrace/categories` | **root** | disabled; oneshot | (not captured) | stopped |
| audioserver | `/system/bin/audioserver` | audioserver | audio camera drmrpc inet media mediadrm net_bt net_bt_admin net_bw_acct oem_2901; class main; onrestart restart audio-hal-2-0 | `audioserver` | running |
| bootanim | `/system/bin/bootanimation` | graphics | graphics audio oem_2901; class core animation; disabled; oneshot | — | stopped |
| camera_recognition_daemon | `/system/vendor/bin/camera_recognition_daemon` | system | system; class main | `camera_recognition` | running |
| cameraserver | `/system/bin/cameraserver` | cameraserver | audio camera input drmrpc oem_2901; class main | `cameraserver` | running |
| **dmsdeweydaemon** | `/vendor/bin/dmsdeweydaemon` | root | oem_2902 oem_2901 media wifi system; class main | `dtcp` | running |
| drm | `/system/bin/drmserver` | drm | drm system inet drmrpc readproc oem_2901; class main | `drmserver` | running |
| **dumpstate** | `/system/bin/dumpstate -s` | **root** | socket `dumpstate stream 0660 shell log`; class main; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatez** | `/system/bin/dumpstate -S -d -z -o /data/user_de/0/com.android.shell/files/bugreports/bugreport` | **root** | same socket; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatedt1** | `dumpstate -S -d -z -t 1 -o …/bugreports/bugreport` | **root** | root system; same socket; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatedt2** | `dumpstate -S -d -z -t 2 -o …` | **root** | root system; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatedt3** | `dumpstate -d -z -t 1 -o … -m` | **root** | root system; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatedt4** | `dumpstate -d -z -t 1 -e -o … -m` | **root** | root system; disabled; oneshot | `dumpstate` | stopped |
| **dumpstatedt5** | `/system/bin/dumpstate -L` | **root** | root system; disabled; oneshot | `dumpstate` | stopped |
| gatekeeperd | `/system/bin/gatekeeperd /data/misc/gatekeeper` | system | —; class late_start | `gatekeeperd` | running |
| hwservicemanager | `/system/bin/hwservicemanager` | system | system readproc; disabled; critical | `hwservicemanager` | running |
| **installd** | `/system/bin/installd` | **root** | class main | `installd` | running |
| keystore | `/system/bin/keystore /data/misc/keystore` | keystore | keystore drmrpc readproc; class main | `keystore` | running |
| **lmkd** | `/system/bin/lmkd` | **root** | root readproc; class core; critical; socket lmkd 0660 system system | `lmkd` | running |
| logd | `/system/bin/logd` | logd | logd system readproc; sockets logd/logdr/logdw; class (none) | `logd` | running |
| logd-reinit | `/system/bin/logd --reinit` | logd | oneshot; disabled | `logd` | stopped |
| mdnsd | `/system/bin/mdnsd` | mdnsr | inet; socket mdnsd 0660; disabled; oneshot | `mdnsd` | running |
| mediadrm | `/system/bin/mediadrmserver` | media | mediadrm drmrpc oem_2901; class main | `mediadrmserver` | running |
| mediaextractor | `/system/bin/mediaextractor` | mediaex | drmrpc mediadrm oem_2901; class main | `mediaextractor` | running |
| mediametrics | `/system/bin/mediametrics` | media | media; class main | `mediametrics` | running |
| media | `/system/bin/mediaserver` | media | audio camera inet net_bt net_bt_admin net_bw_acct drmrpc mediadrm oem_2902 oem_2901; class main | `mediaserver` | running |
| mtpd | `/system/bin/mtpd` | vpn | vpn inet; socket mtpd 600 system system; NET_ADMIN NET_RAW; disabled; oneshot | — | stopped |
| **netd** | `/system/bin/netd` | **root** | sockets netd/dnsproxyd/mdns/fwmarkd; class main | `netd` | running |
| racoon | `/system/bin/racoon` | vpn | vpn inet; socket racoon 600; disabled; oneshot | — | stopped |
| servicemanager | `/system/bin/servicemanager` | system | system readproc; class core animation; critical | `servicemanager` | running |
| storaged | `/system/bin/storaged` | root (explicit) | package_info; class main; priority 10; file /d/mmc0/mmc0:0001/ext_csd r | `storaged` | running |
| surfaceflinger | `/system/bin/surfaceflinger` | system | graphics drmrpc readproc oem_2901; class core animation; 3 pdx sockets 0666 | `surfaceflinger` | running |
| tombstoned | `/system/bin/tombstoned` | tombstoned | system; class late_start; 2 sockets 0666 | `tombstoned` | running |
| **uncrypt** | `/system/bin/uncrypt` | **root** | socket uncrypt 600; class main; disabled; oneshot | — | stopped |
| **setup-bcb** | `/system/bin/uncrypt --setup-bcb` | **root** | same; disabled; oneshot | — | stopped |
| **clear-bcb** | `/system/bin/uncrypt --clear-bcb` | **root** | same; disabled; oneshot | — | stopped |
| **vold** | `/system/bin/vold --blkid_context=… --fsck_context=…` | **root** | socket vold/cryptd 0660 root mount; class core; ioprio be 2 | `vold` | running |
| webview_zygote32 | `/system/bin/webview_zygote32` | webview_zygote | socket webview_zygote 660 webview_zygote system | `webview_zygote` | running |
| wificond | `/system/bin/wificond` | wifi | wifi net_raw net_admin; class main | `wificond` | running |

### 3.2 Services that exist **only** in the unreadable root graph (21, runtime-confirmed)

| service | `init.svc` | runtime pid / uid / domain | best-evidence exec | confidence |
|---|---|---|---|---|
| adbd | running | 1440 / 2000 / `u:r:adbd:s0` | `/sbin/adbd --root_seclabel=u:r:su:s0` | **confirmed** (cmdline) |
| console | running | 1156 / 2000 / `u:r:shell:s0` | `/system/bin/sh`; AOSP stock definition `user shell` | **confirmed** (pid, uid) |
| dtv-svc | stopped | — | `/system/bin/sh /vendor/bin/dtv_svc.sh` | high (boot log strings match the script byte-for-byte) |
| healthd | running | 1173 / 0 / `u:r:healthd:s0` | `/system/bin/healthd` | confirmed |
| insmod | stopped | — | `/system/bin/sh /vendor/etc/script/insmod.sh` | medium (name match; script fits the boot log `insmod_dtv_driver_ko*`) |
| interactivetv | running | 1191 / **2000 (gid 0)** / `u:r:interactivetvutil:s0` | `/system/bin/interactivetvutil` | **confirmed** (cmdline) |
| itdplatformd | running | 16201 / 0 / `u:r:itdplatformdaemon:s0` | `/system/vendor/bin/itdplatformdaemon` | confirmed |
| k2logcat | running | 1185 / 0 / `u:r:mt_k2logcat:s0` | `/vendor/bin/k2logcat` | confirmed |
| kyildm | running | 1193 / 1004 / `u:r:kyil:s0` | `/system/vendor/bin/kyildm` | confirmed |
| magicpacketseek | running | 1198 / 0 / `u:r:magicpacketseek:s0` | `/system/vendor/bin/magicpacketseek` | confirmed |
| mtk_rm | stopped | — | `/system/bin/sh /vendor/bin/mtk_rm.sh` | high (boot log strings match) |
| post-init | stopped | — | `/system/bin/sh /odm/etc/service/post-init.sh` | medium-high |
| post-init-cust | stopped | — | unknown; commented hint in post-init.sh: `/linux_rootfs/usr/bin/post_init_cust.sh` | low |
| pre-init | stopped | — | `/system/bin/sh /odm/etc/service/pre-init.sh` | high (boot log `pre-init: end` is this script's last line) |
| sony-version | stopped | — | `/system/bin/sh /odm/etc/service/sony_version.sh` | high (script writes `/proc/sony_version`, md5-style name match) |
| sony-ko | stopped | — | `/vendor/bin/init_sony_ko.sh` (label `sony_ko_exec`, unreadable) | medium-high |
| sonyinputmanager | running | 16110 / 1004 / `u:r:sony_input_manager:s0` | `/vendor/bin/sony_input_manager` | confirmed |
| ueventd | running | 721 / 0 / `u:r:ueventd:s0` | `/sbin/ueventd` | confirmed |
| updatedns | stopped | — | unknown (script/binary not on readable fs) | none |
| wpa_supplicant | running | 2188 / 1010 / `hal_wifi_supplicant_default` | `/vendor/bin/hw/wpa_supplicant -g@android:wpa_wlan0 … -c /data/misc/wifi/wpa_supplicant.conf` | confirmed |
| zygote | running | 1154 / 0 / `u:r:zygote:s0` | `/system/bin/app_process` (AOSP `init.zygote32.rc`) | confirmed |

**Gap (cannot be closed from userspace):** services that are declared in the unreadable root rc but
have *never* been started have no `init.svc.*` property and no process, so their names are unknown.
Executables with dedicated **service exec types** prove that some exist: see §3.3.

### 3.3 Root/service executables present but with no matching service in the readable graph

From `/nonplat_file_contexts` (`*_exec` types are only ever applied by init to a service/forked exec):

| path | SELinux exec type | running? | inference |
|---|---|---|---|
| `/system/vendor/bin/hw/com.sony.dtv.hardware.audio@1.0-service` | `hdmiaudio_exec` | no | Sony HDMI-audio HAL; root service defined in unreadable rc |
| `/system/vendor/bin/hw/com.sony.dtv.hardware.network@1.0-service` | `sony_network_exec` | no | Sony network HAL; same |
| `/vendor/bin/sony_be_wakelock` | `sony_be_wakelock_exec` | no | BE-control wakelock helper (root) |
| `/vendor/bin/sony_mainunitkey_manager` | `sony_mainunitkey_manager_exec` | no | backs binder `MainUnitKeyService`; started on demand |
| `/vendor/bin/dbus-daemon` | `dbus_daemon_exec` | no | Sony middleware d-bus; root or system |
| `/vendor/bin/init_sony_ko.sh` | `sony_ko_exec` | at boot only | service `sony-ko` |
| `/vendor/bin/MtkRmServer` | (unreadable, `MtkRmServer` stat denied) | yes | exec'd by `mtk_rm.sh` |
| `/vendor/bin/MtkRmInitServer` | `vendor_file` | no | wrapper that re-execs `MtkRmServer` and **reboots on crash** (`strings`: "MtkRmServer exit, going to reboot", `execv`, `reboot`) |

---

## 4. Root services that execute a script or interpreter — and where their input comes from
### (the core deliverable; answers "which ones did you not have")

`user` absent ⇒ uid 0. Note the distinction **uid 0 vs SELinux domain**: several of these are uid 0 but
confined to a bespoke domain, so they can do root-DAC operations only where their domain policy also
allows it.

### 4.1 Root shell/interpreter services from the **readable** graph

| service | uid / domain | interpreter + script (exact path) | script fs | data the script reads/writes | writable by non-root? |
|---|---|---|---|---|---|
| **bind_watchdog** | 0 / `u:r:irq_debug:s0` | `/system/bin/sh /odm/etc/service/bind_watchdog.sh` | `/system` squashfs **ro**, `vendor_configs_file` `0644 root:root` | `taskset -p 1 \`pgrep WatchDog\`` only | **no** |
| **setup_irq_debug** | 0 / `u:r:irq_debug:s0` | `/system/bin/sh /odm/etc/service/setup_irq_debug.sh` | ro | writes tracefs `events/irq/*`, `buffer_size_kb`, `trace_options` | **no** (tracefs is prod/debug, no attacker input) |
| **multiramoops** | 0 / `u:r:multiramoops:s0` | `/system/bin/sh /odm/etc/service/multiramoops.sh` | ro | reads `/sys/fs/pstore/console-ramoops*`; writes `/data/odm/dtbugreport/multiramoops/console-ramoops-NN`; then `setprop sys.svp.bugreport.multiramoops 1` → **starts root `dumpstatedt5`** | dir is `0755 root:root`, but **parent `/data/odm` is `0755 system:system`** (system-uid writable) → symlink swap of the whole subtree possible at next boot |
| **sony_version** | 0 / (root graph) | `/system/bin/sh /odm/etc/service/sony_version.sh` | ro | `DIR=/3rd_rw/sony/version`; reads+`>>`-appends `${DIR}/pkg_info.txt`; writes `/proc/sony_version` | **`/3rd_rw/sony` is `0755 system:system`** → uid 1000 can replace `version/` or `pkg_info.txt` with a **symlink**; root `>>` then follows it (fixed content: build date/fingerprint/pkg version/host) |
| **dtv-svc** | 0 / `u:r:mt_dtv-svc:s0` (boot, oneshot) | `/system/bin/sh /vendor/bin/dtv_svc.sh` | ro (`vendor_file`, but shell can read it) | **executes `sh /etc/rc.d/rc.local`** (`/system/etc/rc.d -> /linux_rootfs/etc/rc.d`, ro); `sh /system/vendor/etc/script/setup_zram.sh` (ro); **conditionally executes `${ARIB_BOOT}/sony/arib/etc/aribinit.sh -d` where `ARIB_BOOT` is read from `/3rd_rw/aribboot`**; `chmod 771 /tmp`; `chmod 666 /tmp/cacerts.pem` | **YES, conditionally: `/3rd_rw/sony` is uid-1000-writable and `/3rd_rw` is rw ext4.** See §5.1 |
| **mtk_rm** | 0 / (root graph) | `/system/bin/sh /vendor/bin/mtk_rm.sh` | ro | waits `/tmp/mknod_util_end`; runs `/vendor/bin/MtkRmServer &`; `echo $! > /tmp/rm_pid`; `touch /tmp/mtk_rm_end` | `/tmp` = `0771 root:system` → **not** shell-writable (verified `[ -w /tmp ]` = false) |
| pre-init | 0 / `u:r:mt_pre-init:s0` (AVC evidence) | `/system/bin/sh /odm/etc/service/pre-init.sh` | ro | sources `/vendor/etc/boot.conf` (ro); `setprop persist.mtk.printk_level`; writes `/proc/sys/kernel/printk`; optionally runs `set_eth0_mac.sh`; copies `media_codecs_*.xml` → `/tmp/media_codecs.xml`; `setprop sys.display-size` | no attacker-controlled input (boot.conf ro, cmdline inaccessible) |
| post-init | 0 / (root graph) | `/system/bin/sh /odm/etc/service/post-init.sh` | ro | sources boot.conf; `insmod musb_hdrc_u2.ko`; runs `/vendor/etc/script/adb_net.sh` or `adb_usb.sh` as root — **`setprop service.adb.tcp.port 5555; stop adbd; start adbd`**; `rm -f /*.ko`; `touch /tmp/android_boot_complete`; `/etc/service/rm_svc_chk.sh` does not exist on the Android root | no attacker-controlled input |
| sony-ko | 0 / (root graph) | `/vendor/bin/init_sony_ko.sh` | ro, **SELinux-denied to shell** | insmod of Sony `.ko`s | unknown (cannot read the script) |
| insmod | 0 / (root graph) | `/system/bin/sh /vendor/etc/script/insmod.sh` | ro | `insmod` ro modules; writes `${usbdev}/power/persist` under `/sys` | no |
| updatedns | 0 / (root graph) | unknown | — | (name suggests `/etc/resolv.conf` update; `/linux_rootfs/etc/resolv.conf -> /tmp/resolv.conf`) | `/tmp` not shell-writable |
| mknod_util | 0 / (root graph) | unknown script (boot log markers) | — | creates `/dev` nodes; `touch /tmp/mknod_util_end` | `/tmp` not shell-writable |
| rc.local chain | 0 | `sh /etc/rc.d/rc.local` → `/linux_rootfs/etc/rc.d/rc.local` | `/linux_rootfs` squashfs **ro**, `mt_rootfs_exec` | runs `rc.local.partial`, `fusion.ko`, `mount_3rd_ro.sh`, `mount_3rd.sh`, `/linux_rootfs/basic/autorun.sh` (ro) | **no** |

### 4.2 Root services that execute binaries **and spawn shells** (from readable graph)

| service | uid / domain | exec | why it is a shell executor | consumed input / writable? |
|---|---|---|---|---|
| **dumpstate**, **dumpstatez**, **dumpstatedt1**…**dt5** | 0 / `u:r:dumpstate:s0` | `/system/bin/dumpstate …` | dumpstate is a *shell-command collector*: it `fork/exec`s `/system/bin/sh -c '<cmd>'` for its batteries (this is exactly the mechanism this project already exploited with a page-cache-patched `/system/bin/sh`). `-o` output dir is **shell-owned** `/data/user_de/0/com.android.shell/files/bugreports/`; socket `dumpstate` is **`0660 shell log`** and init created it (kernel log: `Created socket '/dev/socket/dumpstate', mode 660, user 2000, group 1007`) | **`/system/bin/sh` is a root-executed interpreter from a ro squashfs; there is no *file* input in a writable dir, the payload is the interpreter image itself.** Output dir is shell-writable → root-write into a uid-2000 directory (symlink/race angle) |
| **dtdumpstate_a/b** | 0 / `u:r:dtdumpstate:s0` | `/vendor/bin/dtdumpstate -p A|B` | `strings`/imports: `fork`, `execvp`, `socket_local_client`, `open/dup2`, `chmod`, `stat`; constant `/3rd_rw/tombstone/bugreport/shell/`; messages `*** exec(%s): %s`, `Command Timeout`, `[command_print]Kill Error.`, `------ SH LOG (%s) ------`. Companion `/vendor/bin/debugshcmd` (16 KB) implements the `fork`+`execvp` + `dmesg` capture. Work material is `/vendor/etc/service/dtbugreport/` (`sony_bugreport_material_file`, ro — shell cannot even list it) | executes **`/3rd_rw/tombstone/bugreport/shell/`** — DAC `0777 root:root` (created by `dtbugreport.rc`), SELinux `sony_tombstone_data_file`; also reads `/3rd/sony/arib/bin/logdump` (ro, absent on this model), writes `/tmp/odm/dtbugreport/` (DAC 0777, `sony_bugreport_tmp_data_file`) |
| **reverseproxy** | user `root`, group `oem_2900`, domain `nginx` | `/vendor/bin/nginx -c /vendor/etc/nginxconf/nginx.conf` | master stays root, workers drop to `nobody`; config is ro | `include /vendor/etc/nginxconf/sites-enabled/*` (all ro); tmp dirs `/tmp/odm/nginx{,/client_body_temp,/proxy_temp}` `0700 oem_2900`, `/tmp/odm/nginx_socket` `0770 system:oem_2900`; upstream sockets inside **app data dirs**: `/data/data/com.sony.dtv.photosharingplus/files/mexi.sock`, `/data/data/com.sony.mexi.sample.server.android/files/mexi.sock` (**app-owned**) — but those are proxied by the worker, not the root master |
| **boottrace** | 0 / (domain not captured) | `/system/bin/atrace --async_start -f /data/misc/boottrace/categories` | atrace spawns `ps`/`cat`-class commands | `/data/misc/boottrace` is `0700 root:root` (created by `bootstat.rc`) → categories file not writable by shell/apps |
| **dbgset3rd_set** | 0 / `u:r:debugsettings:s0` | `/odm/bin/debugsettings -d /storage/` | no exec, but it is a **root property writer** driven by a file | opens `%s/%s` = **`/storage//sony_dtv_debug_settings.txt`**; also uses `/data/odm/debugprop`; sets `persist.svp.dbg.*` and `persist.sys.svp.dbg.*` props parsed from the file (imports `property_get`, `getopt`, `fopen`, `chmod`, `fwrite`; `strings`: `sys.svp.dbg.3rd.settings`, `sony_dtv_debug_settings.txt`, `/data/odm/debugprop`, `%s/%s`, `cannot open setting file`). `/storage` itself is `0755 root:root` → **NOT writable by shell or an app** (see §8 correction) |
| **b2bcmd_\*** (10 services) | 0 / `u:r:b2bcmd:s0` | `/system/vendor/bin/b2bcmd <verb>` | C++ factory tool (96 744 B, imports `property_get/set`, `MTEEPROM_Read/Write`) | fixed verbs only, but its **file inputs are attacker-influenced**: `/data/vendor/b2b/mountpoint` (used as path prefix for `/arib_channel_preset.bin{,.tmp}`), `/data/vendor/b2b/eeprom_read`, `…/eeprom_read_result`, `/data/vendor/b2b/decrypt_phrase.tmp`, `/data/vendor/b2b/b2bcmd_sock_name.tmp`, and temp files `/tmp/odm/b2b/b2bcmd-*`. `/data/vendor/b2b` is **`0755 system:system`** = **uid 1000 writable**. `/tmp/odm/b2b` is **DAC 0777** |

### 4.3 Root daemons (not shells) with writable data roots

| service / process | uid / domain | data path | DAC / SELinux | writable by |
|---|---|---|---|---|
| dmsdeweydaemon (`dtcp`) | 0 / `u:r:dtcp:s0` | `/3rd_rw/sony/dtcp` | `0770 root:oem_2902`, `dtcp_data_file`, parent `/3rd_rw/sony` `0755 system:system` | gid `oem_2902`; parent replaceable by uid 1000 |
| telepathydaemon | 0 / `u:r:telepathy:s0` | `/data/odm/telepathy` | `0700 root:root`, parent `0755 system:system` | uid 1000 can replace the dir/symlink it |
| itdplatformdaemon | 0 / `u:r:itdplatformdaemon:s0` | `/data/vendor/itvu` (label `itvu_data_file`; creator is in unreadable rc) | unknown owner | unknown |
| app_man / dtv_svc | 0 / `u:r:mt_dtv-svc:s0` | `/tmp/DTVService`, `/tmp/dtv_svc_application_ipc`, `/tmp/fifo_dtv_write`, `/basic/am_config`, `/basic/am_start.ini` | `/tmp` is `0771 root:system` (post-`chmod`) + SELinux `tmpfs` type | **no** — shell and untrusted_app were both denied `write fifo_dtv_write` (`avc ... scontext=u:r:shell:s0 tcontext=u:object_r:tmpfs:s0 tclass=fifo_file`) |
| MtkRmServer | 0 / `u:r:mt_mtk_rm:s0` | `/tmp/MTKRMService` socket | `tmpfs` sock_file; shell getattr denied | no |
| k2logcat | 0 / `u:r:mt_k2logcat:s0` | reads `/dev/kmsg` (klogctl), props `persist.mtk.k2logcat`, `persist.mtk.k2printf` | — | n/a |
| magicpacketseek | 0 / `u:r:magicpacketseek:s0` | binder `com.sony.dtv.mpsservice`; no file data found | — | n/a |

---

## 5. Deep dive on the three writable-executable / writable-input chains

### 5.1 `dtv-svc` → `/vendor/bin/dtv_svc.sh` → `/3rd_rw/sony/arib/etc/aribinit.sh` (root exec on rw ext4)

`/vendor/bin/dtv_svc.sh` is readable (`0755 root:shell`, `vendor_file`) and contains:

```sh
ARIB_BOOT=3rd
ARIB_BOOT_SW=/3rd_rw/aribboot
if [ -f "${ARIB_BOOT_SW}" ]; then
    ARIB_BOOT=`/system/bin/cat "${ARIB_BOOT_SW}"`
fi
if [ "${ARIB_BOOT}" = "3rd" -o "${ARIB_BOOT}" = "3rd_rw" ]; then
    ARIB_INIT_SCRIPT="/${ARIB_BOOT}/sony/arib/etc/aribinit.sh"
    if [ -f "${ARIB_INIT_SCRIPT}" ]; then
        while true; do [ -f /tmp/dtv_svc_is_ready ] && break; sleep 1; done
        ...
        ${ARIB_INIT_SCRIPT} -d          # <-- executed as uid 0 at boot
    fi
fi
```

- `/3rd_rw` is **rw ext4** (`/dev/block/mmcblk0p15`), SELinux `third_rw_fs`.
- `/3rd_rw/sony` is created by `sony.common.rc` as **`0755 system:system`** → **uid 1000 (system) can
  create `/3rd_rw/sony/arib/etc/aribinit.sh`**.
- The only condition is the content of **`/3rd_rw/aribboot`** (top of `/3rd_rw`, `0755 root:root`, so
  not creatable by uid 1000) being `3rd_rw`; `/3rd_rw/sony/arib` is not present on this model
  (`/3rd/sony` ro copy contains only `flash_fs qsip_ex software_license`). So this is a latent
  "root executes a file from user-writable media" path that activates if `aribboot` says `3rd_rw`
  and the tree exists. **Cannot be stat'ed from shell** (`/3rd_rw` is SELinux-denied to shell —
  needs a domain with `third_rw_fs` read).

### 5.2 `dtdumpstate` → `debugshcmd` → `/3rd_rw/tombstone/bugreport/shell/` (root exec from 0777 dir)

- `dtbugreport.rc` (`on post-fs-data-odm`) → `mkdir /3rd_rw/tombstone 777 root root` and
  `mkdir /tmp/odm/dtbugreport 777 root root`.
- `/vendor/bin/dtdumpstate` `fork()`s `/vendor/bin/debugshcmd`, which per its strings `execvp`s
  commands and logs them under `/3rd_rw/tombstone/bugreport/shell/`.
- The dir is DAC `0777` (any uid) but SELinux type `sony_tombstone_data_file`; prior measurement
  *(inherited, not re-measured)*: `u:r:shell`, `u:r:untrusted_app` and `u:r:zygote` are all denied
  write. So it needs a domain that can write `sony_tombstone_data_file` **and** can trigger
  `sys.svp.dbg.dtdumpstate.a/b`.

### 5.3 `b2bcmd` (root) ← `/data/vendor/b2b` (system-writable) and `/tmp/odm/b2b` (0777)

- `b2bcmd.rc`: `mkdir /data/vendor 0775; mkdir /data/vendor/b2b 755 system system;
  mkdir /tmp/odm 0777 root root; mkdir /tmp/odm/b2b 0777 root root`.
- `b2bcmd` reads `/data/vendor/b2b/mountpoint` and builds the file it reads/writes from it
  (`/arib_channel_preset.bin`) — a **root file read/write with an attacker-controllable path prefix**
  if uid 1000 is achieved. Its verbs (`filewrite_prepare`, `fwwrite_prepare`, `fileread_prepare`,
  `eeprom_read`, `decrypt_phrase`, `export/import`, `tuner_enable/disable`) are selected by the
  `sys.svp.b2bcmd.state` property value.
- The trigger is blocked for shell/apps (property type `svp_prop`), so the practical chain is
  **uid 1000 → root**, not shell → root.

### 5.4 `sony_version` symlink-following root write

`sony_version.sh` does `echo ${MANGLED_INFO} >> ${FILE}` where
`FILE=/3rd_rw/sony/version/pkg_info.txt`; `/3rd_rw/sony` is `0755 system:system` → uid 1000 can
create `version` (or `version/pkg_info.txt`) as a symlink to any path; the root script will append the
build string to it. Fixed content limits impact, but it is a *root write through attacker-controlled
file* and it runs every boot.

---

## 6. Property triggers — complete list and reachability (answers Q2)

### 6.1 All `on property:*` triggers in readable rc (35), and what they start

| # | trigger (exact) | extra condition | action | target service / effect | source rc |
|---|---|---|---|---|---|
| 1 | `sys.svp.b2bcmd.state=eeprom_read` | — | start **b2bcmd_er** | root `b2bcmd eeprom_read` | `b2bcmd.rc` |
| 2 | `sys.svp.b2bcmd.state=fwwrite_prepare` | — | start **b2bcmd_fwwrite** | root | `b2bcmd.rc` |
| 3 | `sys.svp.b2bcmd.state=filewrite_cleanup` | — | start **b2bcmd_fwcleanup** | root | `b2bcmd.rc` |
| 4 | `sys.svp.b2bcmd.state=filewrite_prepare` | — | start **b2bcmd_filewrite** | root | `b2bcmd.rc` |
| 5 | `sys.svp.b2bcmd.state=fileread_prepare` | — | start **b2bcmd_fileread** | root | `b2bcmd.rc` |
| 6 | `sys.svp.b2bcmd.state=export_start` | — | start **b2bcmd_exp** | root | `b2bcmd.rc` |
| 7 | `sys.svp.b2bcmd.state=import_start` | — | start **b2bcmd_imp** | root | `b2bcmd.rc` |
| 8 | `sys.svp.b2bcmd.state=tuner_disable` | — | start **b2bcmd_td** | root | `b2bcmd.rc` |
| 9 | `sys.svp.b2bcmd.state=tuner_enable` | — | start **b2bcmd_te** | root | `b2bcmd.rc` |
| 10 | `sys.svp.b2bcmd.state=decrypt_phrase` | — | start **b2bcmd_dp** | root | `b2bcmd.rc` |
| 11 | `sys.boot_completed=1` | — | start **bind_watchdog** | root `sh bind_watchdog.sh` | `bind_watchdog.rc` |
| 12 | `sys.svp.dbg.3rd.settings=*` | — | start **dbgset3rd_set** | root `debugsettings -d /storage/` | `debugsettings.rc` |
| 13 | `sys.svp.dbg.dtdumpstate.a=*` | — | start **dtdumpstate_a** | root `dtdumpstate -p A` | `dtdumpstate.rc` |
| 14 | `sys.svp.dbg.dtdumpstate.b=*` | — | start **dtdumpstate_b** | root `dtdumpstate -p B` | `dtdumpstate.rc` |
| 15 | `persist.svp.dbg.logd.size.main=*` | — | `setprop persist.logd.size.main ${…}` | **init-mediated property write** | `mlog.rc` |
| 16 | `persist.svp.dbg.k2mlog=*` | — | `setprop persist.mtk.k2mlog ${…}` | init-mediated write (`mtk_prop`) | `mlog.rc` |
| 17 | `persist.svp.dbg.mlog2logcat=*` | — | `setprop persist.mtk.mlog2logcat ${…}` | init-mediated write | `mlog.rc` |
| 18 | `sys.svp.reverseproxy.enable=1` | — | start **reverseproxy** | root nginx master | `nginx.rc` |
| 19 | `sys.svp.reverseproxy.enable=0` | — | stop **reverseproxy** | | `nginx.rc` |
| 20 | `sys.boot_completed=1` | `&& persist.svp.dbg.irq_debug=1` | start **setup_irq_debug** | root sh script | `setup_irq_debug.rc` |
| 21 | `persist.debug.atrace.boottrace=1` | — | start **boottrace** | root `atrace --async_start -f /data/misc/boottrace/categories` | `atrace.rc` |
| 22 | `vts.native_server.on=1` | `&& ro.build.type=userdebug` | stop **bluetooth-1-0** | **inert on this user build** | `android.hardware.bluetooth@1.0-service.rc` |
| 23 | `vts.native_server.on=1` | `&& ro.build.type=eng` | stop **bluetooth-1-0** | inert (user build) | same |
| 24 | `vts.native_server.on=0` | `&& ro.build.type=userdebug` | start **bluetooth-1-0** | inert | same |
| 25 | `vts.native_server.on=0` | `&& ro.build.type=eng` | start **bluetooth-1-0** | inert | same |
| 26 | `vts.native_server.on=1` | — | stop **audioserver** | inert only if set; not gated but no root gain | `audioserver.rc` |
| 27 | `vts.native_server.on=0` | — | start **audioserver** | | `audioserver.rc` |
| 28 | `init.svc.zygote=stopping` | — | setprop `sys.logbootcomplete 0` | init-internal; not settable | `bootstat.rc` |
| 29 | `sys.boot_completed=1` | `&& sys.logbootcomplete=1` | `exec - root root -- /system/bin/bootstat …` (×4) | **root one-shot execs** | `bootstat.rc` |
| 30 | `sys.svp.bugreport.output=*` | — | start **dumpstatedt3** | root dumpstate `-m` (copy report to USB) | `dumpstate.rc` |
| 31 | `sys.svp.bugreport.enc.output=*` | — | start **dumpstatedt4** | root dumpstate `-e` (encrypted report) | `dumpstate.rc` |
| 32 | `sys.svp.bugreport.multiramoops=1` | — | start **dumpstatedt5** | root `dumpstate -L` | `dumpstate.rc` |
| 33 | `init.svc.zygote=stopped` | — | stop **webview_zygote32** | init-internal | `webview_zygote32.rc` |
| 34 | `sys.boot_completed=1` | `&& sys.wifitracing.started=0` | mkdir/restorecon/write tracefs + `setprop sys.wifitracing.started 1` | tracefs chown `system` | `wifi-events.rc` |
| 35 | `sys.boot_completed=1` | `&& wifi.interface=* && sys.wifitracing.started=1` | write tracefs net filter | | `wifi-events.rc` |

### 6.2 Which of these properties can we actually set?

Property labels come from `/plat_property_contexts` + `/nonplat_property_contexts` (readable):

| prefix | SELinux property type | who can set it (evidence) |
|---|---|---|
| `sys.svp.*`, `svp.*`, `persist.svp.*`, `persist.sys.svp.*`, `ro.svp.*`, `camera.support`, `nrdp.*` | **`svp_prop`** | **not shell, not ordinary app, not zygote** — prior session measured `setprop sys.svp.*` denied in all three reachable domains (`avc: denied { set } … property_socket`, inherited, not re-measured). Setter is almost certainly Sony `system_app`/vendor code. |
| `persist.debug.*` | `persist_debug_prop` (prefix `persist.debug.`) | **unmeasured.** `debug.test.prop` *is* present in `getprop` (proof a debug-ish prop was set at some point, attribution unknown). `persist.debug.atrace.boottrace=1` → `boottrace` root atrace; low value (root atrace reading a root-only categories file), but it is the **only trigger on a possibly-weaker label** — worth one measurement. |
| `service.adb.*`, `security.perf_harden` | **`shell_prop`** — clearly shell-settable | `service.adb.tcp.port`, `service.adb.root` are settable by shell. **No trigger in the readable graph uses them.** (`service.adb.root` + adbd restart is a separate avenue: adbd indeed starts with `--root_seclabel=u:r:su:s0`, but `ro.debuggable=0`/`ro.secure=1` → `ALLOW_ADBD_ROOT` off in this user build; `post-init.sh` runs adbd restart as root itself.) |
| `vts.*` | `default_prop` | irrelevant: all `vts` start/stop actions are gated by `ro.build.type=userdebug|eng`, build is `user`. |
| `sys.boot_completed`, `sys.logbootcomplete`, `sys.wifitracing.started`, `wifi.interface` | `system_prop` / `wifi_prop` | set by system_server/init, not shell. |
| `init.svc.*` | init-owned | read-only by design. |

**Conclusion:** every Sony root-trigger needs a `svp_prop` write; that is the single wall. If a domain
that can write `svp_prop` (or `property_service` on it) is ever obtained — a Sony system_app bug, a
service-account process, a root-capable domain — then #12/#13/#14/#30/#31 and the whole
`b2bcmd_*` family become **direct root executors**. Conversely, shell-only exploitation must use
§11 candidates 1–2.

**Unreadable-graph gap:** the root `.rc` files almost certainly declare more property triggers
(`sys.svp.*`, `persist.svp.*`, boot-phase triggers). They cannot be enumerated statically from shell;
capture the init action log after the next boot (§12.1) to get them **with their exact source
`file:line`**.

---

## 7. Root `exec` one-shots in init actions (no service involved)

Only two readable rc files contain `exec` (Android 8.0's only root-exec-in-action form):

```
/system/etc/init/bootstat.rc
    on post-fs-data && property:init.svc.bootanim=running && property:ro.crypto.type=block
        exec - root root -- /system/bin/bootstat -r post_decrypt_time_elapsed
    on property:sys.boot_completed=1 && property:sys.logbootcomplete=1
        exec - root root -- /system/bin/bootstat --record_boot_complete
        exec - root root -- /system/bin/bootstat --record_boot_reason
        exec - root root -- /system/bin/bootstat --record_time_since_factory_reset
        exec - root root -- /system/bin/bootstat -l

/system/etc/init/vdc.rc
    on defaultcrypto
        exec - root -- /system/bin/vdc --wait cryptfs mountdefaultencrypted
    on encrypt
        start surfaceflinger
        exec - root -- /system/bin/vdc --wait cryptfs enablecrypto inplace default noui
```

All arguments are fixed; `/system/bin/bootstat` and `/system/bin/vdc` are ro; none reads an
attacker-writable path. No `exec_start` verb exists on Android 8.0.

---

## 8. Writable-path / root-consumer matrix (answers Q3)

Writability below is **DAC-verified from the device** (`stat`, `[ -w … ]`, `ls -lZ`) plus the
SELinux type from `/plat_file_contexts` / `/nonplat_file_contexts`; where SELinux is the deciding
factor the AVC evidence is quoted.

| path | mount | DAC mode / owner | SELinux type | shell (2000) write? | app write? | root consumers (init graph) |
|---|---|---|---|---|---|---|
| `/data/local/tmp` | /data ext4 rw | `0771 shell:shell` (`shell_data_file`) | `shell_data_file` | **YES** (`[ -w ]`=true) | no | **none found** — no init service/trigger reads or executes from here |
| `/storage/emulated/0` (`/sdcard`) | sdcardfs | `0771 root:sdcard_rw` | `sdcardfs` | **YES** (`[ -w ]`=true) | **YES** (with storage perm) | **none executes from here.** Only `dumpstate -m` writes USB copies; `debugsettings` reads `/storage/` *top level*, not this subdir |
| `/storage` (top) | tmpfs | `0755 root:root` | `storage_file` | **NO** (`[ -w ]`=false) | no | `debugsettings` reads `/storage//sony_dtv_debug_settings.txt` |
| `/tmp` | tmpfs rw | mount `1771`, then `dtv_svc.sh`: `chmod 771; chown 0:1000` → `0771 root:system` | `tmpfs` | **NO** (`[ -w ]`=false; AVC: `getattr` on `/tmp/*` denied `tcontext=tmpfs`) | no | TV stack FIFOs/sockets, nginx, dtbugreport, mknod flags |
| `/tmp/odm` | tmpfs | `0755 system:system` (`sony_tmp_data_file`) | `sony_tmp_data_file` | **NO** (AVC getattr denied) | no | b2bcmd, dtdumpstate, nginx |
| `/tmp/odm/b2b` | tmpfs | init: **`0777 root:root`** | `sony_b2b_tmp_data_file` | DAC yes / **SELinux-gated** | SELinux-gated | **`b2bcmd`** (temp `b2bcmd-*` files, socket-name file) |
| `/tmp/odm/dtbugreport` | tmpfs | init: **`0777 root:root`** | `sony_bugreport_tmp_data_file` | SELinux-gated | SELinux-gated | **`dtdumpstate` / `debugshcmd`** |
| `/tmp/odm/nginx*` | tmpfs | `0700 oem_2900`; socket dir `0770 system:oem_2900` | `sony_nginx_tmp_data_file` | no | no | nginx temp/sockets |
| `/3rd_rw` | ext4 **rw** | `0755 root:root` | `third_rw_fs` | **NO** (AVC denied) | no | `aribboot` (read), `aribinit.sh` (exec) via dtv-svc; `sony_version`; `dtcp`; tombstones |
| `/3rd_rw/sony` | ext4 rw | `0755 system:system` | `sony_data_file` | no | **uid 1000 only** | `sony_version` (append), `aribinit.sh` (exec path), `dtcp` data |
| `/3rd_rw/sony/dtcp` | ext4 rw | `0770 root:oem_2902` | `dtcp_data_file` | no | gid 2902 | `dmsdeweydaemon` |
| `/3rd_rw/tombstone` | ext4 rw | init: **`0777 root:root`** | `sony_tombstone_data_file` | SELinux-gated *(inherited: denied)* | SELinux-gated | **`debugshcmd` exec target dir** (`…/bugreport/shell/`) |
| `/3rd_rw/localtime` | (symlink target) | — | — | — | — | not init-consumed |
| `/data/vendor` | ext4 rw | init rc: `0775 root:root` | vendor data | no | no | — |
| `/data/vendor/b2b` | ext4 rw | init rc: **`0755 system:system`** | `b2b_data_file` | no | **uid 1000 only** | **`b2bcmd`** (`mountpoint`, `eeprom_read*`, `decrypt_phrase.tmp`) |
| `/data/vendor/itvu` | ext4 rw | unknown | `itvu_data_file` | no | likely uid 1000 | `itdplatformdaemon` |
| `/data/vendor/recognition` | ext4 rw | `0755 system:system` | `camera_recognition_data_file` | no | uid 1000 | daemon runs as system (not root) |
| `/data/odm` | ext4 rw | init: `0755 system:system` | `sony_data_file` | no | **uid 1000** | **parent of all root-data subdirs below** |
| `/data/odm/debugprop` | ext4 rw | `0755 root:root` | `sony_debugprop_data_file` | no | parent `system`-owned | `debugsettings` (reads/writes) |
| `/data/odm/dtbugreport{,/multiramoops,/dtdebug}`, `/data/odm/crashlogs` | ext4 rw | `0755 root:root` / `system:system` | `sony_bugreport_data_file` | no | parent `system`-owned | `multiramoops`, dumpstate ext, bugreport |
| `/data/odm/telepathy` | ext4 rw | `0700 root:root` | `telepathy_data_file` | no | parent `system`-owned | `telepathydaemon` |
| `/data/user_de/0/com.android.shell/files/bugreports` | ext4 rw | shell-owned dir | `shell_data_file` | **YES (owner)** | no | **root `dumpstate*` writes reports here** |
| `/cache` | ext4 rw | `0770 system:cache` | cache_file | no | no | none found in readable graph |
| `/upgrade` | vfat rw | `0764 root:root` | (vfat) | read-only for shell | no | none found |
| `/proc/boottime` | proc | **`0666 root:root`** | `proc` | **YES, writable by any uid** | yes | *written by* root boot scripts; not a root consumer, but log-spoofable |

**Negative results that matter** (previously assumed surfaces, now checked against the init graph):

- **nothing in the init graph executes or reads from `/data/local/tmp`** (the one writable path shell
  fully controls);
- `/storage/emulated/0` is shell/app-writable but **no root service reads it** — the only Sony
  storage reader (`debugsettings`) uses the `/storage/` *top level* (root-only, and only USB mount
  roots appear beneath it, not inside it). This corrects the earlier note that
  "`debugsettings -d /storage/` reads a writable path" — the exact open is
  `/storage//sony_dtv_debug_settings.txt`, and `/storage` is `0755 root:root`.

---

## 9. rc actions that create, restorecon, chmod, chown, write, or race paths (answers Q4)

### 9.1 `mkdir` with permissive modes (candidate drop/plant dirs)

| source rc | command | resulting DAC | SELinux type | who can write after boot |
|---|---|---|---|---|
| `b2bcmd.rc` (post-fs-data) | `mkdir /tmp/odm 0777 root root` | 0777 | `sony_tmp_data_file` | any uid by DAC; SELinux gates |
| `b2bcmd.rc` | `mkdir /tmp/odm/b2b 0777 root root` | 0777 | `sony_b2b_tmp_data_file` | any uid by DAC; consumed by **root b2bcmd** |
| `b2bcmd.rc` | `mkdir /data/vendor 0775` ; `mkdir /data/vendor/b2b 755 system system` | 0775/0755 | `b2b_data_file` | **uid 1000 writes `/data/vendor/b2b`** |
| `dtbugreport.rc` (post-fs-data-odm) | `mkdir /3rd_rw/tombstone 777 root root` | 0777 | `sony_tombstone_data_file` | any uid by DAC; consumed by **root debugshcmd** |
| `dtbugreport.rc` | `mkdir /tmp/odm/dtbugreport 777 root root` | 0777 | `sony_bugreport_tmp_data_file` | any uid by DAC; consumed by **root dtdumpstate** |
| `dtbugreport.rc` | `mkdir /data/odm/crashlogs 755 system system` | 0755 | `sony_data_file` | uid 1000 |
| `nginx.rc` (post-fs-data-odm) | `mkdir /tmp/odm/nginx … 700 oem_2900`; `mkdir /tmp/odm/nginx_socket 770 system oem_2900` | 0700/0770 | `sony_nginx_tmp_data_file` | gid `oem_2900` (owner) |
| `sony.common.rc` (post-fs-data) | `mkdir /data/odm 755 system system` / `/tmp/odm 755 system system` / `/3rd_rw/sony 755 system system` / `/3rd_rw/persist{,/odm} 755 system system` | 0755 | `sony_data_file` | uid 1000 (owner) |
| `debugsettings.rc` | `mkdir /data/odm/debugprop 755 root root` | 0755 | `sony_debugprop_data_file` | root only contents, **parent system-owned** |
| `telepathydaemon.rc` | `mkdir /data/odm/telepathy 700 root root` | 0700 | `telepathy_data_file` | root only, parent system-owned |
| `dmsdeweydaemon.rc` | `mkdir /3rd_rw/sony/dtcp 0770 root oem_2902` | 0770 | `dtcp_data_file` | gid 2902 |
| `camera_recognition_daemon.rc` (boot) | `mkdir /data/vendor/recognition 755 system system` | 0755 | `camera_recognition_data_file` | uid 1000 |
| `bootstat.rc` (post-fs-data) | `mkdir /data/misc/bootstat 0700 root root` | 0700 | — | root only |

### 9.2 `restorecon_recursive` in an init action — symlink/relabel race surface

```
sony.common.rc:
on post-fs-data-odm-restorecon
    restorecon_recursive /data/odm
    restorecon_recursive /tmp/odm
    restorecon_recursive /3rd_rw/sony
    restorecon_recursive /3rd_rw/persist/odm
```

`/data/odm` and `/3rd_rw/sony` are **persistent rw-ext4 directories owned by `system:system`**
(`0755`). A uid-1000 process that can create entries there can pre-create **symlinks / replacement
directories** that survive a reboot (the dirs are on `/data` and `/3rd_rw`, not tmpfs), and on the
next boot init will run `mkdir`/`restorecon_recursive` over them as **root**. Also note the mkdir
targets beneath those parents (`/data/odm/debugprop`, `/data/odm/dtbugreport`, `/data/odm/telepathy`,
`/3rd_rw/sony/dtcp`) are all root-owned leaves under a **system-owned parent** → a uid-1000 writer can
rename/replace those leaves between reboots, redirecting the root services' data. This is the classic
"persisted path swap under a root-imposed tree" pattern and the only rc-file race worth pursuing
beyond the 0777 dirs.

### 9.3 Other privileged init commands (non-root attack value)

- `atrace.rc` (on `post-fs`) `chown root shell` + `chmod 0664` on ~40 tracefs `enable` nodes,
  `trace_clock`, `buffer_size_kb`, `trace_marker` (`0222`), `trace` (`0660 root shell`) →
  **shell can enable kernel tracing / write trace_marker** (kernel-log injection surface; no
  privilege gain by itself).
- `wifi-events.rc` mkdir/restorecon/chown of `/sys/kernel/debug/tracing/instances/wifi`
  (chown `system`, mode 200/400/600).
- `dumpstate.rc` `chown root mount` + `chmod 0444` on `/sys/kernel/debug/mmc0/mmc0:0001/ext_csd`.
- `logd.rc` `write /dev/event-log-tags` + chown/chmod.
- `installd.rc` `mkdir /config/sdcardfs/extensions/…` (~100 dirs on configfs).
- `vdc.rc` root `exec` (§7).
- Every `sony.common.rc` `trigger post-fs-data-odm` / `-restorecon` chain is what makes the
  `/data/odm`, `/tmp/odm`, `/3rd_rw/sony` trees exist at all.

---

## 10. `/vendor/bin`, `/odm/bin`, `/system/vendor/bin` enumeration

`/odm -> /vendor` and `/vendor -> /system/vendor`, so **`/odm/bin` and `/system/vendor/bin` are the
same directory as `/vendor/bin`** (there is no separate odm partition). Directory: `0755 root:shell`,
`vendor_file`. Every entry is `0755 root:shell` (world-executable by DAC) **except** the Bluetooth
HAL (`0700 bluetooth:bluetooth`). SELinux exec-type labels restrict who may execute what; 19 entries
are additionally **not even stat-able** from shell (`getattr` denied) because of their exec/svc type.

| path (`/vendor/bin/…`) | size | exec SELinux type | stat'able by shell |
|---|---|---|---|
| `b2bcmd` | 96744 | `b2bcmd_exec` | yes |
| `debugsettings` | 16292 | `debugsettings_exec` | yes |
| `dtdumpstate` | 24684 | `dtdumpstate_exec` | yes |
| `debugshcmd` | 16228 | `vendor_file` | yes |
| `dtbugreport` | 16268 | `vendor_file` | yes |
| `dumpecsserver` | 29284 | `dumpecsserver_exec` | yes |
| `eepserver` | 29264 | `eepserver_exec` | yes |
| `setmviprop` | 16380 | `setmviprop_exec` | yes |
| `k2logcat` | 16152 | `mt_k2logcat_exec` | yes |
| `gatord` | 1469836 | `vendor_file` | yes |
| `modprobe`, `iw`, `nvs-cat`, `switch_fbm`, `mhl_test`, `hdmi_cec_test`, `cli_shell`, `ttyman_shell`, `tvinputhal_test`, `wfd_cli`, `DeviceConfig_TV.bin`, `dhcp6c.script`, `dhcp6cPD.script`, `dtv_svc.sh`, `logcat2data.sh`, `mtk_bugreport.sh`, `mtk_rm.sh`, `set_wopacket_port*`, `MtkRmInitServer`, `MtkRmTest`, `vndservice` | — | `vendor_file` / script | yes |
| `MtkRmServer` | — | **denied stat** | **no** |
| `camera_recognition_daemon` | — | **denied stat** | **no** |
| `dmsdeweydaemon` | — | **denied stat** | **no** |
| `init_sony_ko.sh` | — | `sony_ko_exec` (from file_contexts) | **no** |
| `itdplatformdaemon` | — | **denied stat** | **no** |
| `iwpriv`, `iwpriv_wifi_operation` | — | **denied stat** | **no** |
| `kyildm` | — | `kyil_exec` | **no** |
| `magicpacketseek` | — | `magicpacketseek_exec` | **no** |
| `nginx` | — | `nginx_exec` | **no** |
| `restart_wifi.sh`, `update_linux_network`, `updown_wlan.sh`, `wifi_fw_check`, `wifi_set.sh`, `wowl_off.sh`, `wowl_on.sh` | — | **denied stat** | **no** |
| `sony_input_manager` | — | `sony_input_manager_exec` | **no** |
| `telepathydaemon` | — | `telepathy_exec` | **no** |
| `/vendor/bin/hw/*` (16 entries) | — | dedicated `hal_*_exec` types | yes (all `0755 root:shell` except bluetooth) |

`/vendor/bin/hw` (readable): `android.hardware.{audio@2.0-service-mediatek, bluetooth@1.0-service,
camera.provider@2.4-service, configstore@1.0-service, drm@1.0-service, drm@1.0-service.widevine,
graphics.allocator@2.0-service, graphics.composer@2.1-service, health@1.0-service,
keymaster@3.0-service, media.omx@1.0-service, power@1.0-service, tv.cec@1.0-service,
tv.input@1.0-service-mediatek, vendor.mediatek.hardware.pppoeproxy@1.0-service, wpa_supplicant}` —
all `0755 root:shell` except `android.hardware.bluetooth@1.0-service` (`0700 bluetooth:bluetooth`).

Also present but not readable/stat-able from shell (dedicated exec types imply init services in the
unreadable graph): `/system/vendor/bin/hw/com.sony.dtv.hardware.audio@1.0-service` (`hdmiaudio_exec`),
`…hardware.network@1.0-service` (`sony_network_exec`), `/vendor/bin/sony_be_wakelock`,
`/vendor/bin/sony_mainunitkey_manager`, `/vendor/bin/dbus-daemon` (see §3.3).

---

## 11. Ranked root-context privesc candidates

Ranking = (runs as uid 0 or bridges into uid 0) × (input/executable on a path a reachable principal
can write) × (reachability from a principal we can obtain today). Only real root-context executors are
listed; plainly non-root services are omitted.

### Tier 1 — reachable now, root execution

**1. `dumpstate` family — the one root executor reachable from plain `adb shell`.**
`/system/etc/init/dumpstate.rc:621-703` defines `dumpstate`, `dumpstatez`, `dumpstatedt1`–`dt5`,
all **uid 0**, `socket dumpstate stream 0660 shell log`, `disabled`, `oneshot`.
`dumpstate` collects by executing `/system/bin/sh` as root; the output directory
`/data/user_de/0/com.android.shell/files/bugreports/` is **owned by uid 2000**. init's kernel log
shows the trigger socket being created (`Created socket '/dev/socket/dumpstate', mode 660, user 2000,
group 1007`), so shell can start it (this is precisely how `adb bugreport` reaches root). The project
has already demonstrated root code execution through a page-cache-patched `/system/bin/sh` +
`adb bugreport`. **Why rank 1:** only shell-reachable root exec; the payload is the interpreter image
in `/system` (patchable from a uid-0/zygote page-cache primitive), not a writable config file, so no
`svp_prop` is needed.

**2. `dtv-svc` → `/vendor/bin/dtv_svc.sh` → `/3rd_rw/sony/arib/etc/aribinit.sh` — root exec from rw
ext4 media, at every boot.**
`/vendor/bin/dtv_svc.sh` (readable): reads `ARIB_BOOT` from **`/3rd_rw/aribboot`**, and if it is
`3rd_rw` executes **`/3rd_rw/sony/arib/etc/aribinit.sh -d` as uid 0**. `/3rd_rw/sony` is
`0755 system:system` → **uid 1000 can plant the executable**; `/3rd_rw` is rw ext4 (persistent).
Gated on `/3rd_rw/aribboot` content and on the `arib` tree existing (not present in the ro `/3rd`
copy on this model; `/3rd_rw` could not be stat'ed from shell). **Why rank 2:** it is a persistent,
boot-triggered root **executable on writable storage**, it was not in any prior inventory, and it
requires only uid-1000 write — a lower bar than any `svp_prop`. First action for a domain able to read
`/3rd_rw` (`mt_dtv-svc`, `interactivetvutil`?): `ls -la /3rd_rw /3rd_rw/sony` and check for
`aribboot`.

**3. `dtdumpstate_a/b` → `debugshcmd` → `execvp` out of `/3rd_rw/tombstone/bugreport/shell/`.**
`/vendor/etc/init/dtdumpstate.rc` (root, `dtdumpstate` domain, oneshot, seclabel from
`dtdumpstate_exec`); `dtbugreport.rc` creates `/3rd_rw/tombstone` **`0777`**. `debugshcmd`
(`/vendor/bin/debugshcmd`) does `fork`+`execvp` and writes `SH LOG` files under
`/3rd_rw/tombstone/bugreport/shell/`; `dtdumpstate` supplies work material from
`/vendor/etc/service/dtbugreport/` (ro, `sony_bugreport_material_file`). **Why rank 3:** root
exec-from-writable-dir is exactly the pattern; blocked only by (a) SELinux write on
`sony_tombstone_data_file` (denied for shell/app/zygote — *inherited*) and (b) the trigger property
`sys.svp.dbg.dtdumpstate.a/b` being `svp_prop` (not shell-settable). If either wall falls this is an
instant root shell.

**4. `b2bcmd_*` (10 root services) with `/data/vendor/b2b` system-writable + `/tmp/odm/b2b` 0777.**
`/vendor/etc/init/b2bcmd.rc`. Root tool with EEPROM read/write, file read/write, firmware write,
export/import, decrypt. Data root **`/data/vendor/b2b` is `0755 system:system` → uid 1000 controls
`mountpoint`, `eeprom_read`, result files**; temp dir `/tmp/odm/b2b` is DAC `0777`. Trigger is
`sys.svp.b2bcmd.state=<verb>` (`svp_prop`, denied to shell/app). **Why rank 4:** best
service-account(uid 1000)→root primitive on the box (EEPROM/file write as root with attacker-influenced
paths); only needs a `svp_prop` setter.

### Tier 2 — root services with input on a path uid 1000 (`system`) can influence

**5. `sony_version` (root sh) — `/3rd_rw/sony/version/pkg_info.txt` symlink-follow root append.**
`/odm/etc/service/sony_version.sh` (readable): `echo ${MANGLED_INFO} >> ${FILE}` where `FILE` lives in
a `system`-owned dir; fixed content limits damage but it is a root write through an attacker-chosen
path (could target `/data/misc/...` root-only files).

**6. `multiramoops` (root sh, `u:r:multiramoops`) — `/data/odm/dtbugreport/multiramoops/` under a
system-owned parent.** A uid-1000 swap of the leaf dir (or a symlink) redirects a **root write of a
kernel ramoops dump (kernel-log info leak)** to an attacker-chosen path; also chains
`setprop sys.svp.bugreport.multiramoops 1` → root `dumpstatedt5`.

**7. `telepathydaemon` (root, `u:r:telepathy`) — `/data/odm/telepathy` (`0700 root:root`) under the
system-owned `/data/odm`.** Leaf replace → root daemon reads/writes attacker path.

**8. `dmsdeweydaemon` (root, `u:r:dtcp`) — `/3rd_rw/sony/dtcp` `0770 root:oem_2902`.** Any process
running with gid `oem_2902` writes the root DTCP daemon's data dir. `oem_2902` is granted to the
dtcp daemon itself; check whether any Sony app/daemon process carries that gid.

**9. `dbgset3rd_set` (root, `u:r:debugsettings`) — reads `/storage//sony_dtv_debug_settings.txt`.**
The earlier assumption "`/storage/` is writable by us" is **wrong for the path actually opened**:
`/storage` is `0755 root:root`; only mount roots appear beneath it. **But** the parent of its
persist dir `/data/odm/debugprop` is system-owned → uid-1000 leaf swap. Trigger `svp_prop`.

### Tier 3 — checked and closed (state explicitly so they are not re-chased)

- `bind_watchdog`, `setup_irq_debug`: root but confined to `irq_debug`; only fixed `pgrep/taskset` /
  tracefs writes; **no writable input**.
- `mlog` (`/sbin/mlog`), `k2logcat` (reads `/dev/kmsg`): root log shippers; no writable input.
- `boottrace` (root `atrace -f /data/misc/boottrace/categories`): categories dir is `0700 root:root`;
  only trigger on `persist.debug.atrace.boottrace` (potentially weaker `persist_debug_prop` label) —
  but impact is atrace tracing, not code exec.
- `pre-init`, `post-init`, `insmod`, `sony-ko`, `updatedns`, `mknod_util`, `mtk_rm`, `rc.local`
  chain: fixed paths on ro squashfs; `/tmp` is not writable by shell (0771 root:system) and the
  scripts do not execute from `/tmp`.
- `reverseproxy`/nginx: config tree all ro; worker drops to `nobody`; only temp dirs in
  `oem_2900`-owned `/tmp`.
- `app_man`/`dtv_svc` (root `mt_dtv-svc`): control FIFOs/sockets in `/tmp`, but `/tmp` is
  `0771 root:system` and SELinux denies shell `write fifo_dtv_write` (AVC on device). Not reachable
  from uid 2000.
- `MtkRmServer`, `magicpacketseek`, `itdplatformdaemon`, `k2logcat`: no attacker-writable input
  found; binder/socket surfaces belong to the binder report, not the init graph.

### Cross-link worth a follow-up (not an init service itself)

**`interactivetvutil`** runs as **uid 2000 (same as shell), gid 0**, in its own domain
`u:r:interactivetvutil:s0`, and is the intended bridge into the root `mt_dtv-svc` TV stack
(`/tmp/fifo_dtv_write`, `/tmp/DTVService`). The binder inventory already confirmed its
`com.sony.dtv.itvunative.interactivetvutil` service transacts from `shell`. Because it shares uid 2000
and gid 0, any DAC-only trust check based on file ownership (`/data/local/tmp`, bugreport dirs) treats
it and shell as one principal. If any of its methods forwards TV-stack commands, shell→root-TV-stack
control would run through a **uid-2000 daemon** — it is the most promising "unfinished" bridge in the
init graph, but it needs method-level RE (binder report territory).

---

## 12. Open questions / recommended next steps (all read-only unless flagged)

1. **Capture the full init action graph after the next reboot (highest value, read-only).**
   Android 8 init logs every executed action command with `action=<name> (<rc file>:<line>)` to the
   kernel log (proven live above). Boot is at 15:08 and the log buffer now starts 15:28, so the
   unreadable `/init.rc`, `/init.mt5890.rc`, `/init.mtk_common.rc`, `/init.mkn.rc` graph is only
   recoverable in the first minutes after a boot:
   ```
   adb shell "logcat -b kernel -d | grep 'init    :'"
   ```
   This yields service starts, trigger→command mapping, `exec` calls, and the triggering rc file:line
   — including the 14 root rc files we cannot `cat`. If a reboot is ever done anyway, this should be
   the first command run afterwards.
2. **Get a domain that can read `/3rd_rw` and `/tmp`** to confirm the `dtv-svc` ARIB branch:
   `ls -la /3rd_rw`, `cat /3rd_rw/aribboot`, `ls -la /3rd_rw/sony`. Candidates that may have the
   access (all uid 0 or special domains): `mt_dtv-svc` (app_man), `u:r:interactivetvutil`, or the
   dumpstate root domain. From `interactivetvutil` (uid 2000) a DAC check of `/3rd_rw` would pass
   only through group/other bits; SELinux still applies.
3. **Dump the binary policy from a root/privileged domain** to settle `svp_prop` setters and the
   custom domains (`dtdumpstate`, `debugsettings`, `irq_debug`, `multiramoops`, `mt_dtv-svc`,
   `interactivetvutil`, `dumpstate`). `/sys/fs/selinux/policy` is mode `0444` but open-denied to
   shell (and to zygote per docs/08). The working sh-patch + dumpstate root domain could copy it out
   (the only question is where that domain may write).
4. **Measure `persist.debug.atrace.boottrace` settability** (cheap, one property write + `logcat -b
   kernel | grep boottrace`). If shell can set `persist_debug_prop`, the same might hold for other
   debug-prefixed Sony props — currently the only label between us and the `svp_prop` wall.
5. **Check gid `oem_2900`/`oem_2902` distribution** (which processes/apps carry these gids) to judge
   candidates 8 and the nginx temp dirs. `ps -A -o pid,user,group,args` shows groups; only the two
   root daemons (dmsdeweydaemon → `oem_2902`; telepathydaemon → `oem_2901`) were visible in the
   running set.
6. **RE the two writable-input tools** (`/vendor/bin/dtdumpstate` + `debugshcmd`, `/vendor/bin/b2bcmd`,
   `/vendor/bin/debugsettings`) with the strings already extracted here; the exact file grammars and
   whether `debugshcmd` executes scripts *from* `/3rd_rw/tombstone/bugreport/shell/` (vs merely
   logging there) decides candidate 3's value.
7. **`/proc/boottime` is world-writable (`0666`)** — any domain can forge boot-script log lines. Not a
   privilege bug, but it means the boot log is not trustworthy evidence if a hostile app writes it
   first; cite `/proc/boottime` with that caveat.

---

## Appendix A — raw artifact locations (host temp, this session)

| file | contents |
|---|---|
| `%TEMP%\remap_getprop.txt` | full `getprop` (240 props) |
| `%TEMP%\remap_procs.txt`, `remap_procs2.txt` | `/proc/*/cmdline`+uid and `/proc/*/status` scan (290 pids) |
| `%TEMP%\remap_psZ.txt` | `ps -Z` (287 rows, full SELinux label/uid/name) |
| `%TEMP%\remap_rc_readable.txt` | all 66 readable rc files, concatenated (1098 lines) |
| `%TEMP%\remap_ctx.txt` | `plat/nonplat_service_contexts` + `plat/nonplat_property_contexts` (294 lines) |
| `%TEMP%\remap_filectx.txt` | `plat_file_contexts` + `nonplat_file_contexts` (884 lines) |
| `%TEMP%\remap_etc2.txt`, `remap_dev.txt`, `remap_basic.txt`, `remap_nginx_sites.txt`, `remap_findrc.txt`, `remap_bootconf.txt`, `remap_selinuxetc.txt`, `remap_klog_actions.txt` | targeted device reads |
| `%TEMP%\remap_bins\` | pulled `b2bcmd`, `debugsettings`, `dtdumpstate`, `dtbugreport`, `debugshcmd`, `k2logcat`, `dumpecsserver`, `MtkRmInitServer`, `MtkRmTest`, `cli_shell`, `vndservice`, `set_wopacket_port` |
| `%TEMP%\remap_strings.txt` | printable strings of all pulled binaries |
