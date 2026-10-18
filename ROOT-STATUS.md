# Root: state, capability matrix, and what is left

## Achieved (device-verified)

**Arbitrary code execution as uid 0 in `u:r:dumpstate:s0`**, triggered by `adb bugreport`, using
only page-cache writes from uid 2000 (no kernel exploit).

```
uid=0(root) gid=0(root) groups=0(root) context=u:r:dumpstate:s0
ppid: /system/bin/dumpstate -S -d -z -o /data/user_de/0/com.android.shell/files/bugreports/bugreport
```

The payload (`/data/local/tmp/r.sh`) is re-runnable: edit it, run `adb bugreport`, read the result.
That is a full root command channel, batch-style.

### Bonus: `sys.svp.*` property control

The dumpstate-domain root **can set the `sys.svp.*` properties** that are denied to shell,
untrusted_app and zygote. Verified SET_OK for all of:

```
sys.svp.dbg.3rd.settings     -> debugsettings service
sys.svp.bugreport.output     -> dumpstatedt3, confirmed init.svc.dumpstatedt3 = running
sys.svp.b2bcmd.state         -> b2bcmd (eeprom_read fired)
sys.svp.dbg.dtdumpstate.a    -> dtdumpstate
```

`ctl.start` itself is still denied (`ctl_prop`).

## Measured capability matrix from the root context

| operation | as dumpstate root |
|---|---|
| run arbitrary commands as uid 0 | **yes** |
| set `sys.svp.*` properties | **yes** |
| read `/data/system` (appops.xml, packages.xml) | **yes** |
| write `/data/anr` | **yes** |
| open `/dev/mali0`, `/dev/ion` | **yes** |
| write `/3rd_rw/*` (tombstone, sony) | no (SELinux `sony_tombstone_data_file`) |
| write `/sys/fs/selinux/enforce` | no (SELinux) |
| write `/data/system`, `/data/property` | no (SELinux) |
| remount `/system` rw | no (ro block device + SELinux) |
| read `/dev/block/mmcblk0*` (any partition) | no (SELinux) |
| open `/dev/kmem2`, `/dev/ttyMT3`, `/dev/vndbinder` | no (SELinux) |
| bind a TCP listener | no (SELinux inet) |
| `/proc/kallsyms` real values | no (kptr_restrict) |

So this is **uid 0 in a confined system domain**. SELinux is now the only wall.

## What is left, precisely

Every framework path is measured and walled. The only remaining route to "SELinux off / kernel
level" is **CVE-2023-4211** (Mali kbase tracking-page UAF write on `mm_struct`). A specialist
verified it against the **shipped `mali_kbase.ko`** (not just sources):

* bug present in the shipped binary: no `vma_pages()==1` check in `kbase_mmap`
* `mm->page_table_lock` @ `+0x3C`, `mm->rss_stat.count[MM_FILEPAGES]` @ `+0x154`
* kernel built **without** `SPLIT_RSS_COUNTING`, so the spinlock branch is real
* port delta: this driver rejects `PROT_NONE` tracking mmap (use `PROT_READ`), needs
  `VERSION_CHECK {10,6}`

Two safe phases are designed and compile:
* **phase A** (zero risk): steer the drain at a *live* child mm, so the kernel prints
  `BUG: Bad rss-counter state mm:<ptr> idx:0 val:-N` - confirms the whole trigger chain *and*
  leaks a kernel pointer, with no UAF.
* **phase B** (crash-safe): the race. `mm_struct` has a dedicated slab cache, so a mis-landed
  write can only hit another `mm_struct` (an RSS counter) - no oops.

Phase C (cross-cache to a PTE page for real kernel R/W) is the expensive part and needs its own
approved session.

## Also achieved this session

* `/dev/input/event0,1` are OPEN_RW to shell and **input injection works** (`sendevent` accepted,
  `getevent` captured the injected EV_KEY/SYN on `mtkinp_events`) - a UI-automation primitive.
* The `/dev/cli` MTK console is **disabled** by the driver ("cli device is disabled"), no enable
  path found (no module param, no sysfs node, no property; `ENABLE_MW_CLI=true` has no consumer).
* The vendor binder mount primitive (`mountISO`/`mountISOex`) is a **no-op** (log-only Java), but
  `DMRemoteService.partedDisk` reaches root `dtv_svc` through a confused deputy (destructive
  partition tool, not a shell).
* CVE-2021-28663, CVE-2021-28664, CVE-2021-44828 all ruled out on r20p0 by local-source and
  shipped-binary evidence.

---

## Persistence wiring (added, boot-time)

The console app's JNI patcher (`apkbuild/jni/pwn.c` -> now also carries the dumpstate hook) was
extended so the boot JobScheduler job re-applies **all three** page-cache patches:
`libc.so:0x25a90` (console payload), `libdumpstateutil.so:0x6200` (root stub),
`libdumpstateutil.so:0x6d10` (init_array pointer).

Important detail found while wiring it: the Mali primitive supports **one `pc_patch` per
process** (a second call in the same process hangs), so each patch is applied from a `fork()`ed
child. `apply_one()` does fork -> mali_setup -> one pc_patch -> _exit, parent waits.

Also observed: the app crashes with an ActivityManager error when it is already running as uid 0
("Package com.pwn.probe does not belong to <uid>"), so the patch path only runs at boot while the
page cache is clean and the app still has its normal uid - which is exactly the intended flow
(patch -> restart -> console as uid 0).

Page-cache patches are also **evictable under memory pressure**: during this session the
`libdumpstateutil.so` patches reverted on their own between runs, which is why the root payload
must be re-applied before a trigger if a lot has happened since. The manual helpers
(`/data/local/tmp/pB`, pP/pUid, pDSA/pDSB/pDST) remain the reliable way to re-apply on demand.

---

## Live confirmation (re-verified end to end)

After the page-cache patches were re-applied (`pDST` then `pDSA` on the device), one `adb bugreport`
produced:

```
=== ROOT CHANNEL LIVE Sun Oct 18 17:11:16 EDT 2026 ===
uid=0(root) gid=0(root) groups=0(root) context=u:r:dumpstate:s0
context: u:r:dumpstate:s0
enforce: Enforcing
host: BRAVIA 4K 2015 Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/OPR2...
uptime:  17:11:16 up  2:02,  0 users
```

That is a repeatable root command channel on the TV, triggered from a plain adb shell.

### Operational note: keep the ARM and Thumb stubs apart

The first helper built for `libdumpstateutil.so` (`pDSB`) contains the **ARM** stub
(`ff 00 2d e9 ...`) and the correct one (`pDST`) contains the **Thumb** stub (`ff b4 02 27 ...`).
Writing the ARM stub makes dumpstate die with SIGILL and the bugreport trigger then fails with
"Failed to connect to dumpstatez service" - which looks like an unrelated trigger problem but is
actually the wrong-instruction-set stub. Always verify the first 8 bytes at `0x6200` are
`ff b4 02 27 00 df 00 28` after patching.

### Current gap

SELinux. Root in `dumpstate` cannot write `/3rd_rw`, cannot `setenforce 0`, cannot load policy,
cannot touch block devices. The only remaining route is CVE-2023-4211 phase A -> B -> C
(tv-research/cve2023-4211). Phase A ran cleanly but produced no rss-counter BUG, so the trigger
precondition needs debugging (task-8).
