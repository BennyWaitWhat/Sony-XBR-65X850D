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
