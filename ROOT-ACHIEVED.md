# ROOT: arbitrary code execution as uid 0 in `u:r:dumpstate:s0`

## What we got

Proof, captured on the device (16:58-16:59):

```
=== root? ===
uid=0(root) gid=0(root) groups=0(root) context=u:r:dumpstate:s0
context: u:r:dumpstate:s0
enforce: Enforcing
ppid: /system/bin/dumpstate -S -d -z -o /data/user_de/0/com.android.shell/files/bugreports/bugreport
```

Our script runs as **root inside the `dumpstate` SELinux domain**, forked from the real
`/system/bin/dumpstate` process, and dumpstate then completes normally ("done (id 3)").

## The method (page-cache patch + init-array hook, no kernel exploit)

1. `/system/lib/libdumpstateutil.so` is **readable by uid 2000** and is loaded *only* by
   `dumpstate`, which init runs as **root** (its service definition has no `user=` line).
2. The library's `.init_array` (file offset `0x6d10`, one 4-byte entry) holds `0x24d9`, a Thumb
   init function. The loader calls it on load.
3. Point that entry at a stub placed in the gap between the RX segment (`0x0..0x6132`) and the RW
   segment (`0x6d0c`). That gap lies inside the RX segment's page-rounded mapping (to `0x7000`)
   and belongs to no section, so it is free, mapped and executable. We used `0x6200`.
4. The stub forks: the child `execve`s `/system/bin/sh /data/local/tmp/r.sh` (running as root), the
   parent tail-jumps to the original init function so the library still initialises correctly.
5. Both edits are page-cache writes from uid 2000 (one `pc_patch` per process - two helpers), so
   nothing is written to disk and a reboot reverts everything.
6. Trigger: `adb bugreport`. It works again now (the earlier "Failed to connect to dumpstatez" was
   caused by the first, broken stub crashing dumpstate before its socket came up).

### Two bugs found and fixed along the way

* **Instruction set**: the first stub was ARM but `.init_array[0]` is a **Thumb** function, so the
  CPU entered it in Thumb state and raised SIGILL at `+2` (`fault addr ...6202`,
  `#00 pc 00006202 /system/lib/libdumpstateutil.so`). The stub must be Thumb.
* **Patch order**: the stub must be written before the pointer, same as the `sh` work.

## Capability matrix from the dumpstate domain (measured)

| operation | result |
|---|---|
| run arbitrary commands as uid 0 | **yes** |
| read `/data/system` (appops.xml, etc.) | **yes** (some entries denied) |
| write `/data/anr` | **yes** |
| write `/3rd_rw/sony` (persistent boot-exec path) | no (SELinux) |
| write `/3rd_rw` root dir | no (SELinux) |
| write `/odm/etc/service` | no (read-only filesystem) |
| write `/sys/fs/selinux/enforce` | no (SELinux) |
| remount `/system` rw | no (read-only block device + SELinux) |
| `/proc/kallsyms` real addresses | no (kptr_restrict) |

So this is **uid 0 in a system domain**, not SELinux-off. Reaching permissive/kernel-level still
requires the kernel route (CVE-2023-4211), which is now the only remaining blocker.

## Reverting

Reboot (page cache is dropped). Or apply the original 4 bytes to `libdumpstateutil.so:0x6d10`
(`0x24d9` = `d9 24 00 00`) with the same page-cache primitive.

## Files

* `payload/libdumpstateutil-stub-thumb.s` - the stub (Thumb, fork + exec + tail-jump)
* `poc/cli_drive.c` - the /dev/cli driver used to prove that device is disabled
* harness: `patcher4.c` template, one `pc_patch` per binary, stub written first
