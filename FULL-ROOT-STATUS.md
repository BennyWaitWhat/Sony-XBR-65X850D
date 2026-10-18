# Where full root stands

## Working, verified on the retail TV

* **uid 0 in `u:r:dumpstate:s0`** via a page-cache hook on `libdumpstateutil.so`
  (`.init_array[0]` -> Thumb stub in the 0x6132..0x6d0c cave -> fork; child execs
  `/system/bin/sh /data/local/tmp/r.sh` as root; parent chains to the original init).
  Trigger: `adb bugreport`. Re-applied with `pDST` then `pDSA`, both on the device.
* **`sys.svp.*` property control** from that root (denied to shell/app/zygote).
* **CVE-2023-4211 kernel write primitive confirmed**: phase B produced 12
  `BUG: Bad rss-counter state mm:<ptr> idx:0 val:+/-1028` lines, i.e. a 4-byte atomic add with
  attacker-controlled sign and magnitude at `freed_mm+0x154`, crash-safe thanks to the dedicated
  `mm_cachep` slab.

## SELinux is unbreakable from userspace (all measured)

| attempt | result |
|---|---|
| `/sys/fs/selinux/disable` | **EINVAL** - kernel built without `CONFIG_SECURITY_SELINUX_DISABLE` |
| `/sys/fs/selinux/enforce` write | denied |
| policy load (`/sys/fs/selinux/load`) | denied |
| `setcon` / `setexeccon` to `u:r:su:s0` | denied |
| permissive domains | none (0 `permissive=1` AVCs ever) |
| `/dev/__properties__` (to flip `ro.debuggable`) | denied even as uid 0 |
| kernel address leak (kallsyms, vmallocinfo, module sections, iomem) | all zeroed/denied |

## Two paths to Magisk-equivalent root, and where each got stuck

### A. adbd one-byte patch -> `adb root` -> `u:r:su:s0` (permissive)
The TV's adbd is started `--root_seclabel=u:r:su:s0`, so `adb root` yields a permissive-domain
shell. The only guard reads `ro.debuggable`; the property NAME string sits at adbd file offset
`0xd061e` and patching its last byte (`0xd062a`, 0x65 -> 0x58) makes the lookup fail and the guard
pass. `/sbin` is rootfs (ro), so the edit must be a page-cache write - and it has to execute inside
a library dumpstate loads, because shell cannot open `/sbin/adbd` while dumpstate root cannot exec
dropped binaries.

Built and installed a 1501-byte no-libc PIC patcher in the `libdumpstateutil` cave. It runs, but
**the chain back to the original init function fails**: taking `&adbd_cave_entry` is constant-folded
by the compiler, so the rebase collapses to the absolute link-time `0x24d9` (SIGSEGV at 0x24d8),
and the `adr`-based rewrite still lands wrong (fault 0x14). Returning to the loader directly was
also tried; the larger payload then crashed the GPU-write helper on install. Reverted to the working
Thumb stub each time - the root channel is intact.

Next step for A: put the tail-jump in a hand-written `.s` file rather than inline asm (a single
`adr r12, 1f` / `ldr r3, =delta` / `bx` block with the delta from a real assembler label), and
install the blob in two pieces if the 1.5 KB single-page GPU write is unreliable.

### B. kernel CVE-2023-4211 phase C -> arbitrary physical R/W -> clear `selinux_enforcing`
The endgame design is written (`endgame/DESIGN.md`, chosen approach B): `avc_denied()` in 3.10 grants
every non-`AVC_STRICT` denial when `selinux_enforcing` is 0, and the only strict call site is
`security_get_user_sids()` (PAM), so a single 4-byte zero store at `PA(selinux_enforcing)` = a full
SELinux bypass. The write address is found by locating the unique
`"enforcing=%d old_enforcing=%d auid=%u ses=%u"` string, validating kernel text via the `stext`
signature and `swapper_pg_dir` entries, then picking the value-1 candidate with multiple `.text`
cross-references and band/unicity rules.

Blocker: this needs the phase C heap/PTE landing, which is the risky part. The first armed attempt
made the TV unreachable at the network level (it stayed up - uptime continuous - but its LAN IP
changed), so it was not retried.
