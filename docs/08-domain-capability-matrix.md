# 08 · Domain capability matrix — and the module-loading primitive

This is the round where the SELinux wall was finally measured properly, and where the way
through it was found.

## Method

Our existing `setresuid` hook runs in zygote's forked child **before** the context switch, so
we extended it into a *combined* payload:

```
r0 == 10014 (our app)     -> return 0                    (console keeps uid 0)
r0 == 1000  (system apps) -> run the probe, then real setresuid(208)
r0 == anything else       -> real setresuid(208)
```

The probe forks and `execve`'s `app_process` with a `CLASSPATH` pointing at our own APK, so
ordinary Java code runs as **`uid 0` in `u:r:zygote:s0`** and reports through logcat.

## What `u:r:zygote:s0` can and cannot reach

| Target | Result |
|---|---|
| `/proc/cmdline` | ✅ **readable** — full `mtdparts` table, `root=/dev/mmcblk0p5`, `gpustart=831950848`, `console=ttyMT0,115200n1` |
| `/proc/slabinfo` | ✅ readable |
| `/proc/kallsyms` | ⚠️ readable but **all values `00000000`** (`kptr_restrict` + no `CAP_SYSLOG`) |
| `/sys/fs/selinux/enforce` | ✅ read (returns `1`), ❌ **write denied** |
| `/sys/fs/selinux/policy` | ❌ denied |
| `/proc/self/attr/current` | ✅ → `u:r:zygote:s0` |
| `/dev/block`, `/dev/block/by-name` | ❌ **denied** — no partition access, so no vmlinux |
| `/proc/modules`, `/proc/timer_list` | ❌ denied |
| `/dev/mem`, `/dev/kmem` | absent |
| `execve(/system/bin/sh)` | ❌ `shell_exec` denied |
| `setexeccon` / transition to `system_server` | ❌ `{ setexec }` denied |
| `socket()` | ❌ `EACCES` |
| ART JIT (`execmem`), odex `execute` | ❌ denied |
| **`init_module()`** | ✅ **NOT denied** (see below) |

### Capabilities: why `CapEff` was zero, and the fix

`SetCapabilities()` runs **before** `setresuid` in zygote's child, so by the time our hook runs
the capabilities are already gone — and even if they were not, `execve` would drop them
because the **capability bounding set is empty** (`prctl(PR_CAPBSET_DROP)`), and the kernel's
"root exec gets permitted caps" special case is clipped by `cap_bset`.

The fix is to patch **`capset()`** (`libc` vaddr `0x49b18`, ARM) to return 0. Because that
happens *before* `setresuid`, the zygote child keeps the capability set it inherited from
zygote — **and `execve` is then not needed to use them.**

## The finding: we can load a kernel module

Test payload (`exploit/zygote-root-probe/init_module-test.s`), with `capset` patched:

1. attempt `init_module(garbage, 16, NULL)` (`__NR_init_module = 105`),
2. if the return value is `-EPERM`, follow the normal path silently,
3. otherwise fork and `exec` the Java probe (a visible signal).

Observed: **the probe appeared**, and the audit log contained **no `module_load` denial and no
capability denial** — only an unrelated `proc_modules` read denial. So:

* `capset` patched ⇒ the zygote child really does carry `CAP_SYS_MODULE` ✅
* SELinux **permits `module_load` from `u:r:zygote:s0`** ✅
* the call failed only because the image was garbage (`ENOEXEC`), not for permission reasons ✅

**A loadable kernel module is arbitrary kernel code.** This removes every remaining blocker at
once: no symbol leak, no PTE grooming, no `selinuxfs` write. A module can call
`kallsyms_lookup_name()` itself and simply clear `selinux_enforcing`.

## Plan for the module

1. Take an existing `.ko` from `/vendor/lib/modules/` (readable from shell) so the
   **vermagic** matches `3.10.79` exactly.
2. Offline ELF surgery: replace `.text` with our init code, and retarget one relocation's
   symbol name to **`kallsyms_lookup_name`** (a GPL-only export, so the module gets a GPL
   `license` in `.modinfo`).
3. Deliver the image somewhere the zygote child can read — `/data/dalvik-cache/…` works
   (zygote may write it), or embed it in the two pages of `libc.so` page cache we can already
   patch.
4. Payload (with `capset` patched): `read(image)` → `init_module(image, len, "")`.
5. Module `init_module()`: `p = kallsyms_lookup_name("selinux_enforcing"); *(int *)p = 0;`
   → SELinux becomes permissive system-wide.
6. With SELinux off: remount `/system`, install a real init service, and persistence stops
   depending on the page-cache trick entirely.

Risks, stated plainly: `panic_on_oops=1`, so a malformed module or a bad pointer is an instant
reboot. A *rejected* module (`Invalid module format`, vermagic mismatch) is completely safe,
which is why the vermagic must be copied from a shipping module rather than guessed.
