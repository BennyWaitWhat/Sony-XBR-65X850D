# 05 · Bonus research — uid 0 code execution in `u:r:zygote:s0`

Before settling on the app-based design, a more ambitious target was explored: getting code
to run inside **zygote itself**, which is `uid 0` and — critically — a much more privileged
SELinux domain.

## The insight

`setresuid` is called by zygote's **forked child, before `selinux_android_setcontext()`**.
At that moment the child is still in the **zygote domain** running as root. So any code
patched over `setresuid` executes as **root inside `u:r:zygote:s0`**.

That was confirmed by an SELinux denial — the most useful kind of success:

```console
avc: denied { execute } for name="sh" dev="mmcblk0p44" ino=772
    scontext=u:r:zygote:s0            ← our payload ran here, as root
    tcontext=u:object_r:shell_exec:s0
    tclass=file permissive=0
```

The payload had executed; it just was not allowed to `execve("/system/bin/sh")`.

## Measured capability matrix of the zygote domain

| Attempt | Result |
|---|---|
| uid | `0` ✅ |
| write `/data/dalvik-cache` | ✅ allowed |
| `execve("/system/bin/sh")` | ❌ `shell_exec` denied |
| `setexeccon` → transition to `system_server` | ❌ `{ setexec }` denied |
| binder / `ServiceManager.listServices()` | ❌ returns 0 services |
| `socket()` + `bind()` | ❌ `EACCES` |
| `/data/local/tmp`, `/data/system`, `/sdcard` | ❌ AVC denied |
| ART JIT (`execmem`) | ❌ AVC denied |
| **`execve("/system/bin/app_process")`** | ✅ **allowed** (`zygote_exec`) |

That last row is the interesting one: zygote *is* allowed to execute `app_process`, which
means **a full Android Java runtime can be started inside the zygote domain as uid 0**.

## Getting Java to run there — three non-obvious requirements

Payload: [`exploit/payloads/zygote-exec-app_process.s`](../exploit/payloads/zygote-exec-app_process.s)

1. **`app_process` takes the classpath from the `CLASSPATH` environment variable**, not from
   `argv[1]`. Android's own `/system/bin/am` is the proof:
   ```sh
   export CLASSPATH=/system/framework/am.jar
   exec app_process /system/bin com.android.commands.am.Am "$@"
   ```
   Passing the APK path as `argv[1]` produces
   `ClassNotFoundException … DexPathList[[]]`.

2. **Passing `envp = NULL` crashes inside ICU.** With no `ANDROID_DATA`, the runtime aborts in
   `ICURegistration::getTzDataOverridePath()`. The payload therefore reads
   `/proc/self/environ`, parses the NUL-separated block into a `char*[]`, prepends its own
   `CLASSPATH` entry, and passes that.

3. **The classpath file must be readable by zygote.** `/data/local/tmp` is
   `shell_data_file` → denied. The *installed APK*
   (`/data/app/com.pwn.probe-…/base.apk`, from `pm path`) **is** readable (it is
   `apk_data_file`), so that path works. Note the random suffix → derive it at runtime.

Resulting logcat, from our own code:

```console
I PWNSS : uid=0 pid=6147 ctx=u:r:zygote:s0
          /data/local/tmp=false /data/system=false /sdcard=false /data/dalvik-cache=true
          services=0 pkgbinder=false actbinder=false
          socketbind ERR java.net.SocketException: socket failed: EACCES
```

A JVM, running as root, in the zygote domain.

## Why the shipped artifact uses the app path instead

Zygote-domain code execution is *deeper* but has no usable I/O channel: no binder, no
sockets, cannot `sh`, cannot read app data. It is a great place to run code and a terrible
place to run a shell. The app-based design (uid 0 in `untrusted_app`, which *does* have a
network stack and the whole Android framework) is what actually delivers a usable root
console.

This research is kept because it is the most promising foothold for the next phase: a
process in the zygote domain with **no SELinux restriction on exec** would be a much better
launchpad than a sandboxed app.
