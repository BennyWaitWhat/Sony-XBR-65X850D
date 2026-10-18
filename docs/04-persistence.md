# 04 · Persistence — surviving the reboot

Goal: after a cold boot, **with no human in the loop**, the device ends up with a uid-0
process and a listening root console again.

## Design

Three pieces:

1. **The patcher ships inside the APK as a JNI library** — the exploit needs
   `open/mmap/mremap/ioctl`, which pure Java cannot do.
2. A **persisted `JobScheduler` job** re-runs it at boot (BOOT_COMPLETED does not reach this
   app — see below).
3. After patching, the app **kills itself and schedules its own restart**, so the *next*
   process is forked by zygote and keeps uid 0. A foreground service then hosts the console.

## 1. The JNI patcher

`apk/jni/pwn.c` exports:

```c
JNIEXPORT jint JNICALL Java_com_pwn_probe_Main_applyPatches(JNIEnv *env, jclass cls)
{
    /* patch 1: payload at 0x25a90   (fresh mali context per page) */
    /* patch 2: branch   at 0x4a990  */
    return (r1 == 0 && r2 == 0) ? 1 : (r1 * 100 + r2);
}
```

> ⚠️ **Build the .so with `-D_FILE_OFFSET_BITS=64`.**
> Without it `off_t` is 32-bit, the 64-bit GPU VA used as an `mmap()` offset gets
> truncated, and the event-region mmap fails with `ENOMEM (12)`. This looked exactly like
> a SELinux denial for one debugging cycle — it was not (`avc` was silent).

Packaged as `lib/armeabi-v7a/libpwn.so` inside the APK, loaded with
`System.loadLibrary("pwn")`.

## 2. Boot trigger: BOOT_COMPLETED does not work here

A `BOOT_COMPLETED` receiver was registered, the permission was granted, the app was **not**
in the stopped state — and the broadcast was simply never dispatched to this sideloaded app
on this TV. Evidence:

```console
$ adb shell dumpsys package com.pwn.probe | grep -E "stopped=|RECEIVE_BOOT"
      android.permission.RECEIVE_BOOT_COMPLETED      (granted=true)
      User 0: ... stopped=false notLaunched=false enabled=0
$ adb shell logcat -d | grep -i com.pwn.probe      # at boot: nothing from AMS
```

Meanwhile Sony's own apps received it normally. So the working trigger is a **persisted job**:

```java
new JobInfo.Builder(1, new ComponentName(c, BootJobService.class))
    .setPersisted(true)        // survives reboot, re-scheduled by the system
    .setMinimumLatency(1500)   // run ~immediately after boot
    .build();
```

> ⚠️ **Second gotcha:** jobs must be scheduled by a process running as the app's *normal*
> uid. A uid-0 process cannot schedule:
> `IllegalArgumentException: uid 0 cannot schedule job in com.pwn.probe`.
> The job therefore **re-arms itself** on every run, so there is always a pending job for the
> next boot.

## 3. The boot flow

```
cold boot
  └─ JobScheduler runs BootJobService            uid 10014  (normal)
       ├─ scheduleJob(this)                      → re-arm for the next boot
       ├─ applyPatches()                         → JNI: page-cache patch, returns 1
       ├─ AlarmManager.setExact(now + 3s)        → PendingIntent → BootReceiver
       └─ Process.killProcess(myPid())           → die, so the next process is fresh
            └─ alarm fires
                 └─ BootReceiver in a NEW process  uid 0   ← targeted setresuid patch
                      ├─ startForegroundService(ConsoleService)
                      └─ console listening on :4445
```

## Verification

Clean reboot, no manual commands, then:

```console
$ adb shell od -An -tx1 -j 0x4a990 -N 4 /system/lib/libc.so
 3e 6c ff ea                     ← patch re-applied automatically
$ adb shell ps -A -o PID,UID,NAME | grep pwn
 5024     0 com.pwn.probe        ← uid 0
```

and over a tailnet:

```console
BANNER: OK uid=0 pid=5024
uid=0(root) gid=10014(u0_a14) ...
PERSISTENT_ROOT_OK
```

Self-healing details: `ConsoleService` is a **foreground service** with `START_STICKY`, so
the console also survives the app being backgrounded (verified while a streaming app was in
the foreground).

## Removing it

```bash
adb uninstall com.pwn.probe
adb reboot          # clears the page cache → libc.so is pristine again
```

Nothing outside the app is modified on disk at any point.
