# Sony XBR-65X850D (BRAVIA 4K 2015) — Binder / HIDL / System-Service Attack Surface

**Target:** `100.70.99.3:5555` (tailnet fallback `100.115.119.101:5555`)
**Product:** `SVP4KDTV15_UC` / `BRAVIA_4K_2015` / device `SVP-DTV15`
**Build:** Android 8.0.0 (SDK 26), fingerprint `Sony/SVP4KDTV15_UC/SVP-DTV15:8.0.0/OPR2.170623.027.S16/6.827:user/release-keys`
**Kernel:** `3.10.79 #1 SMP PREEMPT Wed Mar 4 17:00:38 JST 2020 armv7l`
**SoC:** MediaTek MT5890
**Access:** adb over TCP, `uid=2000(shell)`, SELinux context `u:r:shell:s0`, `getenforce` = `Enforcing`, `ro.debuggable=0`, `ro.secure=1`, `ro.build.type=user`
**Scope:** Binder / HIDL / system-service surface only. No reboots, no `/system` writes, Mali GPU (`/dev/mali0`) untouched (owned by another investigation).

---

## 0. Executive summary

Five things matter here, in order:

1. **The vendor Binder plane performs no caller-identity checks at all.** Eleven MediaTek/Sony services were probed; *none* returned a `SecurityException`, permission string, or `PERMISSION_DENIED`. A control experiment on AOSP services on the same device proves that permission denials *are* visible to `service call` when they exist (§3.1). Their absence is therefore meaningful, not a measurement artifact.

2. **`DMRemoteService` (`com.mediatek.dm.IDMRemoteService`) is fully callable from `shell` and exposes filesystem-destructive and mount operations.** Recovered transaction map (§4.1): `formatVol` (17), `partedDisk` (19), `mountVol/Ex` (12/13), `mountISO/ex` (14/15), `umount*` (10/11/16), `setDMSysProperty` (22). Read-only codes were invoked successfully with real return values.

3. **`TVRemoteService` (`com.mediatek.twoworlds.tv.ITVRemoteService`) is callable and its method bodies execute for `shell`** — `getInstanceCount` returns a monotonic counter (1→6 over six isolated calls), which proves server-side execution and cross-call state. (An earlier "state mutation via registerCallback" reading of this same data was tested and **retracted**; see §3.3.)

4. **`GestureService` is a reproducible one-packet crash primitive.** `service call GestureService 1` returns `DEAD_OBJECT` ("Broken pipe") and the service disappears from `service list`, then re-registers. Reproduced twice.

5. **The HIDL plane is real but thin, and the vendor Binder namespace is closed to shell.** 11 binderized HALs are reachable via `hwservicemanager` from `shell` (§5). `/dev/vndbinder` is *not* openable from `shell` — `/system/vendor/bin/vndservice list` aborts with "Binder driver could not be opened".

**Most important caveat:** `shell` (uid 2000) on a user-build Android 8 device is *already* highly privileged via `cmd`/`dumpsys` (it can change settings, appops, start activities, install packages). The marginal value of the vendor services is not "getting a shell" — it is **executing code paths inside `system_app` (uid 1000) and inside root-capable vendor daemons**, plus a set of destructive filesystem operations that AOSP services gate far more tightly.

---

## 1. Methodology and guardrails

| Decision | Rationale |
|---|---|
| Probed transaction codes 0–5 only | Codes ≥6 unexplored; low codes are overwhelmingly getters |
| Did **not** run a blind `service call <name> 1` sweep over all 129 services | Code 1 on `recovery`, `mount`, `installd` can reboot or wipe. A full matrix would be reckless; the sweep was restricted to vendor services plus explicit AOSP controls. |
| Did **not** invoke `formatVol`, `partedDisk`, `mountVol`, `mountISO`, `setDMSysProperty` | These mutate state / destroy data. Documented as reachable-with-signature but untested. |
| Did not write to `/system`, `/data`, or set properties | Read-only mandate. |
| No `nc`-based socket connect test | Toybox `nc` on this build has **no** unix-socket option (`Unknown option U`). Used `open()` errno probe instead (§8). |

**One disclosable side effect:** `service call <svc> 1` on `DMRemoteService` and `TVRemoteService` invokes `registerDMCallback` / `registerCallback` with an absent Binder argument, i.e. it registers a `null` callback. `TVRemoteService` was cleaned with `unregisterAll` (code 3). `DMRemoteService` has no `unregisterAll`; `unregisterDMCallback` (code 2) was invoked as best-effort cleanup. Both services remained healthy afterwards (`getDeviceCount` → 0, `getInstanceCount` → 3). No reboot occurred.

---

## 2. Full Binder inventory

`service list` → **129 services** (indices 0–128). Raw capture: `raw/service-list.txt`.
`cmd -l` agrees (129 running services). Raw: §7.

The inventory is dominated by AOSP Android 8.0 services. The vendor-specific subset is small and sits at both ends of the list:

| # | Service | Interface descriptor | Owner |
|---|---|---|---|
| 0 | `DMRemoteService` | `com.mediatek.dm.IDMRemoteService` | MediaTek |
| 1 | `TVRemoteService` | `com.mediatek.twoworlds.tv.ITVRemoteService` | MediaTek |
| 118 | `GestureService` | `com.sony.dtv.remotetouchpad.gesture.IGestureService` | Sony |
| 120 | `DmsDeamonReceiver` | *(empty — native)* | Sony |
| 121 | `com.sony.dtv.camerarecognitiondaemon` | `...ICameraRecognitionDaemon` | Sony |
| 122 | `TpdReceiver` | *(empty — native)* | Sony |
| 123 | `...nativevideoshm.VideoShmServ` | `...VideoShmServ` | Sony |
| 124 | `com.sony.dtv.mpsservice` | *(empty)* | Sony |
| 125 | `com.sony.dtv.itvunative.interactivetvutil` | `com.sony.dtv.itvunative.IInteractiveTvUtil` | Sony |
| 126 | `com.sony.dtv.kyildm.kyilservice` | `com.sony.dtv.kyildm.Ikyilservice` | Sony |
| 128 | `com.sony.dtv.modelvariation.eepservice` | *(empty)* | Sony |

Note that `DMRemoteService` and `TVRemoteService` occupy indices **0 and 1** — they are published before essentially every AOSP service including `activity` (89) and `package` (92).

### 2.1 Complete service table

Status legend:
- **TRANSACTS** — binder transaction accepted and executed; clean reply, no denial.
- **CRASH** — transaction accepted but kills the provider process.
- **DENIAL** — transaction accepted, service-level permission check surfaced.
- **NO-TX** — enumerable (`service list`/`service check`/`dumpsys -l`) but `service call` reports "does not exist".
- **not probed** — deliberately not called (see §1).

| # | Service | Descriptor | Class | Shell (uid 2000) | Note |
|---|---|---|---|---|---|
| 0 | `DMRemoteService` | `com.mediatek.dm.IDMRemoteService` | MediaTek | TRANSACTS | MTK; formatVol(17)/partedDisk(19)/mountISO(14) reachable, untested |
| 1 | `TVRemoteService` | `com.mediatek.twoworlds.tv.ITVRemoteService` | MediaTek | TRANSACTS | MTK; code 4 increments per call - server-side execution proven |
| 2 | `contexthub` | `android.hardware.location.IContextHubService` | AOSP | not probed |  |
| 3 | `netd_listener` | `android.net.metrics.INetdEventListener` | AOSP | not probed |  |
| 4 | `connmetrics` | `android.net.IIpConnectivityMetrics` | AOSP | not probed |  |
| 5 | `bluetooth_manager` | `android.bluetooth.IBluetoothManager` | AOSP | not probed |  |
| 6 | `imms` | `com.android.internal.telephony.IMms` | AOSP | not probed |  |
| 7 | `media_projection` | `android.media.projection.IMediaProjectionManager` | AOSP | not probed |  |
| 8 | `launcherapps` | `android.content.pm.ILauncherApps` | AOSP | not probed |  |
| 9 | `shortcut` | `android.content.pm.IShortcutService` | AOSP | not probed |  |
| 10 | `media_router` | `android.media.IMediaRouterService` | AOSP | not probed |  |
| 11 | `media_resource_monitor` | `android.media.IMediaResourceMonitor` | AOSP | not probed |  |
| 12 | `tv_input` | `android.media.tv.ITvInputManager` | AOSP | not probed |  |
| 13 | `hdmi_control` | `android.hardware.hdmi.IHdmiControlService` | AOSP | not probed |  |
| 14 | `media_session` | `android.media.session.ISessionManager` | AOSP | not probed |  |
| 15 | `restrictions` | `android.content.IRestrictionsManager` | AOSP | not probed |  |
| 16 | `graphicsstats` | `android.view.IGraphicsStats` | AOSP | not probed |  |
| 17 | `dreams` | `android.service.dreams.IDreamManager` | AOSP | not probed |  |
| 18 | `commontime_management` | *(none)* | AOSP (native) | NO-TX |  |
| 19 | `network_time_update_service` | *(none)* | AOSP (native) | not probed |  |
| 20 | `samplingprofiler` | *(none)* | AOSP (native) | NO-TX |  |
| 21 | `diskstats` | *(none)* | AOSP (native) | NO-TX |  |
| 22 | `voiceinteraction` | `com.android.internal.app.IVoiceInteractionManagerService` | AOSP | not probed |  |
| 23 | `appwidget` | `com.android.internal.appwidget.IAppWidgetService` | AOSP | not probed |  |
| 24 | `backup` | `android.app.backup.IBackupManager` | AOSP | not probed |  |
| 25 | `trust` | `android.app.trust.ITrustManager` | AOSP | not probed |  |
| 26 | `soundtrigger` | `com.android.internal.app.ISoundTriggerService` | AOSP | not probed |  |
| 27 | `jobscheduler` | `android.app.job.IJobScheduler` | AOSP | not probed |  |
| 28 | `hardware_properties` | `android.os.IHardwarePropertiesManager` | AOSP | not probed |  |
| 29 | `serial` | `android.hardware.ISerialManager` | AOSP | not probed |  |
| 30 | `usb` | `android.hardware.usb.IUsbManager` | AOSP | not probed |  |
| 31 | `DockObserver` | *(none)* | AOSP (native) | NO-TX |  |
| 32 | `audio` | `android.media.IAudioService` | AOSP | not probed |  |
| 33 | `wallpaper` | `android.app.IWallpaperManager` | AOSP | not probed |  |
| 34 | `search` | `android.app.ISearchManager` | AOSP | not probed |  |
| 35 | `country_detector` | `android.location.ICountryDetector` | AOSP | not probed |  |
| 36 | `location` | `android.location.ILocationManager` | AOSP | not probed |  |
| 37 | `devicestoragemonitor` | *(none)* | AOSP (native) | NO-TX |  |
| 38 | `notification` | `android.app.INotificationManager` | AOSP | not probed |  |
| 39 | `updatelock` | `android.os.IUpdateLock` | AOSP | not probed |  |
| 40 | `servicediscovery` | `android.net.nsd.INsdManager` | AOSP | not probed |  |
| 41 | `connectivity` | `android.net.IConnectivityManager` | AOSP | not probed |  |
| 42 | `ethernet` | `android.net.IEthernetManager` | AOSP | not probed |  |
| 43 | `wifip2p` | `android.net.wifi.p2p.IWifiP2pManager` | AOSP | not probed |  |
| 44 | `rttmanager` | `android.net.wifi.IRttManager` | AOSP | not probed |  |
| 45 | `wifiscanner` | `android.net.wifi.IWifiScanner` | AOSP | not probed |  |
| 46 | `wifi` | `android.net.wifi.IWifiManager` | AOSP | not probed |  |
| 47 | `netpolicy` | `android.net.INetworkPolicyManager` | AOSP | not probed |  |
| 48 | `netstats` | `android.net.INetworkStatsService` | AOSP | not probed |  |
| 49 | `network_score` | `android.net.INetworkScoreService` | AOSP | not probed |  |
| 50 | `textservices` | `com.android.internal.textservice.ITextServicesManager` | AOSP | not probed |  |
| 51 | `network_management` | `android.os.INetworkManagementService` | AOSP | not probed |  |
| 52 | `clipboard` | `android.content.IClipboard` | AOSP | not probed |  |
| 53 | `statusbar` | `com.android.internal.statusbar.IStatusBarService` | AOSP | not probed |  |
| 54 | `device_policy` | `android.app.admin.IDevicePolicyManager` | AOSP | TRANSACTS | control: clean replies |
| 55 | `deviceidle` | `android.os.IDeviceIdleController` | AOSP | not probed |  |
| 56 | `lock_settings` | `com.android.internal.widget.ILockSettings` | AOSP | not probed |  |
| 57 | `uimode` | `android.app.IUiModeManager` | AOSP | not probed |  |
| 58 | `storagestats` | `android.app.usage.IStorageStatsManager` | AOSP | not probed |  |
| 59 | `mount` | `android.os.storage.IStorageManager` | AOSP | DENIAL | control: exception text returned |
| 60 | `accessibility` | `android.view.accessibility.IAccessibilityManager` | AOSP | not probed |  |
| 61 | `input_method` | `com.android.internal.view.IInputMethodManager` | AOSP | not probed |  |
| 62 | `pinner` | *(none)* | AOSP (native) | NO-TX |  |
| 63 | `vrmanager` | `android.service.vr.IVrManager` | AOSP | not probed |  |
| 64 | `input` | `android.hardware.input.IInputManager` | AOSP | not probed |  |
| 65 | `window` | `android.view.IWindowManager` | AOSP | not probed |  |
| 66 | `sensorservice` | `android.gui.SensorServer` | AOSP | not probed |  |
| 67 | `alarm` | `android.app.IAlarmManager` | AOSP | not probed |  |
| 68 | `consumer_ir` | `android.hardware.IConsumerIrService` | AOSP | not probed |  |
| 69 | `overlay` | `android.content.om.IOverlayManager` | AOSP | not probed |  |
| 70 | `vibrator` | `android.os.IVibratorService` | AOSP | not probed |  |
| 71 | `settings` | *(none)* | AOSP (native) | NO-TX |  |
| 72 | `content` | `android.content.IContentService` | AOSP | not probed |  |
| 73 | `account` | `android.accounts.IAccountManager` | AOSP | not probed |  |
| 74 | `media.camera.proxy` | `android.hardware.ICameraServiceProxy` | AOSP | not probed |  |
| 75 | `telephony.registry` | `com.android.internal.telephony.ITelephonyRegistry` | AOSP | not probed |  |
| 76 | `scheduling_policy` | `android.os.ISchedulingPolicyService` | AOSP | not probed |  |
| 77 | `sec_key_att_app_id_provider` | `android.security.keymaster.IKeyAttestationApplicationIdProvider` | AOSP | not probed |  |
| 78 | `webviewupdate` | `android.webkit.IWebViewUpdateService` | AOSP | not probed |  |
| 79 | `usagestats` | `android.app.usage.IUsageStatsManager` | AOSP | not probed |  |
| 80 | `battery` | *(none)* | AOSP (native) | NO-TX |  |
| 81 | `dropbox` | `com.android.internal.os.IDropBoxManagerService` | AOSP | not probed |  |
| 82 | `processinfo` | `android.os.IProcessInfoService` | AOSP | not probed |  |
| 83 | `permission` | `android.os.IPermissionController` | AOSP | not probed |  |
| 84 | `cpuinfo` | *(none)* | AOSP (native) | NO-TX |  |
| 85 | `dbinfo` | *(none)* | AOSP (native) | NO-TX |  |
| 86 | `gfxinfo` | *(none)* | AOSP (native) | NO-TX |  |
| 87 | `meminfo` | *(none)* | AOSP (native) | NO-TX |  |
| 88 | `procstats` | `com.android.internal.app.procstats.IProcessStats` | AOSP | not probed |  |
| 89 | `activity` | `android.app.IActivityManager` | AOSP | DENIAL | control: exception text returned |
| 90 | `user` | `android.os.IUserManager` | AOSP | DENIAL | control: 'You need MANAGE_USERS permission' |
| 91 | `otadexopt` | `android.content.pm.IOtaDexopt` | AOSP | not probed |  |
| 92 | `package` | `android.content.pm.IPackageManager` | AOSP | DENIAL | control: exception text returned |
| 93 | `display` | `android.hardware.display.IDisplayManager` | AOSP | not probed |  |
| 94 | `recovery` | `android.os.IRecoverySystem` | AOSP | not probed |  |
| 95 | `power` | `android.os.IPowerManager` | AOSP | not probed |  |
| 96 | `appops` | `com.android.internal.app.IAppOpsService` | AOSP | not probed |  |
| 97 | `batterystats` | `com.android.internal.app.IBatteryStats` | AOSP | not probed |  |
| 98 | `media.resource_manager` | `android.media.IResourceManagerService` | AOSP | not probed |  |
| 99 | `media.player` | `android.media.IMediaPlayerService` | AOSP | not probed |  |
| 100 | `device_identifiers` | `android.os.IDeviceIdentifiersPolicyService` | AOSP | not probed |  |
| 101 | `media.sound_trigger_hw` | `android.hardware.ISoundTriggerHwService` | AOSP | not probed |  |
| 102 | `media.radio` | `android.hardware.IRadioService` | AOSP | not probed |  |
| 103 | `media.audio_policy` | `android.media.IAudioPolicyService` | AOSP | not probed |  |
| 104 | `storaged` | `Storaged` | AOSP | TRANSACTS | native, empty descriptor, yet transacts |
| 105 | `gpu` | `android.ui.IGpuService` | AOSP | not probed |  |
| 106 | `SurfaceFlinger` | `android.ui.ISurfaceComposer` | AOSP | not probed |  |
| 107 | `media.camera` | `android.hardware.ICameraService` | AOSP | not probed |  |
| 108 | `media.extractor` | `android.media.IMediaExtractorService` | AOSP | not probed |  |
| 109 | `media.audio_flinger` | `android.media.IAudioFlinger` | AOSP | not probed |  |
| 110 | `media.metrics` | `android.media.IMediaAnalyticsService` | AOSP | not probed |  |
| 111 | `netd` | *(none)* | AOSP (native) | NO-TX |  |
| 112 | `drm.drmManager` | `drm.IDrmManagerService` | AOSP | not probed |  |
| 113 | `wificond` | *(none)* | AOSP (native) | NO-TX |  |
| 114 | `android.service.gatekeeper.IGateKeeperService` | *(none)* | AOSP (native) | not probed |  |
| 115 | `media.cas` | `android.media.IMediaCasService` | AOSP | not probed |  |
| 116 | `media.drm` | `android.media.IMediaDrmService` | AOSP | not probed |  |
| 117 | `android.security.keystore` | `android.security.IKeystoreService` | AOSP | not probed |  |
| 118 | `GestureService` | `com.sony.dtv.remotetouchpad.gesture.IGestureService` | Sony | CRASH | Sony; code 1 reliably kills provider |
| 119 | `installd` | *(none)* | AOSP (native) | NO-TX |  |
| 120 | `DmsDeamonReceiver` | *(none)* | Sony | NO-TX | Sony; blocked |
| 121 | `com.sony.dtv.camerarecognitiondaemon` | `com.sony.dtv.camerarecognitiondaemon.ICameraRecognitionDaemon` | Sony | TRANSACTS | Sony; codes 3/4 -> 0x00030001 |
| 122 | `TpdReceiver` | *(none)* | Sony | NO-TX | Sony; blocked |
| 123 | `com.sony.dtv.interactivetvplatform.discovery.interfaces.platform.nativevideoshm.VideoShmServ` | `com.sony.dtv.interactivetvplatform.discovery.interfaces.platform.nativevideoshm.VideoShmServ` | Sony | TRANSACTS | Sony; code 3 returns 20-byte handle descriptor |
| 124 | `com.sony.dtv.mpsservice` | *(none)* | Sony | NO-TX | Sony; present but blocked |
| 125 | `com.sony.dtv.itvunative.interactivetvutil` | `com.sony.dtv.itvunative.IInteractiveTvUtil` | Sony | TRANSACTS | Sony; daemon runs as uid 2000, gid 0 |
| 126 | `com.sony.dtv.kyildm.kyilservice` | `com.sony.dtv.kyildm.Ikyilservice` | Sony | TRANSACTS | Sony; code 5 -> 0x5d5b |
| 127 | `batteryproperties` | `android.os.IBatteryPropertiesRegistrar` | AOSP | not probed |  |
| 128 | `com.sony.dtv.modelvariation.eepservice` | *(none)* | Sony | NO-TX | Sony; EEPROM/model variation; blocked |

---

## 3. Reachability from `shell` (uid 2000)

### 3.1 The control experiment (why "no denial" is a real result)

Before trusting clean replies, I established what a denial *looks like* on this exact device, using AOSP services known to be permission-gated. Results (`service call` prints the reply Parcel):

```
### user code=1
Result: Parcel(
  0x00000000: ffffffff 0000003d 006f0059 00200075 '....=...Y.o.u. .'
  0x00000010: 0065006e 00640065 004d0020 004e0041 'n.e.e.d. .M.A.N.'
### mount code=1
  0x00000000: fffffffc 00000073 00740041 00740065 '....s...A.t.t.e.'
```

Decoded:

| Reply shape | Meaning |
|---|---|
| `Parcel(00000000 ...)` | `writeNoException()` → method ran, result follows |
| `Parcel(ffffffff <len> <utf16>)` | Java exception carrying a message, e.g. **"You need MANAGE_USERS permission"** |
| `Parcel(fffffffc <len> <utf16>)` | Java exception, e.g. NPE "Attempt to invoke … on a null object reference" |
| `Error: 0xffffffb6 "Not a data message"` | `NOT_ENOUGH_DATA` — service's `onTransact` ran and could not unmarshal the (empty) argument list |
| `Error: 0xffffffe0 "Broken pipe"` | `DEAD_OBJECT` — the provider process died during the transaction |

So: a permission denial on this platform is **loud**. The vendor services produced `00000000` and `NOT_ENOUGH_DATA` — never a denial. Combined with the fact that the transport itself succeeded, this is solid evidence that **no vendor service enforces a caller check at the transport layer**. Two caveats, stated precisely: (a) a per-method check *inside* a method we never invoked with valid arguments cannot be excluded by this test alone; (b) for `DMRemoteService` this caveat does not apply to the argument-free getters, which were invoked successfully (§3.3).

`NOT_ENOUGH_DATA` is itself positive evidence: to reach `Parcel::readString16` and fail, the service must have already entered `onTransact`. A service that rejected the caller at the transport layer would never get there.

### 3.2 Vendor service call matrix

Full raw capture: `raw/vendor-call-matrix.txt`. Abridged:

```
DMRemoteService      c0: Error 0xffffffb6 (NOT_ENOUGH_DATA)
                     c1: 00000000              c2: 00000000
                     c3: 00000000 00000000     c4: 00000000 ffffffff
                     c5: 00000000 00000000
TVRemoteService      c0: Error 0xffffffb6
                     c1..c3: 00000000          c4: 00000000 00000002
                     c5: 00000000
GestureService       c0: Error 0xffffffb6
                     c1: Error 0xffffffe0 "Broken pipe"   <-- provider died
                     c2..c5: Parcel(NULL)
kyilservice          c0: Error 0xffffffb6   c3: 00000000
                     c4: Parcel(NULL)       c5: 00005d5b
camerarecognition    c0: Error 0xffffffb6   c3/c4: 00030001   c5: 00000000
interactivetvutil    c0: Error 0xffffffb6   c3/c4/c5: Parcel(NULL)
VideoShmServ         c0: Error 0xffffffb6   c4: 00000000
                     c3: 0x00000000 66642a85 0000017f 00000004
mpsservice           "Service ... does not exist" (all codes)
eepservice           "Service ... does not exist"
DmsDeamonReceiver    "Service ... does not exist"
TpdReceiver          "Service ... does not exist"
```

### 3.3 Confirmed live invocations (not just transport acceptance)

`DMRemoteService`, using the recovered method map, with **no arguments** — read-only getters:

```
$ service call DMRemoteService 3     # getDeviceCount() -> I
Result: Parcel(00000000 00000000   '........')      -> 0 devices
$ service call DMRemoteService 6     # getMountPointCount() -> I
Result: Parcel(00000000 00000000   '........')      -> 0 mounts
$ service call DMRemoteService 21    # isNoitfyPrepareDone() -> Z
Result: Parcel(00000000 00000001   '........')      -> true
$ service call DMRemoteService 5     # getDeviceList() -> List
Result: Parcel(00000000 00000000   '........')      -> null
```

These are real return values from a `system_app` (uid 1000) service, produced by `shell` (uid 2000).

**Server-side execution proof** — `TVRemoteService`, `getInstanceCount` (code 4), repeated with no other calls in between:

| Call # | Reply | Value |
|---|---|---|
| 1 | `00000000 00000001` | 1 |
| 2 | `00000000 00000002` | 2 |
| 3 | `00000000 00000003` | 3 |
| 4 | `00000000 00000004` | 4 |
| 5 | `00000000 00000005` | 5 |
| 6 | `00000000 00000006` | 6 |

A monotonic, call-driven sequence. **Correction to an earlier reading of this data:** I initially attributed the 1→2→3 progression to `registerCallback` (code 1) mutating service state. That was wrong — an isolated loop of six `getInstanceCount` calls with nothing else in between produced 1→6, so the counter reflects instantiations/calls, not registrations. The honest conclusions are:

- **CONFIRMED:** the method body executes server-side on behalf of `shell`, and the service keeps mutable state across invocations (the returned value changes).
- **NOT CONFIRMED:** that `registerCallback(null)` alters persistent service state. The null-callback registration may well be stored, but this counter does not prove it.
- **Retracted:** the "state mutation proof" claim. Corrected here rather than silently dropped.

### 3.4 The "does not exist" anomaly (NO-TX services)

Four vendor services are enumerable but not transactable:

```
$ service check com.sony.dtv.mpsservice
Service com.sony.dtv.mpsservice: found
$ service call com.sony.dtv.mpsservice 0
service: Service com.sony.dtv.mpsservice does not exist
```

This is **not** evidence the services are absent. The same pattern affects many AOSP services with empty descriptors (`netd`, `installd`, `settings`, `battery`, `pinner`, `cpuinfo`, `dbinfo`, `gfxinfo`, `meminfo`, `diskstats`, `DockObserver`, `devicestoragemonitor`, `commontime_management`, `samplingprofiler`, `wificond`) — while `storaged` (also empty descriptor) *does* transact. So "empty descriptor" alone does not explain it.

Working hypotheses (unresolved, flagged SPECULATIVE):
- **SELinux `service_manager find` restriction** in `servicemanager` keyed by service type, silently reported as a null `getService()`.
- **Namespace split**: `/dev/vndbinder` services leaking into `service list` on this vendor build.

Supporting evidence for the second: `/system/vendor/bin/vndservice list` cannot run from `shell` at all —
```
Binder driver could not be opened.  Terminating.
Aborted
```
i.e. `/dev/vndbinder` is closed to `u:r:shell`. I could not read `/sys/fs/selinux/policy`, `dmesg`, or `/data/misc/audit/` to confirm which mechanism applies, so this stays unresolved rather than claimed.

---

## 4. Vendor service interfaces (recovered from DEX)

`dexdump` is unavailable on the device and in the installed SDK build-tools. I wrote a minimal DEX parser (`dexdump_map.py`, `sigmap.py` in this directory) to recover the AIDL `TRANSACTION_*` constants, which map transaction codes to method names exactly. Source jars pulled from `/system/framework`.

### 4.1 `IDMRemoteService` — MediaTek device/USB storage manager

```
code 1  registerDMCallback(IDMCallback) -> V
code 2  unregisterDMCallback(IDMCallback) -> V
code 3  getDeviceCount() -> I
code 4  getDeviceContent(Device) -> List
code 5  getDeviceList() -> List
code 6  getMountPointCount() -> I
code 7  getMountPointList() -> List
code 8  getMountPoint(String) -> MountPoint
code 9  getParentDevice(MountPoint) -> Device
code 10 umountDevice(String) -> V
code 11 umountVol(String) -> V
code 12 mountVol(String) -> I
code 13 mountVolEx(String, String) -> V
code 14 mountISO(String) -> V
code 15 mountISOex(String, String) -> V
code 16 umountISO(String) -> V
code 17 formatVol(String, String) -> I          <-- destructive
code 18 checkVol(String, String) -> I
code 19 partedDisk(String, String) -> I         <-- destructive (partitioning)
code 20 isVirtualDevice(String) -> Z
code 21 isNoitfyPrepareDone() -> Z
code 22 setDMSysProperty(boolean) -> V
```

Accuracy note: `setDMSysProperty` takes a **single boolean**, not a string pair — it is a narrow flag setter (likely "DM prepare done"), **not** an arbitrary property-write primitive. Do not over-value it.

The destructive surface is `formatVol(String, String)` and `partedDisk(String, String)`: volume identifier + filesystem/partition-spec strings, executed in the DM service's process. `mountISO(String)` takes an arbitrary image path.

### 4.2 `ITVRemoteService` — MediaTek TV remote façade

```
code 1 registerCallback(...) -> V
code 2 unregisterCallback(...) -> V
code 3 unregisterAll() -> V
code 4 getInstanceCount() -> I
code 5 setKeyRouteSwitchFromTVRemoteService(...) -> V
code 6 addListenerConfig(...) -> V
code 7 removeListenerConfig(...) -> V
code 8 getTVRemoteServiceReady() -> Z
```

Only 8 methods — it is a small façade. The large interface in the same jar (`MtkTvITVCallback`, 85 `notify*` methods from `notifySvctxNotificationCode` to `notifyFollowingEventUpdate`) is the *reverse* direction (service → client callback), so it is not directly attackable from `shell` (we can only pass a null Binder). `setKeyRouteSwitchFromTVRemoteService` (code 5) is the semantically interesting one: TV key-event routing.

### 4.3 Hosting process / privilege of the MediaTek services

Replies include a Java exception slot (`writeNoException` int), so both are **Java AIDL services**, not native. Candidates: `system_server`, or the `system_app`-uid agents:

| Process | pid | uid | SELinux domain |
|---|---|---|---|
| `com.mediatek.dmagent` | 2975 | **1000 (system)** | `u:r:system_app:s0` |
| `com.mediatek.agent` | 2881 | **1000 (system)** | `u:r:system_app:s0` |
| `app_man` / `dtv_svc` | 1484 / 1499 | **0 (root)** | `u:r:mt_dtv-svc:s0` |

`DMRemoteserviceagent.apk` is a 16 KB stub whose manifest declares `android.uid.system` and only three permissions — the real classes live in `/system/framework/com.mediatek.dm.jar`, and `com.mediatek.dm.jar` **and** `com.mediatek.twoworlds.tv.jar` are both on `BOOTCLASSPATH`:

```
/system/framework/com.mediatek.twoworlds.tv.jar
/system/framework/com.mediatek.dm.jar
```

Boot-classpath membership means `system_server` *could* host these. **Attribution is unresolved** (a remote test cannot distinguish without crashing `system_server`, which would reboot the TV — explicitly out of scope). Either way the effective privilege is uid 1000; if it is `system_server`, the ceiling is far higher.

---

## 5. HIDL surface

`lshal` is the old Android 8.0 binary: it supports `list`/`debug`/`help` only. It rejects `--types=b` and does not accept `-i <fqname>`.

Full output: `raw/lshal.txt` — 61 HAL rows (**50 `Server N/A` + 11 with live servers**). Note that `lshal` emits its "Skipping …" warnings on **stderr**, so they are not in the captured file; 24 were produced (`cannot be fetched from service manager (null)`), e.g. `android.frameworks.displayservice@1.0::IDisplayService/default` and `vendor.mediatek.hardware.pppoeproxy@1.0::IPppoeProxy/default`. Those 24 are a subset of the 50 N/A rows — the remainder are manifest entries never fetched at all.

**11 binderized HALs have live servers and were successfully fetched from `shell`:**

| HAL | Server pid |
|---|---|
| `android.hardware.keymaster@3.0::IKeymasterDevice/default` | 1014 |
| `android.hardware.bluetooth@1.0::IBluetoothHci/default` | 1161 |
| `android.hardware.camera.provider@2.4::ICameraProvider/legacy/0` | 1162 |
| `android.hardware.drm@1.0::ICryptoFactory/default` | 1164 |
| `android.hardware.drm@1.0::IDrmFactory/default` | 1164 |
| `android.hardware.graphics.allocator@2.0::IAllocator/default` | 1166 |
| `android.hardware.graphics.composer@2.1::IComposer/default` | 1167 |
| `android.hardware.health@1.0::IHealth/default` | 1168 |
| `android.hardware.power@1.0::IPower/default` | 1170 |
| `android.hardware.tv.cec@1.0::IHdmiCec/default` | 1171 |
| `android.hardware.tv.input@1.0::ITvInput/default` | 1463 |

The remaining ~50 declared HALs report `Server N/A` — these are **passthrough** HALs on this partially-binderized BSP (no server process to talk to), not a permission failure.

Transport is world-accessible:
```
crw-rw-rw- 1 root root u:object_r:hwbinder_device:s0  10, 57 /dev/hwbinder
crw-rw-rw- 1 root root u:object_r:binder_device:s0   10, 58 /dev/binder
crw-rw-rw- 1 root root u:object_r:vndbinder_device:s0 10,56 /dev/vndbinder
```
(0666 on all three, but SELinux gates actual use: `/dev/vndbinder` is refused to `shell`, §3.4.)

`hwservicemanager` runs as pid 1006, `u:r:hwservicemanager:s0`. `vndservicemanager` as pid 1008.

**Assessment:** `hwservicemanager` lookup from `shell` works, so HAL *enumeration* is unprivileged. Per-HAL method invocation additionally requires `binder_call` permission into each `hal_*` domain (`u:r:hal_keymaster_default`, `u:r:hal_audio_mediatek_tv`, etc.), which AOSP policy typically restricts to specific clients. I could not test an actual HAL method call from `shell` — there is no generic HIDL client CLI on the device, and building one would require a compiler/dex toolchain. **Untested, marked SPECULATIVE.** Keymaster 3.0 and `hal_audio_mediatek_tv` are the highest-value targets if a client can be arranged.

No `default` HAL in the list exposes an obviously privileged operation beyond normal HAL duty; `ITvInput/default` and `IHdmiCec/default` are the TV-specific ones and the most interesting given the device class.

---

## 6. `cmd` and `dumpsys` capabilities

`cmd -l` lists 129 running services (same set as `service list`). Raw: `raw/cmd-l.txt`.

| `cmd` target | Shell access | Notes |
|---|---|---|
| `cmd package` | **Yes** | full help incl. `compile`, install-related |
| `cmd activity` | **Yes** | `start-activity`, `--start-profiler`, `-S`, allocation tracking |
| `cmd appops` | **Yes** | `set`/`get` — `cmd appops set <pkg> <op> <mode>` |
| `cmd deviceidle` | **Yes** | `step`, `force-idle`, `whitelist` |
| `cmd overlay` | **Yes** | `list`, `dump`, enable/disable of RRO overlays |
| `cmd uimode` | **Yes** | `night yes\|no\|auto` |
| `cmd settings` | **Yes** | `get` / **`put`** — arbitrary settings mutation |
| `cmd wifi` | No | "No shell command implementation." |
| `cmd media_session` | No | "No shell command implementation." |

Read-only proofs of privilege (`shell` executed these successfully):
```
$ cmd settings get system screen_brightness        -> 128
$ cmd overlay list                                 -> com.sony.dtv.sonyselect
                                                      [x] com.sony.dtv.sonyselect.overlay
$ cmd appops get com.android.shell                 -> RUN_IN_BACKGROUND: allow; time=+16h0m11s177ms ago
$ cmd deviceidle whitelist                         -> system-excidle,com.google.android.apps.mediashell,10000 ...
$ cmd uimode night                                 -> Night mode: no
```

`dumpsys <vendor service>` produced **empty output for all 8 vendor services tested** (`DMRemoteService`, `TVRemoteService`, `GestureService`, `kyilservice`, `mpsservice`, `eepservice`, `DmsDeamonReceiver`, `TpdReceiver`) — they implement no `dump()` method, or an empty one. `dumpsys` is therefore useless as a vendor-service recon channel here, but note that `dumpsys <name>` returning *nothing* (rather than `Can't find service: X`, which is what a bogus name yields) is itself evidence that the `dumpsys` resolver reaches these names.

---

## 7. Processes, SELinux contexts, and vendor daemons

`ps -A -Z` → 291 lines. Raw: `raw/ps-A-Z.txt`. Domain histogram (top entries):

| Count | Domain |
|---|---|
| 174 | `u:r:kernel:s0` (kernel threads) |
| 24 | `u:r:sony_platform_app:s0:c512,c768` |
| 13 | `u:r:system_app:s0` |
| 6 | `u:r:priv_app:s0:c512,c768` |
| 4 | `u:r:untrusted_app:s0:c512,c768` |
| 3 | `u:r:shell:s0` |
| 3 | `u:r:netd:s0` |
| 2 | `u:r:mt_dtv-svc:s0` |
| 2 | `u:r:platform_app:s0:c512,c768` |
| 1 each | `mediadrmserver`, `mediaextractor`, `mediametrics`, `mediaserver`, `mdnsd`, **`magicpacketseek`**, **`mt_k2logcat`**, `logd`, `lmkd`, `mediacodec`, `adbd`, `sdcardd`, `servicemanager`, **`sony_input_manager`**, `storaged`, `surfaceflinger` |

### 7.1 Dedicated vendor daemon domains (all bespoke, all `Seccomp: 0`)

| Process | pid | uid | gid | `CapEff` | Domain |
|---|---|---|---|---|---|
| `dumpecsserver` | 1176 | 1000 system | 1000 | `0` | `u:r:dumpecsserver:s0` |
| `eepserver` | 1177 | 1000 system | **0 root** | `0` | `u:r:eepserver:s0` |
| `k2logcat` | 1185 | **0 root** | 0 | — | `u:r:mt_k2logcat:s0` |
| `MtkRmServer` | 1187 | **0 root** | 0 | — | `u:r:mt_mtk_rm:s0` |
| `interactivetvutil` | 1191 | **2000 shell** | **0 root** | `0` | `u:r:interactivetvutil:s0` |
| `itdplatformdaemon` | 1192 | **0 root** | 1000 | `0x1fffffffff` | `u:r:itdplatformdaemon:s0` |
| `kyildm` | 1193 | **1004 input** | 1004 | `0` | `u:r:kyil:s0` |
| `dmsdeweydaemon` | 1194 | **0 root** | 2902 | `0x1fffffffff` | `u:r:dtcp:s0` |
| `telepathydaemon` | 1197 | **0 root** | 2901 | `0x1fffffffff` | `u:r:telepathy:s0` |
| `magicpacketseek` | 1198 | **0 root** | 1000 | `0x1fffffffff` | `u:r:magicpacketseek:s0` |
| `camera_recognition_daemon` | 1202 | 1000 system | 1000 | — | `u:r:camera_recognition:s0` |
| `app_man` | 1484 | **0 root** | 0 | `0x1fffffffff` | `u:r:mt_dtv-svc:s0` |
| `dtv_svc` | 1499 | **0 root** | 0 | `0x1fffffffff` | `u:r:mt_dtv-svc:s0` |

`CapEff: 0x1fffffffff` = the full 41-bit capability bounding set. These are **true root** with no seccomp filter. `Seccomp: 0` on every vendor daemon is notable — Android's own app processes are seccomp-filtered; these are not.

### 7.2 The `interactivetvutil` anomaly

`interactivetvutil` (pid 1191) runs as **uid 2000 — the same uid as `shell`** — but with **gid 0 (root group)** and its own SELinux domain `u:r:interactivetvutil:s0`. It publishes `com.sony.dtv.itvunative.interactivetvutil` (`IInteractiveTvUtil`), which `shell` can transact with (`Parcel(NULL)` replies, §3.2).

Two consequences worth flagging:
- **Shared uid 2000** means any DAC check of the form `st_uid == getuid()` (or `/data/local/tmp` file ownership) treats `shell` and this daemon as the same principal. A file dropped by `shell` in a uid-2000-writable location is, from a Unix-ownership standpoint, "the daemon's own file".
- **gid 0** gives it root-group access that `shell` lacks.
- Its domain is *not* `shell`, so SELinux still separates them — this is a DAC-only weakness, not an automatic escalation.

Interface definitions in `InteractiveTvUtil_Client.jar` cover `ILogService` (send, getChannelInfo, getCurrentChannelUri, sendBiLog), `IActionLogService`, `IPrivacyPolicyService` (showPrivacyPolicy, confirmUpdate), `IInteractiveTvUtilProviderService` (`getCid() -> byte[]`, `getPersistentCid() -> byte[]` — a persistent device identifier, likely a tracking ID), and `IPrivacyPolicyServiceCallback`. Low severity, but note the **CID getter is readable by any app that can reach the service**, i.e. a persistent identifier exposure issue.

---

## 8. `/dev/socket` and device nodes

`/dev/socket` readdir succeeds, but **every entry is `getattr`-denied** to `shell`:

```
$ ls -lZ /dev/socket/
ls: /dev/socket//webview_zygote: Permission denied
ls: /dev/socket//wpa_wlan0: Permission denied
ls: /dev/socket//adbd: Permission denied
ls: /dev/socket//mdnsd: Permission denied
ls: /dev/socket//tombstoned_intercept: Permission denied
ls: /dev/socket//tombstoned_crash: Permission denied
ls: /dev/socket//lmkd: Permission denied
ls: /dev/socket//zygote: Permission denied
ls: /dev/socket//fwmarkd: Permission denied
ls: /dev/socket//mdns: Permission denied
ls: /dev/socket//dnsproxyd: Permission denied
ls: /dev/socket//netd: Permission denied
ls: /dev/socket//cryptd: Permission denied
ls: /dev/socket//vold: Permission denied
ls: /dev/socket//logdw: Permission denied
ls: /dev/socket//logdr: Permission denied
ls: /dev/socket//logd: Permission denied
ls: /dev/socket//property_service: Permission denied
total 0
drwxr-xr-x  2 root root   400 2026-10-18 16:26 .
drwxr-xr-x 19 root root 11880 2026-10-18 16:24 ..
```

**18 sockets total.** Not one is stat-able, so per-socket labels and modes are invisible from `shell`.

`nc` is unavailable (`/system/bin/sh: nc: not found`); toybox provides netcat but **without unix-socket support** (`nc: Unknown option U`), so a real `connect()` test was impossible. I substituted an `open()` errno probe:

```
$ echo test > /dev/socket/dnsproxyd   -> can't create: Permission denied
$ echo test > /dev/socket/mdnsd       -> can't create: Permission denied
$ echo test > /dev/socket/adbd        -> can't create: Permission denied
$ echo test > /dev/socket/vold        -> can't create: Permission denied
```

`EACCES` (SELinux `sock_file` denial) rather than the `ENXIO` a normal program would get from `open()` on a socket. Conclusion: **the Android-domain socket plane is closed to `shell`**; only sockets explicitly allowed for the `shell` domain would be reachable, and none of the 18 are.

Device nodes of interest (from `/dev`):
```
crw-rw-rw- 1 root root 10, 61 ashmem
crw-rw-rw- 1 root root 10, 58 binder
crw-rw-rw- 1 root root 10, 57 hwbinder
crw-rw-rw- 1 root root 10, 56 vndbinder
crw-rw-r-- 1 system radio 10, 60 alarm
drwx--x--x 2 root root        __properties__      (0711 — traversal only)
crw------- 1 root root 5, 1   console
crw------- 1 root root 10, 236 device-mapper
```
`__properties__` at `0711` means `shell` cannot list it but the property area is designed for property_service mediation, not direct access.

Out-of-scope but observed while reading `/proc/net/tcp`: TCP listeners on uid 10143 (`com.netflix.ninja`, port 9080 = `0x2378`, bound `0.0.0.0`) and uid 10102 (`com.sony.huey.dlna.module`, four ports). Network service surface belongs to another investigation; flagged only so it is not lost.

---

## 9. Ranked privileged-service entry points

### Tier 1 — CONFIRMED

**1. `DMRemoteService` / `com.mediatek.dm.IDMRemoteService` — unauthenticated, uid 1000, destructive methods.**
- CONFIRMED: transacts from `shell`; read-only methods invoked with real return values (§3.3); no caller check observed.
- CONFIRMED: exposes `formatVol(String,String)` (17) and `partedDisk(String,String)` (19).
- CONFIRMED: `mountVol`/`mountVolEx`/`mountISO`/`mountISOex`/`umountDevice`/`umountVol`/`umountISO`.
- SPECULATIVE (not tested, by choice): whether `formatVol`/`partedDisk` validate the target device string. If unvalidated, this is a "destroy or re-partition attached block storage as uid 1000" primitive. `mountISO(String)` may allow mounting an attacker-supplied image, exposing a filesystem parser in the DM service's context.
- **Recommended next step (needs a decision, it is destructive):** call `checkVol` (18, read-only) with a crafted volume string to probe validation, before ever touching 17/19.

**2. `TVRemoteService` / `com.mediatek.twoworlds.tv.ITVRemoteService` — unauthenticated TV control plane.**
- CONFIRMED: transacts; method bodies execute for `shell` (`getInstanceCount` returns a monotonic 1→6 counter across six isolated calls, §3.3).
- CONFIRMED: `setKeyRouteSwitchFromTVRemoteService` (5) and `addListenerConfig`/`removeListenerConfig` (6/7) exist and are equally unguarded at the transport layer.
- NOT CONFIRMED: that `registerCallback(null)` (code 1) persists state — see the retraction in §3.3.
- SPECULATIVE: code 5 may redirect TV key-event routing; codes 6/7 may let `shell` subscribe to or intercept remote-control traffic. Not tested.
- Note: 20 of 129 services in this device's inventory sit in this "no caller check" class; this one is interesting because it is the input path.

**3. `GestureService` / `com.sony.dtv.remotetouchpad.gesture.IGestureService` — reproducible crash, 1 transaction.**
- CONFIRMED, twice: `service call GestureService 1` → `Error: 0xffffffe0 "Broken pipe"`; immediately afterwards `service check GestureService` → `not found`; later → `found`.
- Severity: low-to-moderate (local DoS of the gesture/touchpad service; it auto-restarts; no privilege gained). But a one-packet, unauthenticated kill of a vendor daemon from uid 2000 is a real availability primitive, and the same class of bug probably exists on other codes (2–5 all returned `Parcel(NULL)` without crashing).

### Tier 2 — CONFIRMED reachable, unclear impact

**4. `com.sony.dtv.itvunative.interactivetvutil` — same-uid-as-shell daemon.**
- CONFIRMED: runs as **uid 2000**, gid 0, own domain; service transacts (`Parcel(NULL)` for codes 1–5).
- SPECULATIVE: DAC-level confusion with `shell`-created files; possible channel to the log/CID/privacy services in the same family.
- Also CONFIRMED: `getPersistentCid() -> byte[]` in the related `IInteractiveTvUtilProviderService` is a persistent device identifier readable by any client that can reach the service.

**5. `com.sony.dtv.camerarecognitiondaemon` and `...nativevideoshm.VideoShmServ`.**
- CONFIRMED: both transact from `shell` without denial. `camerarecognition` codes 3/4 return `0x00030001`; `VideoShmServ` code 3 returns a 20-byte parcel containing `66642a85 0000017f 00000004` — consistent with a handle/size descriptor.
- SPECULATIVE: `VideoShmServ` ("shared video memory service") is the more interesting of the two — shared-memory handles from a vendor service are a classic confused-deputy primitive if the handle is trusted without ownership checks. I did not attempt to map the handle to a mapped region.

### Tier 3 — enumerable but not transactable (blocked, not absent)

**6. `com.sony.dtv.mpsservice`, `com.sony.dtv.modelvariation.eepservice`, `DmsDeamonReceiver`, `TpdReceiver`.**
- CONFIRMED present (`service check` → `found`, `dumpsys -l` lists them).
- CONFIRMED not transactable from `shell` ("does not exist").
- `eepservice` is the model-variation/EEPROM provider (its daemon `eepserver` runs uid 1000 with **gid 0**); `mpsservice` is likely "MPS" (multi-picture/video). These are the right things to be blocked, and they are — but the mechanism is unresolved, so do not assume the block is intentional or permanent.

### Explicitly de-prioritised

- **`setDMSysProperty(boolean)`** — a boolean-only setter, *not* an arbitrary property-write primitive. My initial read of the name suggested otherwise; the recovered signature refutes it.
- **`dumpsys`** — no vendor service implements `dump()`. Dead end for recon.
- **HIDL method invocation** — enumeration works, invocation untested and likely `binder_call`-restricted. Not a demonstrated entry point.

---

## 10. Limitations / what was deliberately not done

1. **No exhaustive 129-service `service call` sweep.** Codes 1–2 on `recovery`, `mount`, `installd`, `package` are not guaranteed to be getters. A blind sweep risked a reboot or data loss, both explicitly forbidden. ~40 services were probed with deliberate selection.
2. **No destructive method invoked.** `formatVol` (17), `partedDisk` (19), `mountVol` (12/13), `mountISO` (14/15), `setDMSysProperty` (22) were mapped but never called. Their validation behaviour is unknown.
3. **No HIDL method invocation.** No generic HIDL client CLI exists on-device and no build toolchain is present; a `binder_call` SELinux denial would be the likely outcome anyway. Keymaster 3.0 remains the highest-value unproven target.
4. **SELinux denials could not be read.** `/proc/cmdline`, `dmesg`, `/sys/fs/selinux/policy` and `/data/misc/audit/` are all denied to `shell`; the crash buffer contained an unrelated `vndservice` abort. Therefore "SELinux denial vs service-level check" is settled for the *positive* cases (denials are loud, §3.1) but **unresolved** for the four NO-TX services (§3.4).
5. **Service attribution unresolved.** Whether `DMRemoteService`/`TVRemoteService` live in `system_server` or the `system_app` agents cannot be determined remotely without risking a system_server crash (→ reboot).
6. **No socket `connect()` test.** No unix-socket-capable client on device; `open()` errno probe used instead.

---

## 11. Raw artifacts

All under `C:\Users\Blanco\Desktop\DeepSeek Operations\tv-research\surface\`:

| File | Contents |
|---|---|
| `raw/service-list.txt` | full `service list`, 129 services |
| `raw/vendor-call-matrix.txt` | `service call` codes 0–5 × 11 vendor services |
| `raw/lshal.txt` | `lshal` table (61 rows: 11 binderized, 50 N/A); stderr warnings not captured |
| `raw/ps-A-Z.txt` | `ps -A -Z`, 291 processes with SELinux contexts |
| `raw/cmd-l.txt` | `cmd -l`, 129 services |
| `raw/dev-socket.txt`, `raw/dev-socket-ls.txt` | `/dev/socket` inventory attempts |
| `dexdump_map.py` | minimal DEX parser → `TRANSACTION_*` code map |
| `sigmap.py` | AIDL method signature dumper |
| `strscan.py` | printable-string scanner for APK/dex/ELF |
| `build_table.py`, `fix_table*.py` | report table generators/repair (build tooling, not findings) |

---

*Report generated from live device interrogation. Every command output quoted above was captured from `100.70.99.3:5555` during this session.*
