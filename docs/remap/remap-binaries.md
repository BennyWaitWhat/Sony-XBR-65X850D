# Offline RE — "foreign" binaries in `/data/local/tmp` + Sony/MTK CLI stack

Target: Sony BRAVIA XBR-65X850D (SVP-DTV15, MediaTek MT5890), Android 8.0.0, kernel 3.10.79 armv7l,
build 6.827, SELinux enforcing. Work is fully offline; the only device interaction was `adb pull`.

Primary question this answers: **what is the `/dev/cli` protocol, what do `ttyman`/`ttyman_shell`/`cli_shell`
do, and what is `cve28663`?** Conclusion up front:

* The four binaries in `/data/local/tmp` are **not vendor binaries — they are our own Go builds** from
  earlier sessions, byte-identical to copies already in the project tree (SHA-256 verified).
  `/data/local/tmp/cli_arm`, `cli2_arm` and `devopen` are *probes*, not clients. `/data/local/tmp/cve28663`
  is a Go port of the public **CVE-2021-28663** Mali kbase PoC.
* The canonical `/dev/cli` client is **`/system/bin/cli`** (16,120 bytes, already pulled) — it is a
  16 KB program whose whole protocol is `ioctl(fd, 0x0, &one_char)`, one character per call. There is
  **no struct, no length field, no nonce, no _IOW-encoded request number**. Responses do not come back
  through the fd; the driver writes to the kernel log.
* `ttyman_shell` writes to the tmpfs FIFO **`/tmp/fifo_dtv_write`** (and `/tmp/fifo_am_write`), and the
  **`ttyman` daemon routes bytes** between the console and `/dev/cli` / those FIFOs / a socket. `ttyman`
  has **no `system`/`exec*`/`fork`/`popen` imports at all** — it cannot execute commands. The FIFO reader
  is the separate root daemon `app_man` (`u:r:mt_dtv-svc:s0`, pid seen in `ps`), which is outside our reach.
* Net effect on this firmware: the console/FIFO machinery is a **character forwarding and console-switching
  layer**, not a shell. `/dev/cli` remains the only vendor node reachable from `shell`, and on this unit the
  driver is a **disabled stub** (prior on-device probe + binaries both consistent with that).

Verification method: ELF headers, `.gnu_debugdata` mini-debug symbol tables (which retain real function names
for the vendor binaries), Capstone Thumb-2 disassembly with gold-linker PLT resolution, rodata/`.text`
string extraction, and SHA-256 comparison against project copies.

---

## 1. Provenance of the `/data/local/tmp` binaries (important correction)

All four were pulled to `tv-research/foreign/` and hashed; each is **byte-identical** to an existing
project build. Embedded Go build paths name the exact source file.

| device path | size | SHA-256 | identical local copy | embedded source path | what it really is |
|---|---|---|---|---|---|
| `/data/local/tmp/cli_arm` | 2,307,053 | `087440f5…d4513` | `tv-research/surface/probe/cli_arm` | `…/surface/probe/cli.go` | probe: open `/dev/cli`, `read`, `ioctl(0,NULL)`, `ioctl(0,zeroed[64])`, `ioctl(0xdeadbeef)`, `ioctl(1)`, `write("A")`, `read`, `FIONREAD` |
| `/data/local/tmp/cli2_arm` | 2,306,728 | `299ad31a…4ba82` | `tv-research/surface/probe/cli2_arm` | `…/surface/probe/cli2.go` | parameterized single-`ioctl` enumerator: `cli2 <hexcmd> [buf|nul]` |
| `/data/local/tmp/cve28663` | 2,308,336 | `b9129ab9…6f9ac` | `tv-research/mali/cve28663_arm` | `…/mali/cve28663.go` | Go port of the `lntrx/CVE-2021-28663` Mali kbase PoC (see §4) |
| `/data/local/tmp/devopen` | 2,238,221 | `178c561d…a9efc` | `tv-research/surface/devopen_arm` | `…/surface/devopen.go` | `/dev` node `open(O_RDWR)` probe over ~23 device paths |

`/data/local/tmp/cli_client` does not exist on the device (pull attempt returns "No such file").
So the earlier `vendorbin/cli_client_arm` (2,304,875 bytes, SHA-256 `acf73e45…e70559`, built from
`vendorbin/cli_client.go`) is **also ours** and was never the device's copy.

**Which of the tools is "most complete"?** For protocol *fidelity*: none of the Go tools is a correct
client; `/system/bin/cli` (vendor) is the ground truth. For experimental breadth:

| tool | models the protocol how? | verdict |
|---|---|---|
| `/system/bin/cli` (vendor, 16,120 B) | `open("/dev/cli", O_RDWR)`; `getchar()` → `ioctl(fd, 0, &c)` per char; exit on typing `quit`; prints `"Cannot do ioctl to CLI device!"` on `ret <= -1` | **authoritative** |
| `vendorbin/cli_client_arm` (ours) | full 64-byte packet: `pkt[0]=char`, `pkt[1..16]=0`, `pkt[17..]=command`; per-char `ioctl(0, pkt)`; then `read(fd,512)`; then query `ioctl(0x80045200, buf)` | most *complete in intent* but **two of its three assumptions are wrong** (see §2.5) |
| `surface/probe/cli_arm` (on device) | no command text at all, only generic `ioctl` probes | best **probe**, not a client |
| `surface/probe/cli2_arm` (on device) | one raw request word per run, optional 64-byte buffer | best **enumerator**, not a client |

Recommended replacement client (built from §2.6): a 30-line program that opens `/dev/cli` O_RDWR and walks
the command string with `ioctl(fd, 0, &ch)`, then reads the reply from `logcat -b kernel`.

---

## 2. `/dev/cli` protocol — reconstructed from vendor binaries

### 2.1 Node facts (from prior device work; unchanged)

* char device **major 241, minor 4**, `/dev/cli`, mode `crw-rw---- root:shell`, label `u:object_r:cli_device:s0`
  (also present as `/linux_rootfs/dev/cli`).
* Only member of the Middleware major-241 family accessible to uid 2000.
* Prior probe (uid 2000): `open(O_RDWR|O_NONBLOCK)` OK; `read()` → `EINVAL`; `write()` → `EINVAL`;
  `ioctl(fd, 0, NULL)`, `ioctl(fd, 0, buf)`, `ioctl(fd, 0x1)`, `ioctl(fd, 0xdeadbeef)`,
  `ioctl(FIONREAD)` all return **0**; kernel log gains `Warning: cli device is disabled` (printk-ratelimited).
* Kernel thread **`[CLI]`** (pid ~1032, ppid 2, `u:r:kernel:s0`, state `x_msg_q_receive`) exists in `ps` —
  the vendor driver's message-queue worker is present even though the file-op command path is gated off.

### 2.2 The ioctl command word

There is exactly **one** request number used by every client: **`0x00000000`**, with a user pointer arg.
No `_IOW`/`_IOR`/`_IOWR`-encoded command exists anywhere in these binaries for `/dev/cli`.

Evidence (all four independent vendor programs):

| binary | site | what it passes |
|---|---|---|
| `/system/bin/cli` | `main+0x40` (file off 0x854) | `r0=fd, r1=0, r2=&char` → `ioctl(fd, 0, &c)` |
| `/system/vendor/bin/cli_shell` | 4 sites (0xe14, 0xe26, 0xe44, 0xe54) | `ioctl(fd, 0, &c)`; also sends `'\r'` then `'\n'` as two further calls |
| `/system/bin/ttyman` | 3 sites (0x1a8e, 0x1aac, 0x1ad4) | `r1=0`, `r2=&char` |
| `/system/vendor/bin/ttyman_shell` | `send_command+0xea` (0xc30) | `r1=0`, `r2=&cmd[i]` in a loop |

Disassembly of `/system/bin/cli:main` (Thumb, 0x814), annotated:

```
0x826  adr  r0, #0x84            ; "/dev/cli"
0x828  blx  __open_2             ; open(path, flags=2=O_RDWR)
0x82c  mov  r4, r0
0x82e  cmp  r4, #-1 ; ble 0x886  ; fail -> puts("Open CLI failed")
0x834  adr  r0, #0x80            ; "Open CLI successfully"
0x836  blx  puts
0x83a  blx  getchar              ; c = getchar()
0x83e  movw r6, #0x6974
0x842  add.w r5, sp, #3          ; &stack_char
0x84c  movt r6, #0x7175          ; r6 = 0x71756974 = "quit" packed
0x850  strb.w r0, [sp, #3]
0x854  mov  r0, r4               ; fd
0x856  movs r1, #0               ; request = 0
0x858  mov  r2, r5               ; &char
0x85a  blx  ioctl
0x85e  cmp  r0, #-1 ; itt le
0x864  movle r0, r8              ; "Cannot do ioctl to CLI device!"
0x866  blxle puts
0x86a  blx  getchar
0x86e  strb.w r0, [sp, #3]
0x872  uxtb r0, r0
0x874  orr.w r7, r0, r7, lsl #8
0x878  cmp  r7, r6 ; bne 0x854    ; loop until 4-byte rolling window == "quit"
```

So: **each keystroke is one `ioctl(fd, 0, &char)`**; the update is synchronous and the byte is the payload.
Termination of the client program is by typing `quit` (the packed constant is `0x71756974` = `'q','u','i','t'`).

### 2.3 Framing / session

* The byte stream is the CLI session itself; there is **no length byte, no header, no checksum, no nonce**.
* Line termination is sent as **individual `'\r'` and `'\n'` ioctl calls** (`cli_shell` does exactly this
  after every argv element; `ttyman`/`ttyman_shell` send the trailing `'\n'` that was already in the buffer).
* Argument separation for `/system/vendor/bin/cli_shell`: after each `argv[i]` it sends a `' '` ioctl, then
  after all args `'\r'`, `'\n'`; it then sleeps ~15.7 ms (`usleep(0x3d40)`) and starts reading the log.
* `/system/bin/cli` sends nothing on exit — the driver's per-character processing is the whole protocol.
* Argument **size**: every client guarantees only a single initialised byte. `ttyman_shell`/`ttyman` pass
  `&cmd[i]` *inside* a 0x100-byte line buffer (so the following command text is adjacent in memory), while
  `/system/bin/cli` passes a lone stack byte with uninitialised neighbours. A driver that read a fixed
  struct would not be driven this way by its own vendor tools ⇒ the driver consumes one byte.

### 2.4 Response channel — the reply does not come back on the fd

`/system/bin/cli` never calls `read()` (it doesn't import it). The CLI driver writes its output with
`printk`, so it lands in the **kernel log**, visible either:

* on the serial console (this is what `ttyman` and the AOSP `console` service manage), or
* via `/dev/kmsg` — **root-only**, so `/system/vendor/bin/cli_shell` fails for us exactly there
  (its own error string `"%s: File open error. %s\n"` with `/dev/kmsg`, visible in
  `vendorbin/cli_trace.txt`), or
* via **`logcat -b kernel`**, which uid 2000 *can* read on this device (established in
  `surface/kernel-devices.md`, "logcat -b kernel gives uid 2000 read access to the kernel log buffer"):
  this is the practical way for a reimplementation to capture output.

`cli_shell` (vendor, 20,376 B) in full — useful template for a faithful client:

1. `fd_cli = open("/dev/cli", O_RDWR)`; on failure prints `"cli_shell: File open error. /dev/cli"`.
2. `fd_kmsg = open("/dev/kmsg", O_RDONLY|O_NONBLOCK|O_CLOEXEC)` (`flags = 0x00080800`); failure → error, exit.
   `lseek(fd_kmsg, 0, SEEK_END)`.
3. Raises the console log level so driver output is kept: opens `/proc/sys/kernel/printk`, `sscanf("%d,")`
   the level, then `snprintf(buf, "echo %d > %s")` and **`system(buf)`** — i.e. `echo <level> >
   /proc/sys/kernel/printk`. (This is the only `system()` in the whole CLI stack and it is a harmless
   loglevel write; the string `"%s: error. Necessary the legacy_mode for pre-3.5 kernel."` covers the
   pre-3.5 `dmesg`/`/proc/kmsg` fallback.)
4. Sends the command: `for i in 1..argc-1 { copy argv[i]; for each char: ioctl(fd_cli, 0, &c); ioctl(fd_cli, 0,
   &' ') }` then `ioctl(&'\r')`, `ioctl(&'\n')`, `usleep(15680)`.
5. `read(fd_kmsg, buf, 0x2000)` loop; parses each kmsg record with
   `sscanf(line, "%u,%*u,%llu,%*[^;];%n", &level, &ts, &off)` (kmsg `level,seq,timestamp,flags;msg` format),
   prints `snprintf("[%5lld.%06lld] ")`, then prints segments of the message delimited by the **literal
   4-character markers `\x09` and `\x0a`** (i.e. the strings `"\\x09"` / `"\\x0a"` at rodata 0x11d8 / 0x2fcd)
   using `printf("%.*s")`. It does not filter for any fixed "CLI>"-style tag, only those escape markers.
6. Usage banner: `Usage: %s "command"`; program name embedded as `cli_shell`.

### 2.5 Corrections to the prior `/dev/cli` write-up (important — do not re-use)

The prior session's notes (`vendorbin/cli_client.go`, `surface/kernel-cve-research.md`) recorded:

| prior claim | reality (from vendor binaries) |
|---|---|
| packet is 64 B: `[0]=char`, `[1..16]=zero`, `[17..]=command string` | **No packet.** Only `pkt[0]`/`&char` is defined; the driver contract is a 1-byte character. Byte 17 was an artefact of our own client buffer. |
| a second ioctl `0x80045200` "query/read returning 40 bytes" | `0x80045200` = `_IOR('R', 0x00, int)` = **`RNDGETENTCNT` for `/dev/urandom`**. In the recorded `trace2` log it is issued on the **`/dev/urandom` fd**, followed by `read(40)` (= 40 random bytes), *not* on `/dev/cli`. There is no query ioctl on `/dev/cli`. |
| "40-byte nonce from `/dev/urandom`" part of the protocol | Same trace artefact; no vendor CLI binary opens `/dev/urandom`, and neither of the two non-Go vendor binaries contains that path. |
| output read via `read(fd, ...)` | `read()` on `/dev/cli` is `EINVAL`; output is kernel-log only. Use `logcat -b kernel` (shell-readable) instead of root-only `/dev/kmsg`. |

### 2.6 Minimal faithful reimplementation

```c
/* build: clang --target=armv7a-linux-androideabi21 */
int fd = open("/dev/cli", O_RDWR);
if (fd < 0) return -1;
for (const char *p = command; *p; p++)
    ioctl(fd, 0, (void *)p);          /* one byte per call, request = 0 */
ioctl(fd, 0, (void *)"\r");           /* CR and LF are separate calls   */
ioctl(fd, 0, (void *)"\n");
close(fd);
/* reply: read kernel log lines, e.g. popen("logcat -b kernel -d -v raw") */
```

Same in Go (replaces the incorrect `cli_client.go`):

```go
fd, _ := syscall.Open("/dev/cli", syscall.O_RDWR, 0)
for i := 0; i < len(cmd); i++ {
    syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0, uintptr(unsafe.Pointer(&cmd[i])))
}
```

On **this** firmware the driver ignores all of it (`ret=0`, `"cli device is disabled"` in the log), so the
reimplementation is only useful if the driver gate is ever lifted (e.g. a different firmware/region image),
or as the client for the message-queue path noted below.

### 2.7 Driver-side hints (why it is inert, and what else might reach it)

* All request words return 0 and no output is produced: the ioctl entry is an early-return stub that logs
  `"cli device is disabled"` behind `printk_ratelimited`.
* The kernel thread **`[CLI]`** is alive and blocked in `x_msg_q_receive`; the same wait state is shared by
  other vendor kernel threads (`[SRM]`, `[FlashIO]`, `[LedEventMsgHand]`, `[VideoMuteNotify]`,
  `[ThermalThread]`). This is the MTK "message queue → kernel worker" pattern: userspace normally posts
  requests through the driver, and the worker consumes them off a queue. If the gate is a compile-time flag,
  the queue itself may still be present/usable — **cheap follow-up** (needs device execution, not done here):
  `grep -i 'cli\|msg_q' /proc/kallsyms` (names are readable for shell, addresses are 0) to get driver
  function names, and check for a queue key/id in `/proc/sysvipc/msg` if the queue is SysV.

---

## 3. `ttyman` (daemon) and `ttyman_shell` (client) — console multiplexer + FIFO IPC

Both vendor binaries retain full function names in `.gnu_debugdata`, which made this tractable.
Files: `/system/bin/ttyman` (24,648 B), `/system/vendor/bin/ttyman_shell` (16,244 B, also in `/odm/bin`
and `/vendor/bin` as the same file). World-executable (`0755 root:shell`); SELinux blocks execution from
`u:r:shell:s0` (prior work), but they are fully reversible statically.

### 3.1 `ttyman_shell` — the "send a command somewhere" tool

Usage string: `Usage: ttyman_shell [ _CTRL_I | _CTRL_A ] "command"`.
`main` builds a 0x100-byte line then calls `send_command`; `open_file` is a trivial `open()` wrapper that
prints `"\n -- Function : %s, Line : %d, error string is : %s --\n"` on failure.

Reconstructed source:

```c
char ctrl = get_ctrl_char(argv[1]);        /* "_CTRL_I"->9, "_CTRL_A"->1, else 0 */
if (argc == 3 && ctrl) snprintf(buf, 256, "%c%s%c", ctrl, argv[2], '\n');
else                   snprintf(buf, 256, "%s%c",  argv[1], '\n');
printf("command=%s\n", buf);
send_command(buf);
```

`send_command(char *cmd)` (disassembly at 0xb40) switches on **`cmd[0]`**, which is the route selector:

| selector | printed | target opened | flags | bytes written / calls |
|---|---|---|---|---|
| `1` (`_CTRL_A` → app_man) | `"Input:  APP_MAN"` | **`/tmp/fifo_am_write`** | `0x802` = `O_RDWR│O_NONBLOCK` | one `write(fd, cmd+1, strnlen(cmd,256))` — raw command line, NUL included |
| `9` (`_CTRL_I` → middleware) | `"Input:  MW"` | **`/tmp/fifo_dtv_write`** | `1` = `O_WRONLY` | `write(":am,am,:dtv_cli_on\n")` (19 B), then `write(fd, cmd+1, strnlen(...))`, then `write("TTY_MAN_EXIT\n")` (14 B) |
| anything else | `"Input:  CLI"` | **`/dev/cli`** | `2` = `O_RDWR` | `n = strnlen(cmd,256)`; `for (i=0;i<n;i++) ioctl(fd, 0, &cmd[i])` |

then `usleep(200000)` (0x30d40), `close(fd)`, return 0; `umask(0)` is called before the two FIFO opens.
Error return is `-5` (`0xFFFFFFFB`) and prints `"ttyman_shell failed. ret=%d\n"`.
All literal strings live inside `.text` (not `.rodata`) in this binary, which is why a naive strings scan
of `.rodata` misses them.

So: **the FIFO path is `/tmp/fifo_dtv_write`; its framing is line-based ASCII with a session prologue
`:am,am,:dtv_cli_on\n`, the command line, and the epilogue `TTY_MAN_EXIT\n`.** The `/dev/cli` fallback uses
exactly the §2 protocol.

### 3.2 `ttyman` — what the daemon actually does

Function inventory (from `.gnu_debugdata`): `ex_program`, `main`, `readkmsg`, `tty_mngr_set_state`,
`tty_mngr_init`, `_tty_mngr_monitor_stdin`, `_tty_mngr_monitor_socket`, `_tty_mngr_monitor_kmsg`,
`tty_mngr_exit`, `_tty_mngr_monitor_fifo_am_read`, `_tty_mngr_monitor_fifo_am_write`,
`_tty_mngr_monitor_fifo_dtv_write`, `_tty_manager_switch_adb_log_mode`.

**Imports check — the decisive answer to the Lead's question:** `ttyman` imports `accept, bind, calloc,
close, free, getchar, ioctl, listen, malloc, mkfifo, printf, pthread_*, putchar, puts, select, signal,
sleep, socket, strchr, strcmp, strlen, strtok, tcgetattr, tcsetattr, unlink, usleep, write` and **no
`system`, `popen`, `exec*`, `fork`, or `posix_spawn` whatsoever.** It cannot execute a command. It is a
byte router plus console state machine.

`tty_mngr_init` (0x12b4):
1. `puts("tty_mngr_init")`, `puts("<Ctrl-E> to direct console log to ttyman.")`.
2. Puts stdin into raw-ish mode: `tcgetattr(0,&t); t.c_lflag &= ~0x2a (ICANON|ECHO|ISIG); t.c_cc[VMIN]=1;
   tcsetattr(0,TCSANOW,&t)`.
3. **`open("/dev/cli", O_RDWR)`** → stored as the CLI fd (global+0); failure aborts init.
4. `pthread_mutex_init`, then `unlink("/tmp/fifo_am_read")`, `umask(0)`, **`mkfifo("/tmp/fifo_am_read", 0777)`**
   (the only FIFO the daemon creates; the two `*_write` FIFOs are created by the app_man/MW side and just
   opened here, with retry loops: `fifo_am_write` with `O_RDWR│O_NONBLOCK`, retry every 1 s;
   `fifo_dtv_write` with `O_WRONLY`, retry every 50 ms).
5. Spawns 6 threads then joins them: `monitor_stdin`, `monitor_socket`, `monitor_kmsg`,
   `monitor_fifo_am_read`, `monitor_fifo_am_write`, `monitor_fifo_dtv_write`; on teardown restores termios.

Threads:

| thread | behaviour |
|---|---|
| `_tty_mngr_monitor_stdin` | the multiplexer state machine (below) |
| `_tty_mngr_monitor_socket` | `socket(AF_UNIX, SOCK_STREAM,0)`; `unlink`+`bind` **`/tmp/socket_tm_read`**, `listen(10)`; `select`/`accept`/`recvfrom` then `printf("%s", buf)` — a **log sink**: anything that can connect writes text that is echoed to the console. No commands taken, no exec. |
| `_tty_mngr_monitor_kmsg` / `readkmsg` | opens **`/proc/kmsg`**, `select`+`read` up to 0xA00000 B, and while the "log to ttyman" flag is set (`global+0x40 == 1`) splits lines on `'\n'` and `puts()` them — this is what `<Ctrl-E>` toggles. |
| `_tty_mngr_monitor_fifo_am_read` | reads **`/tmp/fifo_am_read`** (`O_RDONLY│O_NONBLOCK`), line-buffers the stream, and matches the **tokens `dtv_cli_on` / `dtv_cli_off`**: on `dtv_cli_on` sets mode flag 1 + `set_state(3)`; on `dtv_cli_off` clears it + `set_state(1)`. Buffer overflow guard at 0x41 bytes. |
| `_tty_mngr_monitor_fifo_am_write` | just opens **`/tmp/fifo_am_write`** (`0x802`) and keeps the fd (global+0xc) for the other threads to write into. |
| `_tty_mngr_monitor_fifo_dtv_write` | just opens **`/tmp/fifo_dtv_write`** (`O_WRONLY`) and keeps the fd (global+0x14). |

`tty_mngr_set_state(state)` (0x10c4) — console mode switch, no privilege change:
* **state 1 = APP_MAN**: restores the saved termios with `c_lflag |= 0x2a` (canonical), prints
  `<Ctrl-I>: switch to mw_cli. `, `<Ctrl-A>: switch to app_man. `, `<quit>: switch to app_man. `,
  `<:am,am,:cli_on>: trigger mw_cli via app_man. `
* **state 2 = CLI** (default, set when state==0 at startup): termios raw, prints the `.rodata`
  `<Ctrl-I>: switch to mw_cli or drv_cli. ` / `<Ctrl-A>: switch to drv_cli. ` strings, and `/dev/cli`
  ioctls are used for the keystrokes.
* **state 3 = MW**: raw; keystrokes go to the DTV/middleware path (`/tmp/fifo_dtv_write`).

State machine (verified control bytes in `_tty_mngr_monitor_stdin`):
* state 2 (CLI): `0x09` Ctrl-I → state 3 (writes `:am,am,:cli_on\n` to fifo_am_write, then
  `\x08\x08\x08` to fifo_dtv_write); `0x01` Ctrl-A → opens `/tmp/fifo_am_read` (presence check for
  app_man), then state 1; `0x05` Ctrl-E → toggle log; other bytes → `ioctl(cli_fd, 0, &c)`
  (ESC sequences `ESC [ A/B/D` are forwarded as up to three ioctl calls); typing the 4-byte
  sequence `quit` → open fifo_am_write, state 1.
* state 1 (APP_MAN): `0x01` → state 2; `0x09` → state 3; `0x05` → toggle log; other bytes → line-buffered
  writes to `/tmp/fifo_am_write` (`sprintf("%s%c")` style).
* state 3 (MW): line editor with 16-entry × 0x100-byte command history and ANSI arrow handling; on CR/LF
  the line is forwarded to `/tmp/fifo_dtv_write` (`"%s%c\n"`), `0x09` returns to state 2.

Daemon → peers control strings (all line-based ASCII, all written to **`/tmp/fifo_am_write`**):
`:am,am,:cli_on\n`, `:am,am,:dtv_cli_on\n`, `:am,am,:dtv_cli_off\n`,
`:am,am,:log_to_ttyman_on\n`, `:am,am,:log_to_ttyman_off\n`.
`ttyman_shell`'s mid-layer writes the same style but to **`/tmp/fifo_dtv_write`** with the
`:am,am,:dtv_cli_on` / `TTY_MAN_EXIT` session bracketing.

### 3.3 Verdict on the FIFO channel (the Lead's key question)

* **Path:** `/tmp/fifo_dtv_write`; also `/tmp/fifo_am_write` and `/tmp/fifo_am_read`;
  socket `/tmp/socket_tm_read`; the daemon also creates `/tmp/fifo_am_read` with mode 0777.
* **Framing:** line-based ASCII. DTV path:
  `":am,am,:dtv_cli_on\n" + <command line(s)> + "TTY_MAN_EXIT\n"`. APP_MAN path: raw line(s).
  The `:am,am,:<verb>` prefix is app_man's control syntax (`cli_on`, `dtv_cli_on`, `dtv_cli_off`,
  `log_to_ttyman_on/off`).
* **What ttyman does with it:** it forwards characters and switches console state. **There is no
  `system()`/`exec()`/`fork()`** anywhere in `ttyman` or `ttyman_shell` — this is **not** a shell execution
  channel *in this binary*. The actual command interpreter is on the far end: the FIFOs are consumed by the
  vendor daemon **`app_man`** (observed in `ps`: uid `root`, SELinux `u:r:mt_dtv-svc:s0`, pid 1484, blocked
  in `sys_pause`) and its child **`dtv_svc`** (pid 1499, same root mt_dtv-svc domain); both live in the
  SELinux-blocked vendor userland we cannot read.
  So whether `fifo_dtv_write` is an execution channel depends entirely on `app_man`/`mw_cli`'s parser, which
  we cannot inspect. What we *can* say with certainty: reaching it requires a domain that SELinux allows to
  write `fifo_file` for that path, and `u:r:shell:s0` is explicitly denied
  (`avc: denied { write } name="fifo_dtv_write" dev="tmpfs" tclass=fifo_file`).
* **Actionability:** only if we obtain code execution in a domain that may write that tmpfs FIFO (candidates:
  `mt_dtv-svc`, `system_app`, `platform_app`, `untrusted_app` — each needs a fresh AVC probe; this is a
  30-second test from a root-in-app shell: `echo test > /tmp/fifo_am_write`). Given `app_man` runs isolated
  in `u:r:mt_dtv-svc:s0` as root, this is worth the probe; it is the closest thing to a "vendor root command
  queue" we have found.

---

## 4. `cve28663` → **CVE-2021-28663** (Arm Mali GPU kbase, UAF)

**Identification.** `/data/local/tmp/cve28663` (2,308,336 B, our Go build from `mali/cve28663.go`) is a port
of the public PoC [`lntrx/CVE-2021-28663`](https://github.com/lntrx/CVE-2021-28663) — "a basic PoC leak for
CVE-2021-28663 (internal Android kernel backdoor vulnerability)". The project's `tv-research/cve28663/README.md`
is that repository's README verbatim. CVE-2021-28663 is a **use-after-free / improper GPU-memory operation in
the Arm Mali kernel driver**; Arm's fix ships in Midgard r31p0 / Bifrost r29p0, so this TV's
**Mali r20p0 (UK 10.6)** is inside the vulnerable range. It also appears in the Known Exploited
Vulnerabilities catalogue (CISA KEV mirror).

**What the Go binary does** (exact sequence and constants, all verified against the local
`mali/mali_kbase_ioctl.h` / `poc/mali_base_jm_kernel.h`):

| step | call | request (decoded) | payload |
|---|---|---|---|
| 1 | `open("/dev/mali0", O_RDWR│O_CLOEXEC)` | — | — |
| 2 | `VERSION_CHECK` | `0xc0048000` = `_IOWR(0x80,0,4)` | `{major=0,minor=0}`, **result ignored** |
| 3 | `SET_FLAGS` | `0x40048001` = `_IOW(0x80,1,4)` | `{0}`, result ignored |
| 4 | `mmap(off = 3<<12 = 0x3000)` (`BASE_MEM_MAP_TRACKING_HANDLE`) | — | needed or all later mmaps fail `EINVAL` |
| 5 | `MEM_ALLOC` | `0xc0208005` = `_IOWR(0x80,5,32)` | `{va_pages=3, commit_pages=3, extent=0, flags=0xF}` |
| 6 | `mmap(gpu_va, 3 pages, RW, SHARED)` and fill `0xA5A5A5A5` | — | original region A |
| 7 | `MEM_ALIAS` | `0xc0208015` = `_IOWR(0x80,21,32)` | `{flags=0xD (CPU_RD|GPU_RD|GPU_WR), stride=3, nents=1, ai_ptr=&{{handle=va_A, offset=0, length=3}}}` — **alias is created but not mmapped** |
| 8 | `MEM_FLAGS_CHANGE` | `0x40188017` = `_IOW(0x80,23,24)` | `{gpu_va=va_A, flags=1<<17 (BASE_MEM_DONT_NEED), mask=1<<17}` → pages become evictable |
| 9 | `mmap(alias_va, 3 pages, PROT_READ)` | — | expects a CPU read mapping of pages that kbase may evict/recycle |

That is exactly the published PoC's four-step recipe (alloc+mmap → alias without mmap so `gpu_mapping`
stays 1 → `BASE_MEM_DONT_NEED` on the **original** → `mmap` the **alias** read-only).

**Primitive:** a **read-only CPU mapping of pages the driver believes are unreferenced/evictable** — a
use-after-free read. If the pages are freed and reused by the kernel (page tables, pipe buffers, other
processes' GPU memory), the alias becomes a **kernel/foreign-memory disclosure**. It is *not* a write
primitive: alias flags exclude `CPU_WR` and `MEM_FLAGS_CHANGE` on an alias is rejected `EINVAL` on this
driver (prior on-device verification in `EXPLOIT_HANDOFF.md`).

**Requirements / gaps:** nothing we do not already have — `/dev/mali0` is `crw-rw-rw-` (uid 2000 reachable),
all ioctls above were individually verified working on this TV by the prior session, and the
`EXPLOIT_HANDOFF.md` "working primitives" list covers alloc/alias/flags-change. Two caveats for a real run:
(a) the Go port **ignores the `VERSION_CHECK` result** but sends `{0,0}`, and `MALI-STATUS.md` records that
`{0,0}` → `EINVAL` and `{10,6}` is required on this unit — a driver that rejects the context setup will make
every later ioctl fail, so the binary as-built probably stops early (nobody recorded a successful run of this
exact binary; there is no log in the tree); (b) whether the alias `mmap(PROT_READ)` is permitted at all on
r20p0 is the one untested premise. Fix before use: `{10,6}`, `SET_FLAGS{0}`, and check every return value.

**Verdict relative to what we already hold:** the project already has (i) **arbitrary page-cache write** from
uid 2000 via CVE-2022-22706 (weaponised — patched `libc.so`/`libselinux.so` page cache to get uid-0 code
execution in app/zygote domains) and (ii) a **GPU VA desync / page-table overlap** via CVE-2022-20186 but
*without* an arbitrary-value GPU write (Midgard only writes zeros). CVE-2021-28663 gives *none* of that; what
it can add is a **leak/read oracle**: reading reclaimed pages could supply KASLR-quality kernel pointers and
let us identify page-table / page-cache pages, which is precisely the missing companion for the existing
write and desync primitives. Its sibling **CVE-2021-28664 ("write to read-only memory")** is the more
interesting of the pair and is even less tested — same driver family, same era, and a *write* primitive would
be strictly more valuable. Recommendation: spend at most a day validating the 4-step ordering + the
`PROT_READ` alias mmap on r20p0 (fix VERSION_CHECK first), capture the leak as a read primitive, and stop
there; do not attempt to turn it into a root chain. Priority: below weaponising the existing page-cache write
and below testing CVE-2021-28664.

---

## 5. Other vendor binaries in the pull set (classified, lower priority)

All from `tv-research/cli-re/`, sizes/SHA-256 recorded in §7; all `0755 root:shell`; prior work found the
vendor-tool executions blocked from `u:r:shell:s0` (only the `/system/bin/*` system_file binaries are
directly executable by shell).

| binary | imports that matter | what it is |
|---|---|---|
| `/system/bin/cli` (16,120) | `ioctl, __open_2, getchar, puts` | the canonical `/dev/cli` client (§2). World-executable. |
| `/system/vendor/bin/cli_shell` (20,376) | `open, lseek, read, ioctl, sscanf, system, strstr, usleep, printf` | richer CLI client: sends argv char-by-char to `/dev/cli`, then dumps/filters `/dev/kmsg`. Needs root for `/dev/kmsg` ⇒ useless as shell, but is the best documentation of framing (§2.4). Same file in `/odm/bin`, `/vendor/bin`. |
| `/system/bin/ttyman` (24,648) | sockets/`mkfifo`/termios/`select`/`ioctl`, **no exec** | console multiplexer + FIFO/socket bridge (§3). Does not run on the current boot (not in `ps`). |
| `/system/vendor/bin/ttyman_shell` (16,244) | `ioctl, __open_2, write` | sends one command to `/dev/cli`, `/tmp/fifo_am_write`, or `/tmp/fifo_dtv_write` (§3.1). |
| `/odm/bin/b2bcmd` (96,744) | `MTAL_Init, MTEEPROM_Read/Write, RSA_public_decrypt, property_set, socket/bind/listen, opendir` | Sony B2B/hotel-mode provisioning daemon+client. RSA-verifies a **signed JSON** command (`PEM_read_bio_RSA_PUBKEY`, `RSA_public_decrypt`) then performs `export`/`import`, `tuner_enable/disable`, **`eeprom_read`** (offset/len/value), `fwwrite`, `decrypt_phrase`. Paths: `/data/vendor/b2b/mountpoint`, `/data/vendor/b2b/eeprom_read`, `…_result`, `/upgrade/upgrade_loader.pkg(.tmp)`, `/arib_channel_preset.bin`, socket `/data/vendor/b2b/b2bcmd_sock_name.tmp`, props `sys.svp.b2bcmd.state`. **Only binary in the tree with an EEPROM write path** — but needs the signing key and a privileged domain; execution is SELinux-blocked from shell. Not an entry point, worth remembering as a capability list. |
| `/odm/bin/debugshcmd` (16,228) | `fork, execvp, opendir, prctl, sigaction, wait_timeout` | **Interesting**: scans `/3rd_rw/tombstone/bugreport/shell/` for `*.sh` and, for each, invokes its fork/`execvp` runner as a `su` command line (strings `su`, `-c`, `sh`, `2>&1`, `>`; the exact argv order is partly obscured by offset-table encoded literals, but the `su -c` shape is clear). It then runs `dmesg` and prints the sections between `------ SH LOG (%s) ------` / `------ CLI LOG (dmesg) ------` markers. This is a **root script runner reading from an ext4-writable partition** (`/3rd_rw`, mmcblk0p15, rw); if a domain we can reach can write an `.sh` into that directory *and* trigger the bugreport flow (`dtbugreport`/`dtdumpstate`/Sony dump service), it is a plausible privilege-escalation / persistence primitive. Needs on-device permission probing of `/3rd_rw` and of the trigger; flagged as a follow-up lead. |
| `/odm/bin/debugsettings` (16,292) | `chmod, property_set` | applies `sony_dtv_debug_settings.txt` / `/data/odm/debugprop` debug properties. Config loader, no exec. |
| `/odm/bin/dtdumpstate` (24,684) | `chmod, open, property_set` | Sony dumpstate wrapper: runs `logdump` (`/3rd/sony/arib/bin/logdump`), `dumpmvi`, `dumpbectrl`, `dumpecs`, `/tmp/odm/dtbugreport`, phases via `sys.svp.dbg.dtdumpstate.a/b` props. |
| `/odm/bin/dumpecsserver` (29,284) | `MTAL_InitExCb`, Binder `BnDumpecsServerAPI` | Binder service exposing `readBlackVideoReg`/`readContinueBlackVideoReg` — a small vendor binder endpoint; low value. |
| `/odm/bin/switch_fbm` (16,148), `MtkRmTest` (16,188), `MtkRmInitServer` (16,248) | `MTAL_Init` / resin | MediaTek framebuffer-manager and resource-manager test utilities; no exec. |
| `/system/bin/sh` (200,152) | — | AOSP mksh; known. |

---

## 6. New leads worth handing to the team (ordered)

1. **`debugshcmd` root script runner** (`/3rd_rw/tombstone/bugreport/shell/*.sh` executed as
   `su -c "sh …"`). Test: can `untrusted_app`/root-in-app/`shell` create a file in that dir (AVC + perms)?
   Can the Sony bugreport trigger be invoked from our current domains (`dtdumpstate`, `dtbugreport`,
   property `sys.svp.dbg.dtdumpstate.*`, or the Android bugreport service)? This is the only root-context
   command execution mechanism found in the vendor binaries and is far cheaper than a kernel exploit.
2. **FIFO injection probe**: from our current root-in-app shell, try `echo x > /tmp/fifo_am_write` and
   `> /tmp/fifo_dtv_write` (and connect to `/tmp/socket_tm_read`). If any is permitted, we have a line into
   `app_man` (`u:r:mt_dtv-svc:s0`, uid 0) whose command grammar (`:am,am,:…`) is now documented. Cheap.
3. **`/dev/cli` msg-queue theory**: `/proc/kallsyms` names for `cli`/`msg_q` symbols (addresses zeroed but
   names visible to shell) + `/proc/sysvipc/msg` if present. If the CLI worker takes SysV messages, and the
   queue perms allow shell, that bypasses the disabled ioctl entry entirely.
4. `b2bcmd` socket/protocol and EEPROM read path — only if a signing-key or parser weakness is suspected;
   needs a domain that can execute it.

---

## 7. Artefacts and repro

Pulled copies (verified): `tv-research/foreign/{cli_arm, cli2_arm, cve28663, devopen}` (SHA-256 in §1).

Analysis outputs (all generated offline from the pulled binaries):

* `foreign/analysis/cli.txt` — full annotated Thumb-2 disassembly of every named function of `/system/bin/cli`
* `foreign/analysis/cli_shell.txt` — same for `/system/vendor/bin/cli_shell`
* `foreign/analysis/ttyman.txt` — same for `/system/bin/ttyman` (13 named functions, PLT calls resolved)
* `foreign/analysis/ttyman_shell.txt` — same for `ttyman_shell`
* `foreign/elfx.py` — ELF sections/imports/strings helper
* `foreign/dbgdata.py` — extracts `.gnu_debugdata` mini-debug `.symtab` (this is what recovered the vendor
  function names; recommend it for every future Sony/MTK binary — they are **stripped but not "stripped"**)
* `foreign/symmap.py`, `foreign/tvdis.py` — symbol/PLT-aware Capstone disassembler
  (`python tvdis.py <elf> --all <out.txt>`)

Vendor binary fingerprints (SHA-256) for future cross-checking:

```
cli           16120  02a57f2f463dac2cb232b53f45bf30068f3e9fbab10fe84c70fca4e3de9e7904
cli_shell     20376  03e58cd19f57022a57eb5c606ab4e3d7b1a4a346941f651122d13792afc91b5a
ttyman        24648  6b6789e29e344d6cb52e552add1f6fb5ec0391d1877ed1db548dd2e0c85e44d2
ttyman_shell  16244  ab9ed0a88d77fd9dc5faa5afcf6186df6fcc67b27a3c28324e7b6ffc3f380022
b2bcmd        96744  72a5a0493991972bd767a58835a652a0e19feebfc794eb567fa3706ddc8039b3
debugshcmd    16228  e9cf62c6e88f973492e22f8118450ed647beee453280e10e7cfafa86fd1c3231
debugsettings 16292  0ae5bf6ee99311bc537420058cf6e8eeec0b77c36fba486e94860e414af041c0
dtdumpstate   24684  03cf2c065d6d2e41acfaab5226f2321b42d553f8e8025827a8b8d2acd6e22637
dumpecsserver 29284  dc926febcc82e21b6878fca60366d324d13137a71b42c878c0492f29130ee720
sh            200152 7744fd7c5e6d5dbbf07d45b8882e27c89e7adde94cc0a8210a06108df51e9010
```

### References

* `lntrx/CVE-2021-28663` PoC — <https://github.com/lntrx/CVE-2021-28663>
* CVE-2021-28663 (NVD) — <https://nvd.nist.gov/vuln/detail/CVE-2021-28663>
* Arm Mali affected/fixed matrix (Midgard < r31p0 / Bifrost < r29p0) —
  <https://www.tenable.com/plugins/nessus/178129>
* CVE-2021-28663 in the Known Exploited Vulnerabilities catalogue (mirror) — <https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/dc390748-0edb-4e94-9082-36aca30caab0>
* CVE-2022-20186 (Mali mem_alias overflow, GitHub Security Lab) —
  <https://github.blog/2022-07-27-corrupting-memory-without-memory-corruption/>
