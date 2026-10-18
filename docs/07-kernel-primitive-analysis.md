# 07 · CVE-2022-20186 — kernel primitive analysis

Status: **analysis, measurement and harness work. Nothing corrupting has been fired at the
device.** The TV is in use, so everything below is either offline analysis, read-only recon,
or *legitimate* API use with parameters that cannot overflow.

## 1. The bug, precisely

`KBASE_IOCTL_MEM_ALIAS` (`_IOWR(0x80, 21, …)`, 32-byte struct) creates a VA region that
aliases other allocations at a fixed stride. Size accounting:

```c
/* r26_mali_kbase_mem_linux.c:1203 — same expression in the shipped r20p0 */
if ((nents * stride) > (U64_MAX / PAGE_SIZE))
        goto bad_size;                       /* u64 multiply — wraps */

*num_pages = nents * stride;                  /* e.g. 2 instead of ~2^63 */
```

The upstream fix (present in r26p0, **absent** on this device) is an input pre-check in the
ioctl handler:

```c
/* r26_mali_kbase_core_linux.c:820 */
if (alias->in.nents == 0 || alias->in.nents > 2048)  return -EINVAL;
if (alias->in.stride > (U64_MAX / 2048))             return -EINVAL;   /* ← missing */
```

Confirmed on the device earlier in this project: `stride = 0x8000000000000001, nents = 2`
yields `va_pages = 2`.

## 2. Where the wrapped value hurts — and a correction

My first reading of this bug was that the oversized `stride` alone pushes the PTE insertion
out of bounds. **That is wrong**, and it is worth writing down because the arithmetic is
subtle:

`kbase_gpu_mmap()` inserts at `reg->start_pfn + i*stride`, and the page-table walk reduces
each index with `& 0x1FF` (`mmu_get_next_pgd`, `r26_mali_kbase_mmu.c:929`) — three 9-bit
levels + 12-bit offset, i.e. a **39-bit** GPU VA, mask `0x7FFFFFF` pages. For the wrap to
keep `num_pages` small we need `stride ≡ k (mod 2^27)` with `num_pages = nents·k`, so every
*start* vpfn `i·stride mod 2^27 = i·k < nents·k = num_pages` — **inside** the region.
Feeding a huge stride alone does not produce stray PTEs.

The real lever is the **run length**, which is not bounded by the region at all:

```c
/* r26_mali_kbase_mem.c:1049 — kbase_gpu_mmap, alias branch */
for (i = 0; i < alias.nents; i++)
        kbase_mmu_insert_pages(kctx->kbdev, &kctx->mmu,
                reg->start_pfn + (i * stride),        /* masked to 39 bits */
                aliased[i].alloc->pages + aliased[i].offset,
                aliased[i].length,                    /* ← up to the SOURCE alloc size */
                reg->flags & gwt_mask, kctx->as_nr);
```

`aliased[i].length` is validated only against the *source allocation*
(`ai[i].offset + ai[i].length > alloc->nents → bad_handle`), never against the new region's
`num_pages`. So:

* region: **2 pages** of tracked VA,
* insertion: up to `length` = the whole source allocation (we can make it thousands of pages),
* start: `start_pfn + i·stride`, reduced mod 2^27.

⇒ a **long run of PTEs is installed outside the tracked region**, mapping our own pages, and
`kbase_gpu_munmap()` only removes `nr_pages` from the region base, so the stray entries are
**never torn down**. That is the primitive.

## 3. Measured on the device (safe: valid parameters only)

```
=== GPU VA allocator layout (custom zone) ===
  alloc #0 : 4 pages -> gpu_va=0x0102000000  pfn=0x102000
  alloc #1 : 4 pages -> gpu_va=0x0102004000  pfn=0x102004
  alloc #2 : 4 pages -> gpu_va=0x0102008000  pfn=0x102008
  alloc #3 : 4 pages -> gpu_va=0x010200c000  pfn=0x10200c
  alloc #4 : 4 pages -> gpu_va=0x0102010000  pfn=0x102010
  delta between consecutive allocations: 0x4000 bytes (0x4 pages)

=== legitimate MEM_ALIAS (stride=2 pages, nents=2, length=1 page each) ===
  MEM_ALIAS ok: gpu_va=0x0102014000 va_pages=4 (expected 2*2=4)

=== valid alias with larger lengths (stride=8 pages, nents=2, length=4) ===
  ok: gpu_va=0x0102018000 va_pages=16 (expect 16)
```

| Fact | Value | Why it matters |
|---|---|---|
| GPU VA zone base | pfn **0x102000** (`gpu_va=0x0102000000`) | target vpfns are computable exactly |
| Allocator | strictly sequential, deterministic | we can predict where a region will land |
| GPU VA space | 39-bit → 2^27 pages, index mask `0x7FFFFFF` | wrap targets are computable |
| `stride` unit | **pages** (compared directly with `length`) | the struct comment saying "bytes" is stale |
| required alias flags | **0xC** = `GPU_RD(1<<2) \| GPU_WR(1<<3)`; `0x3` fails with `ENOMEM` | any validation failure surfaces as `ENOMEM` (the handler returns 0) |
| valid alias verified | 4-page and 16-page aliases, sequential VA | baseline; the API works from our context |
| `sizeof(base_mem_aliasing_info)` | 24 B (handle u64, offset u64, length u64) | sizing for the alias array |
| `sizeof(struct kbase_aliased)` | 24 B (ptr + pad + 2×u64) | sizing for the kernel-side array |
| `panic_on_oops` | **1** (`/init.rc:112`) | any oops = panic = reboot. No room for stray dereferences |

## 4. Kernel info-leak inventory (free, from `adb shell`)

`/proc/kallsyms` is readable but zeroed (`kptr_restrict`). It does not matter — the **kernel
log buffer leaks resolved symbol addresses** at every boot, because a `WARN` fires during
`snd_mtk` module init and dumps a full backtrace:

```
WARNING: at .../lib/kobject.c:196 kobject_add_internal+0x164/0x1c8()
[<c0015080>] (unwind_backtrace+0x0/0xe8)   from [<c0012b30>] (show_stack+0x20/0x24)
[<c0012b30>] (show_stack+0x20/0x24)        from [<c05ab63c>] (dump_stack+0x20/0x28)
[<c05ab63c>] (dump_stack+0x20/0x28)        from [<c00274ac>] (warn_slowpath_common+0x5c/0x7c)
[<c002750c>] (warn_slowpath_fmt+0x40/0x48) from [<c0270604>] (kobject_add_internal+0x164/0x1c8)
[<c02bd148>] (device_add+0xf4/0x564)       from [<c02c1404>] (platform_device_add+0x138/0x1cc)
[<c02c18f4>] (platform_device_register_full+0xa8/0xe4) from [<bfd060cc>] (init_module+0xcc/0x20c [snd_mtk])
[<c007fe24>] (load_module+0xe90/0x19f4)    from [<c0080aec>] (SyS_finit_module+0x6c/0x7c)
[<c000e740>] (ret_fast_syscall+0x0/0x30)
```

Because each frame carries `symbol+offset/size`, the **exact address of every symbol in the
trace is recoverable** (`dump_stack` = `0xc05ab63c - 0x20`, `kobject_add_internal` =
`0xc0270604 - 0x164`, …). Additional leaks in the same buffer:

| Leak | Example | Source |
|---|---|---|
| kernel text (14 symbols, resolved) | `[<c0270604>] kobject_add_internal+0x164` | boot `WARN` backtrace |
| module base | `[<bfd060cc>] init_module+0xcc [snd_mtk]` → base `0xbfd06000` | same trace; modules: `snd_mtk`, `mt7662u_sta`, `fusion`, `texfat`, `tntfs`, `mtk_dummy`, `mtk_mod` |
| kernel heap pointer | `pUrb=0xc98e2600` (13×, kmalloc'd `struct urb`) | `MUC_urb_enqueue` prints `%p` |
| `/proc/slabinfo` | real SLUB object sizes/counts | readable from shell |

Lowest text address observed is `0xc00086d8` (`do_one_initcall`), consistent with
`_text = 0xc0008000` and **no KASLR relocation** — cheap to confirm at the next reboot by
comparing the same addresses.

## 5. Primitive ranking (revised)

| # | Primitive | Mechanism | Risk |
|---|---|---|---|
| **A** | **Long PTE run outside any tracked region** — map thousands of our pages over a chosen 39-bit VA window, permanently (never torn down) | §2, driven by `aliased[i].length` | **medium** — mechanism measured and understood; GPU-side only |
| **B** | **Region/MMU desync → PTE redirection over an existing region's VA** | A, aimed at a VA the tracker will later hand to another region | medium |
| **C** | **PTEs pointing at arbitrary physical pages** via the separate `ai[i].offset + ai[i].length` add-overflow (`mem_linux.c:1298`), which makes `alloc->pages + offset` walk off the array | an OOB *kernel heap read* supplies the PTE values | **high** — a bad read is an oops, and `panic_on_oops=1` |
| **D** | `nents`-driven `vzalloc(sizeof(*aliased) * nents)` overflow | heap overflow with an `nents`-iteration loop | very high — crash generator |

Order of work: **A → B → C**; C only once A/B have established a survivable pattern.

### A useful asymmetry

GPU-side faults are **handled** by kbase and merely logged (this project's page-cache work
produced `PERMISSION_FAULT`, `READ`, `WRITE` events in the kernel log with the TV alive).
Kernel-side dereferences are fatal because of `panic_on_oops=1`. So a primitive that puts bad
values **into PTEs** (GPU-visible, recoverable) is far safer than one that makes the kernel
dereference a bad pointer (fatal) — and the exploit should be shaped accordingly.

## 6. Staged test plan (needs an idle TV for steps 2+)

1. **Dry run / baseline** — done: [`alias_dryrun.c`](../exploit/cve-2022-20186/alias_dryrun.c)
   computes the wrap without firing; the §3 measurements come from a safe probe.
2. **Single controlled probe:** one `MEM_ALIAS` with `nents=2`, `num_pages` wrapped to 2, and
   `length` = the whole source allocation (e.g. 256 pages). Expected: a 256-page PTE run at
   `(0x102000 + i·stride) & 0x7FFFFFF` while the region still reports 2 pages. Watch the
   kernel log for MALI faults; a reboot is the fallback and the boot job restores root by
   itself.
3. **Verify the stray mapping resolves** — GPU-side sentinel written through the aliased VA,
   read back through the CPU mapping of the source pages.
4. **Primitive B** — force the tracker to hand out an overlapping region; observe redirection.
5. Only then: aim at `selinux_enforcing` / credentials, using §4 addresses.

## 7. Why this is still the right path

`selinux_enforcing` is a data symbol. With the leak in §4 we do not need to scan for it — its
address is derivable from a text-relative offset (kernel image, or a known build) or from a
short pattern scan once we have any read primitive. What is missing is exactly one thing:
a **write primitive**, and that is what steps 2–4 are for.

---

## 8. FIRST CONTROLLED FIRE — result (verified, no panic)

Single `MEM_ALIAS` call from a dedicated process/context, parameters chosen so the whole
touchable VA band belongs to that process:

```
[+] source: 256 pages at gpu_va=0x0102000000 pfn=0x102000
[*] MEM_ALIAS nents=2 stride=0x8000000000000001 length=256 ... OK
[+] alias gpu_va=0x0102100000 va_pages=2 (wrapped; real span is huge)
[+] PTE runs inserted at pfn 0x102100 and 0x102101, 256 pages each
[+] next allocation after the alias: gpu_va=0x0102102000 pfn=0x102102
```

What this establishes:

1. **The overflow path executes cleanly.** `nents=2`, `stride=0x8000000000000001`
   (product wraps to 2) and `length=256` were accepted; the kernel reports `va_pages = 2`
   while the alias describes a span of ~2^63 pages.
2. **Two 256-page PTE runs were installed** starting at pfn `0x102100` and `0x102101`,
   i.e. **254 pages beyond** the 2-page region the tracker owns.
3. **The desync is real and observable from userspace:** the very next allocation was handed
   pfn **`0x102102`** — squarely inside the stray run. The region tracker believes that VA is
   free while the MMU already has PTEs there mapping our source allocation.
4. **No MALI fault, no oops, no reboot.** Kernel log stayed clean; TV uptime kept climbing.

`panic_on_oops=1` was respected: this path never makes the kernel dereference anything we
control — it only *writes PTEs*, which is why it is survivable.

### Why the desync matters

A region whose VA the MMU and the tracker disagree about is the standard gateway to
kernel-level reach. The concrete next step is now well-defined:

1. Allocate a **native, CPU-mappable** region `R` (so `mmap()` on the mali fd gives us a
   userspace window onto whatever `R`'s PTEs point at).
2. Use primitive **C** — the *separate* `ai[i].offset + ai[i].length` u64 add-overflow in
   `mem_linux.c:1298` — so the PTE source array (`alloc->pages + offset`) is read from an
   attacker-groomed heap window instead of our own array. Those 32-bit tagged page addresses
   become the PTE values.
3. Groom the kernel heap (SLUB; `slabinfo` is readable) so the OOB window contains the page
   frame numbers we want.
4. Redirect `R`'s PTEs at a chosen physical page → **CPU read/write of kernel memory**
   through `R`'s userspace mapping.
5. With arbitrary physical read/write: locate `selinux_enforcing` (the §4 text leak gives the
   base; the symbol is at a fixed offset for this build) and clear it.

Step 2 is the dangerous one: an OOB read of an unmapped heap address is an oops, and
`panic_on_oops=1` turns that into a reboot. It needs its own carefully bounded probe.
