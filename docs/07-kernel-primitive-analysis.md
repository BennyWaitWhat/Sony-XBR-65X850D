# 07 · CVE-2022-20186 — kernel primitive analysis

Status: **analysis + harness only. Not weaponised, not fired at the device.**
Firing this bug can panic the kernel (and therefore reboot the TV), so it is deliberately
staged behind a dry-run harness.

## What the shipped driver does wrong

`KBASE_IOCTL_MEM_ALIAS` (ioctl `_IOWR(0x80, 21, …)`, 32-byte struct) takes a *stride*
and a *nents* and allocates a VA region covering `stride * nents` pages.

### The fixed version (r26p0 source, for comparison)

`r26_mali_kbase_core_linux.c:813` pre-validates the inputs before any arithmetic happens:

```c
if (alias->in.nents == 0 || alias->in.nents > 2048)   return -EINVAL;
if (alias->in.stride > (U64_MAX / 2048))              return -EINVAL;   /* ← the fix */
ai = vmalloc(sizeof(*ai) * alias->in.nents);
copy_from_user(ai, u64_to_user_ptr(alias->in.aliasing_info),
               sizeof(*ai) * alias->in.nents);
```

With `nents ≤ 2048` **and** `stride ≤ U64_MAX/2048`, the later product cannot overflow.

### The vulnerable version (r20p0, as shipped here)

The bound on `stride` is what we observed to be **missing** on this device. Confirmed
empirically (earlier in this project, and the reason this CVE was selected):

```
stride = 0x8000000000000001, nents = 2
   correct  : 0x8000000000000001 * 2 = 0x1_0000000000000002
   observed : va_pages = 2                       ← the u64 product wrapped
```

That matches `r26_mali_kbase_mem_linux.c:1203` **without** the stride guard:

```c
if ((nents * stride) > (U64_MAX / PAGE_SIZE))   /* wraps — useless check */
        goto bad_size;

*num_pages = nents * stride;                    /* 2  (should be ~2^63) */
```

So `num_pages` — the value used to size the VA region — becomes 2 while the alias array
describes a gigantic span.

## Where the wrapped value is consumed (and where it is not)

Following `kbase_mem_alias()` → `kbase_gpu_mmap()` (`r26_mali_kbase_mem.c:1023`):

```c
err = kbase_add_va_region(kctx, reg, addr, nr_pages /* 2 */, align);   /* tracker: 2 pages */

if (reg->gpu_alloc->type == KBASE_MEM_TYPE_ALIAS) {
    for (i = 0; i < alloc->imported.alias.nents; i++) {
        kbase_mmu_insert_pages(kctx->kbdev, &kctx->mmu,
            reg->start_pfn + (i * stride),                 /* ← spurious vpfn */
            aliased[i].alloc->pages + aliased[i].offset,
            aliased[i].length, reg->flags & gwt_mask, kctx->as_nr);
```

Two independent consequences:

1. **PTEs are inserted outside any tracked region.** `i * stride` is enormous; `kbase_mmu_insert_pages()` has *no* range check, and the page-table walk masks each level with `& 0x1FF`
   (`mmu_get_next_pgd`, `r26_mali_kbase_mmu.c:929`), i.e. three 9-bit levels + 12-bit page
   offset = **39-bit GPU VA = 2^27 pages**. A huge `vpfn` therefore does not go out of
   bounds in the walk — it **wraps to an attacker-chosen 39-bit address** and writes real
   PTEs there.

2. **VA accounting is now a lie.** The region tracker owns 2 pages; the MMU owns entries
   far outside it. Nothing will tear those entries down: `kbase_gpu_munmap()` only unmaps
   `nr_pages` starting at the region base, so the spurious PTEs **leak permanently** while
   the GPU address space believes those ranges are free.

## Candidate primitives (ranked by how much I trust them)

| # | Primitive | Mechanism | Risk |
|---|---|---|---|
| **A** | **GPU VA aliasing of attacker pages** — map our own physical pages at any 39-bit GPU VA, outside any region, permanently | consequence 1 above; `length` is bounded by the source allocation's `nents`, so the insert is small and controlled | medium — needs a follow-up impact (two regions sharing a VA, or a page-table page reachable as a GPU VA) |
| **B** | **Region/MMU desynchronisation** — allocate a second region that the tracker hands out over an already-mapped VA, then set/clear entries on top of foreign PTEs | consequence 2 above | medium — this is the classic route to "GPU VA of a page table", i.e. CPU-editable PTEs |
| **C** | **OOB kernel read into PTEs** — `ai[i].offset + ai[i].length` is a *separate* u64 add that wraps (`mem_linux.c:1298`), so `offset` can be huge and `alloc->pages + offset` walks off the source allocation; those words are installed as PTEs | `kbase_mmu_insert_pages` loop | high — uncontrolled heap reads; most likely to panic or hang |
| **D** | **`nents`-driven heap overflow** — if r20p0 also lacks the `nents ≤ 2048` bound, `vmalloc(sizeof(*ai) * nents)` and `vzalloc(sizeof(*aliased) * nents)` both wrap, and the subsequent loop writes far past the allocation | — | very high — the write loop runs `nents` times, so this is a crash generator, not a controllable primitive |

**Order of work:** A then B. C and D are last-resort and must only be attempted with the TV
idle, because a single bad `nents` turns the device into a reboot.

## Environment facts gathered from the device (read-only)

| Fact | Value | Consequence for a kernel exploit |
|---|---|---|
| Symbol exposure | `/proc/kallsyms` readable **but all addresses are `00000000`** (83 103 lines) | no free symbol leak |
| `kptr_restrict` | unreadable from shell and from our uid-0 app (SELinux) | can't confirm the exact value; behaviour matches `1`/`2` |
| `/proc/cmdline` | denied | KASLR state unknown |
| `/proc/config.gz` | absent | no `CONFIG_*` confirmation |
| Allocator | `/proc/slabinfo` **readable from shell** (SLUB-style: objsize / objperslab / pagesperslab) | useful for grooming and for post-exploit verification |
| Memory | 1 558 368 kB total, ~124 000 kB free | modest heap; SLUB partial slabs are predictable |
| **Our capabilities** | `CapInh/Prm/Eff/Bnd = 0` — **empty bounding set** | uid 0 without caps: no `CAP_SYSLOG`, no shortcuts. The LPE must be done entirely from the kernel bug itself |
| Architecture | armv7, 32-bit userspace, 3.10.79 | 32-bit kernel heap; `kbase` VA is 39-bit |

The empty capability bounding set is worth emphasising: it is dropped by
`prctl(PR_CAPBSET_DROP)` during zygote's privilege drop, *not* by `setresuid`. Patching
`setresuid` (which is what gives the root console) therefore yields `uid 0` with no
capabilities at all — which is exactly why the framework is open but `/proc/kallsyms`,
`dmesg` and raw devices are not.

## Staged test plan (designed around "do not reboot the TV")

1. **Dry run (safe, done here):** compute what the wrap produces for chosen
   `(stride, nents)` without issuing the ioctl — see
   [`alias_dryrun.c`](../exploit/cve-2022-20186/alias_dryrun.c).
2. **Single non-corrupting probe:** one `MEM_ALIAS` with `nents = 2`, a stride that wraps to
   a small `num_pages`, and alias sources whose `length` is 1 page. This creates at most a
   couple of stray PTEs at a chosen VA. Verify from userspace that the surrounding system
   is unaffected; reboot is the fallback.
3. **Primitive A measurement:** confirm the stray mapping actually resolves — e.g. point it
   at a known native allocation and read the GPU address from a second context/job, or use
   the GPU to write a sentinel through the aliased VA and observe the page contents through
   the existing CPU mapping.
4. **Primitive B construction:** force the region tracker to hand out an overlapping region
   and observe whether PTEs can be made to point at a page-table page.
5. Only after 3–4 work: aim at credentials / `selinux_state`.

Steps 2–5 all carry panic risk and must be run when nobody is watching the TV.

## Why this is worth doing anyway

Everything above is the only route off the SELinux island. The app-domain root console is
already useful, but the kernel is where `selinux_enforcing = 0` lives — and that single
variable turns the current "framework root" into real root: remount `/system`, read
`/data/system`, load modules, add a durable init service.
