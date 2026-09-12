# How it works

Everything here is first-hand measurement against `ds.exe` build
**dsq 179 / 4027081** (vanilla MD5 `e379c9366feea0a4d235a54efe678a88`) and
against the running process. No external documentation was involved, and none
of it comes from leaked source or an SDK.

Virtual addresses assume the default image base `0x140000000`. File offsets
are given where the patch actually writes.

## The chain

```
settings.cfg
  -> parser
  -> settings+0x34
  -> setStreamingMemoryMB       writes [engine+0x5BA694] AND [engine+0x5BA698]
  -> calculator 0x14199E870     min(available, MB << 20)
  -> align down to 128 MB
  -> pool+0x10                  the effective budget, in bytes
```

Five things sit on that chain. Open four of them and the fifth still wins.

## Wall 1: the preset

Four sites hold the immediate `0xC00` (3072): the value the "High" preset
writes, the preset writer, the menu list entry, and the recogniser that maps a
value back to a preset name. All four must agree, or the setting reads back as
something else and the menu falls to "Low", which is worse than not touching
anything.

This is also why the patch order matters: **the executable first, `settings.cfg`
second.** A cfg holding a value the exe's recogniser does not accept is worse
than either change alone.

## Wall 2: the setter clamp

```
0x1419AA923   mov  eax, 0x1000        ; 4096
0x1419AA92B   ...
0x1419AA938   mov  [rcx+0x5BA694], eax
```

`clamp(mb, 1536, 4096)`. The patch raises the ceiling to
`max(16384, mb + 2048)`.

Not a flat 16384: on a 24 GB card the ceiling itself would start cutting
again. A C# port of this once got that wrong: it
pinned 16384, compiled clean, and emitted different bytes for any budget above
14336. `test_setter_ceiling_rises_with_the_budget` exists for that reason.

## Wall 3: the 32-bit shift

```
0x14199E90C   mov   ebx, dword ptr [rbp + 0x5BA694]   ; MB
0x14199E927   mov   edi, 0x60000000                   ; the 1536 MB floor
0x14199E92C   cmovs rdx, rax
0x14199E930   shl   ebx, 0x14                         ; <-- 32 bits: truncates here
0x14199E936   cmp   rdx, rbx
0x14199E939   cmovb rbx, rdx                          ; min(available, budget)
0x14199E9E4   and   rbx, 0xFFFFFFFFF8000000           ; align down to 128 MB
```

`4096 << 20` does not fit in 32 bits. It becomes zero, and the `cmovb` picks
the 1536 MB floor. **Asking for more gave you less.** This is the single
consumer: the field `[engine+0x5BA694]` is touched 8 times in the whole
executable and the other 7 are default writes and configuration plumbing.

It cannot be fixed in place, because `shl rbx, 0x14` needs a REX prefix and the
7 bytes at `0x14199E92C` are already full. So the two instructions are
relocated:

```
0x14199E92C   jmp <cave>            ; E9 rel32
0x14199E931   nop
0x14199E932   nop

<cave>        cmovs rdx, rax        ; 48 0F 48 D0
              shl   rbx, 0x14       ; 48 C1 E3 14   <- 64 bits
              jmp   0x14199E933     ; E9 rel32
```

Only two register-only instructions move. Neither touches memory, so the cave
having no unwind info of its own cannot cause an exception to unwind through
it. Verified that no jump anywhere in the binary lands inside the 7
overwritten bytes.

The cave is an `int3` padding run, 18 bytes at `0x14199E85E` in this build,
found by scanning outward from the detour in 0x100-byte windows, skipping
anything that falls inside a `.pdata` function range.

**On a hit the scan walks backwards to the first real `0xCC` before choosing.**
Without that, the byte chosen depends on where the scan window happened to
open, and the patch stops being reproducible. That bug shipped once: it put
the cave at `0x0199DC5F` instead of `0x0199DC5E`, one byte off, and produced a
different executable for the same inputs.

A jmp's `rel32` is measured from the **end** of the jmp. Counting the `E9`
opcode twice, once in the accumulated body length and once in the +5,
returns control to `0x14199E932`, the middle of an instruction. That bug also
shipped once, in a port that compiled without a single warning.

## Wall 4: the mip bias

The most expensive one to find, because it is not a limit. The same setter
writes a **second** field nobody had looked at:

```
0x1419AA938   mov    [rcx+0x5BA694], eax        ; the budget, in MB
0x1419AA93E   add    eax, 0xfffffa00            ; -1536
0x1419AA94A   vdivss xmm1, xmm0, [0x143B9CE68]  ; / 1280.0
0x1419AA952   vsubss xmm0, xmm2, xmm1           ; 1.0 - that
0x1419AA956   vminss xmm0, xmm2, xmm0           ; min(1.0, ...)
0x1419AA95A   vmovss [r9+0x5BA698], xmm0        ; <-- the mip bias
```

The consumer at `0x141C79B0C` does `vcvttss2si`: it **truncates to an integer**
and uses it as a mip level bias.

The engine's design range: 1536 MB → +1, 2816 → 0, 4096 → −1.

| `streaming_memory_mb` | resulting bias |
|---|---|
| 4095 | −0.999 → **0** |
| 8192 | −4.2 → **−4** |
| 12288 | −7.4 → **−7** |

A bias of −7 asks for mips seven levels finer than normal on everything, at
every distance. The streamer cannot possibly satisfy that, so it thrashes:
constant eviction, high mips served, textures that look soft and flat and get
**worse** the more texture data you add, with VRAM usage not even rising.

The constant `1280.0` at `0x143B9CE68` has **exactly one reference in the whole
executable**, confirmed by a linear sweep rather than an index. So it can be
rewritten with a divisor that puts the bias wherever you want it:

```
D = (mb - 1536) / (1.0 - desired_bias)
```

`0.0` is not an arbitrary choice: it is the engine's own default, the value
its no-object branch zeroes the register to.

This is why the patch has no "budget only" mode. Raising the budget without
this is a downgrade.

## Wall 5: the assumed VRAM

The real ceiling, and the one that made all the others pointless.

```
0x14199A6A7   movabs rax, 0x180000000     ; 6144 MB
0x14199A6B1   mov    qword ptr [rdi+0x48], rax
```

`engine+0x48` caps the entire available-memory calculation:

```
available = min(real VRAM, engine+0x48) - reserve - ...
budget    = min(available, streaming_memory_mb)
```

**The engine never queries the card.** Measured live with `engine+0x48` at
6144 MB and a reserve of 4253 MB, the budget came out at **2816 MB, less than
stock** on a 16 GB card. Ten gigabytes discarded before it started.

**And there are two writers, not one.** Patching the `movabs` alone is not
enough. Afterwards `0x1419A53F0` runs and copies 16 bytes of a template out of
`.rdata` over the same field:

```
0x1419A5430   vmovdqu xmm0, [0x143B9CE90]   ; 6144 MB, 96 MB
0x1419A5440   vmovdqu [rsp+0x2e0], xmm0
0x1419A548C   vmovups ymm0, [rsp+0x2e0]
0x1419A5495   vmovups [rcx+0x48], ymm0      ; overwrites what the init wrote
```

The template also leaves `[rcx+0x70]` = `0x20000000` = 512 MB, and reading the
live process showed 512 MB there while the init writes 128 MB. That mismatch
is what gave the second writer away.

**Symptom without disassembling anything:** with only the `movabs` patched the
budget starts high (6016 MB) and *decays* to 2816 over a few minutes. With the
template patched too it holds steady.

Like the divisor, the template has exactly one reference in the binary.

## A separate ceiling: the per-frame arena

Not one of the five walls, not about streaming, and off by default. It shares
this page because it is patched from the same engine constructor.

Every frame is assembled inside a fixed block with a bump allocator. Running
past the end is fatal by design:

```
0x1963220   lea       r10d, [r14 - 1]                  ; requested size
0x196322A   lock xadd [r15+0xC0], eax                  ; bump, shared across threads
0x196327D   mov       eax, dword ptr [r15+0x140]       ; capacity, fixed
0x1963284   cmp       r11d, eax
0x1963287   jbe       ok
0x196329A   call      0x1950640
0x19506F3   mov       dword ptr [0], 0xDEADCA7         ; Decima's assert handler
```

So `0xDEADCA7` in a crash log is the engine **rejecting an allocation**, and
the stack above it names the subsystem that asked. Evidence that it is a
genuine exhaustion rather than one huge request: three measured crashes asked
for `0x8DC0`, `0xD140` and, the telling one, `0x3E0` bytes. That last one is
992 bytes, and it failed too.

What fills it is geometry. `0x19784B0` unpacks a 16-bit stride, rounds it up
to 16, multiplies by an instance count and asks the arena for that, tagged
`0x2E`. The more geometry in frame, the fuller it gets. A mirror draws the
whole scene a second time, which is why that is where it goes over, and why
this is also the real ceiling on any mod that pushes draw distance out.

The arena's own structure, from its constructor at `0x19505F0`. The fields are
`0x40` bytes apart, one cache line each, because the allocator is multi-threaded:

| Offset | Field |
| --- | --- |
| `+0x00` | base |
| `+0x40` | size |
| `+0x80` | header |
| `+0xC0` | current offset (atomic) |
| `+0x140` | capacity = `[+0x40] - [+0x80]` |

The size comes from the engine's root constructor at `0x199A640`, which lays
out a budget table and then builds the arena from it:

```
0x199A69F   mov    qword ptr [rdi+0x50], 0x6000000    ; 96 MB   <- this
0x199A6A7   movabs rax, 0x180000000                   ; assumed VRAM
0x199A6B1   mov    qword ptr [rdi+0x48], rax
...
0x199A75F   lea    rcx, [rdi+0x9C0]                   ; the arena
0x199A766   call   0x19505F0                          ; its constructor
```

`+0x48` is the assumed VRAM of wall 5 and `+0x50` is this: contiguous fields
of one object, six bytes apart in the encoding.

**And, exactly like wall 5, there are two writers.** Patching that immediate
alone was tried in a running game and changed nothing: the capacity still
read 96 MB. The template copy of wall 5 is a 32-byte store landing at
`+0x48`, so it covers `+0x50` as well and puts the stock size straight back:

```
0x1419A5430   vmovdqu xmm0, [0x143B9CE90]   ; 6144 MB, then 96 MB
0x1419A5440   vmovdqu [rsp+0x2e0], xmm0
0x1419A548C   vmovups ymm0, [rsp+0x2e0]
0x1419A5495   vmovups [rcx+0x48], ymm0      ; 32 bytes: +0x48 AND +0x50
```

The template's second qword is the arena size, and it was hiding in plain
sight inside the byte pattern this tool already matched for wall 5:
`00 00 00 80 01 00 00 00` is 6144 MB and the `00 00 00 06` right after it is
96 MB. So the patch writes **both** sites or neither; writing one is a no-op
that looks applied.

**It has to be patched on disk.** Growing it in a running process was tried
twice and does not hold: the engine reinitialises the arena itself and undoes
the change.

**Why neither site is located by a pattern that carries its value.** Both
immediates are things this patch writes, so any pattern containing them stops
matching the moment it is applied, and both the read-back and `locate()` have
to keep working on a file that has been patched. That bites twice here: the
template's own bytes used to be the wall-5 pattern, and they carry the arena
size too, so writing the arena would have blinded the VRAM site and writing
the VRAM would have blinded the arena.

The template is therefore addressed through the two budget qwords that sit
`0x18` before it, `0x800` and `0x400000`, values nothing writes. The assumed
VRAM is at `anchor + 0x18` and the arena at `anchor + 0x20`, with the
template's always-zero third slot checked before either offset is trusted.

The constructor immediate is found through the two instructions that follow
the VRAM store instead:

```
45 33 C0              xor r8d, r8d
C7 47 58 00 00 00 02  mov dword ptr [rdi+0x58], 0x2000000
```

unique in a stock file and in a patched one, carrying no value any patch
writes, with the immediate at `anchor - 0x12`. The store opcode is checked
before the offset is trusted. The obvious shorter anchors are useless:
`48 C7 47 50` alone matches 49 times in this build, and the wall-5 anchor
`48 89 47 48` matches 130.

**The value is a byte count, not MB**, and the store is `mov r/m64, imm32`,
which **sign-extends**, so 2048 MB and up would arrive negative. That, not
caution, is why the range stops where it does.

| Size | Immediate |
| --- | --- |
| 96 MB (stock) | `00 00 00 06` |
| 192 MB | `00 00 00 0C` |
| 512 MB (ceiling) | `00 00 00 20` |

**Confirmed against a running game**, which is the only reason this shipped.
Patching the constructor immediate alone changes nothing, and that is what
turned up the template; with both written, the capacity the engine reports
moves to the new size. The copy from `[rdi+0x50]` through to `[arena+0x40]`
was never traced instruction by instruction, and after that measurement it
does not need to be.

## Locating everything by pattern

No offset in the list above is hardcoded in the script. Each site is found by
a byte signature that must appear **exactly once** in the file; more than one
match is treated the same as none, and the script refuses to write.

| key | pattern | field |
|---|---|---|
| `preset_high` | `B8 00 0C 00 00 C3` | +1, u32 |
| `preset_write` | `C7 41 44 00 0C 00 00 C7 41 50 02 00 00 00` | +3, u32 |
| `preset_menu` | `41 C7 00 00 0C 00 00 8B 13` | +3, u32 |
| `preset_match` | `3D 00 0C 00 00 75` | +1, u32 |
| `setter_ceiling` | `41 B8 00 06 00 00 B8 00 10 00 00` | +7, u32 |
| `vram_code` | `48 B8 00 00 00 80 01 00 00 00` | +2, u64 |
| `vram_template` | `00 00 00 80 01 00 00 00 00 00 00 06 00 00 00 00` | +0, u64 |
| `detour` | `48 0F 48 D0 C1 E3 14 48 8B 01` | 7 bytes replaced |

Three sites cannot be found on their own:

- **`mip_divisor`.** Its `vdivss` opcode is far too common. It is located by
  scanning forward at most 80 bytes from `setter_ceiling`, a site already
  trusted, then following the RIP-relative displacement to the constant and
  sanity-checking that it is a positive float.
- **The cave.** Found structurally, as described under wall 3.
- **`arena_size`.** Found through a downstream anchor rather than its own
  pattern, so that it stays findable once written. See the per-frame arena
  section above.

## Reading the live process

```
python dsdc_streaming_unlock.py measure
```

`ReadProcessMemory` only. Nothing is injected, nothing is installed.

```
engine  = *(void**)(base + 0x4F6D430)
request =  (uint32 )(engine + 0x5BA694)          in MB
mip bias=  (float  )(engine + 0x5BA698)
VRAM cap=  (uint64 )(engine + 0x48)              in bytes
pool    =            engine + 0x2CD28
budget  =  (uint64 )(pool + 0x10)                in bytes  <- the proof
```

These are **not** pattern-matched. They belong to this build and will not
survive an update; `measure` is a diagnostic, not part of the patch.

## The two figures on the options screen

The game prints "available graphics memory" as a pair, and both halves are
worth knowing because sizing the budget against them is what keeps the engine
from over-committing.

**Required** comes from the estimator at `0x1426427E0`:

```asm
mov     edi, 0x25800000            ; a flat 600 MB
call    0x141CCEF30                ; + render targets for the current settings
add     rdi, rax
movsxd  rax, dword ptr [rbx+0x34]  ; streaming_memory_mb
shl     rax, 0x14                  ; << 20, in 64 bits, and clean
add     rax, rdi
```

`0x141CCEF30` temporarily scales width and height by the upscaling factor
(0.5 for one of the DLSS modes, 1.0 otherwise), calls the render-target sizer
at `0x141CCFB90`, then puts the real resolution back. Modelling that exactly
means reverse-engineering the whole render-target table, which is why this
tool estimates it and offers `fit` for anyone who wants the exact figure.

**Available** comes from `0x142642790`, which is a thin wrapper:

```asm
lea     rdx, [rsp+0x20]
lea     rcx, [rip+0x2F167C8]
call    0x1419A4EA0                ; -> virtual call [rax+0x70]
mov     rax, qword ptr [rsp+0x20]  ; returns the first qword
```

That virtual call fills four qwords at `rsp+0x20`, which is exactly the shape
of `DXGI_QUERY_VIDEO_MEMORY_INFO` (Budget, CurrentUsage,
AvailableForReservation, CurrentReservation), and the first one is returned.
So **available is the DXGI Budget**, what Windows is currently willing to
give the process, and not anything this patch writes. Confirmed against a
16 GB card: DXGI reports a 15227 MB budget, and the game shows 14.9 GB.

Both results are converted the same way in `0x1430F1ED5`: integer to float,
then multiplied three times by 0.0009765625 (1/1024), i.e. bytes to GB.

The practical consequence: raising the streaming budget raises the *required*
side one-for-one, while the *available* side does not move. Asking for more
than the card has available is what the stock recommendation used to do.

## Two notes on method

**`.pdata` covers only about 54% of `.text`.** It gives 155,834 functions with
exact bounds, which is enough to index 7.9 million instructions in ten seconds
without Ghidra or IDA, but leaf functions with no unwind info are simply
absent from it. The setter and the mip bias consumer were both in that
missing 46%. Use `.pdata` to navigate; use a linear sweep with
resynchronisation to actually search.

**Measure the process before theorising about the binary.** Three rounds of
static reasoning about this executable produced three changes that each made
things worse. Both findings that solved it, walls 4 and 5, appeared
within minutes of reading memory out of the running game. A ten-second
`ctypes` read, with nothing installed and nothing injected, settled what three
blind edits could not.
