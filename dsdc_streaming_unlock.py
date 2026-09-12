#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Raise the texture streaming budget of Death Stranding Director's Cut.

The engine caps itself at 3072 MB whatever the card has. Four things do it:

  1. the "High" preset asks for 3072 and the setter clamps above 4096
  2. `shl ebx, 0x14` converts MB to bytes in 32 bits, so 4096+ shifts out to
     zero and the engine falls back to its 1536 MB floor
  3. it never queries the card, assuming 6144 MB from an immediate in .text
     and a template in .rdata (both need patching, the template wins)
  4. the setter derives a mip bias from the same number. Left alone it hits
     -7, which pins mip 0 on everything and makes textures worse than stock.
     Not optional, no flag to skip it.

Sites are found by byte pattern, not fixed offset. A missing or ambiguous
pattern aborts without writing. docs/how-it-works.md has the disassembly.

Written for a texture mod: at 3072 MB the streamer evicts faster than it
loads, so the mod got worse the more went into it.

Unofficial, unaffiliated with Kojima Productions, 505 Games or Sony. No
warranty. No game files are redistributed; this patches your own ds.exe after
backing it up. Standard library only.

    python dsdc_streaming_unlock.py [apply|revert|verify|measure|fit] [--help]

PlushRapier145, MIT licence.
"""

import argparse
import ctypes
import glob
import hashlib
import os
import re
import shutil
import stat
import struct
import sys
import time

VERSION = "2.0"

# The build every offset and measurement in this project was taken from.
# A different build is not refused (the patterns decide that), but it is
# called out, because nobody has measured that one.
KNOWN_VANILLA_MD5 = "e379c9366feea0a4d235a54efe678a88"
KNOWN_BUILD = "dsq 179 / 4027081"

BACKUP_EXE = "ds.exe.original"
BACKUP_CFG = "settings.cfg.original"


# ==========================================================================
# Language
# ==========================================================================
#
# Every line the tool prints goes through _(). English is the source text and
# the key; SPANISH at the bottom of this file holds the other half. A test
# walks the AST and fails if any _() literal is missing from that table, so a
# half-translated build cannot ship.

LANG = "en"


def detect_language():
    """Spanish when Windows itself is in Spanish, English otherwise.

    Reads the UI language rather than the locale: someone running an English
    Windows with Mexican regional formats wants English text."""
    if os.name != "nt":
        return "en"
    try:
        langid = _k32().GetUserDefaultUILanguage()
        return "es" if (langid & 0x3FF) == 0x0A else "en"   # 0x0A = Spanish
    except (OSError, AttributeError):
        return "en"


def _(text):
    """Translate one line of output. Unknown text passes through unchanged."""
    if LANG == "en":
        return text
    return SPANISH.get(text, text)

# The two figures the options screen shows, read out of the estimator at
# 0x1426427E0 and the query at 0x142642790:
#
#   required  = MENU_BASE_MB + render targets + streaming_memory_mb
#   available = the DXGI Budget, what Windows grants now, not sticker VRAM
MENU_BASE_MB = 600                  # the flat 0x25800000 the estimator starts from

# Calibrated on one configuration (2560x1440 costing about 424 MB beyond the
# base), so it is an estimate. `fit` takes the exact figure off the screen.
RENDER_TARGET_MB_PER_MPX = 115
DEFAULT_MPX = 3.69                  # 1440p, when settings.cfg has no resolution


# ==========================================================================
# Minimal PE reader
# ==========================================================================

class PE(object):
    """Just enough PE64 to map file offsets to virtual addresses and back,
    plus the .pdata function table so the code cave never lands inside a
    function."""

    def __init__(self, data):
        # struct.error is not a ValueError, so without this a ds.exe cut short
        # by an interrupted download reaches the caller as a traceback instead
        # of "I don't recognise this file".
        try:
            self._parse(data)
        except struct.error:
            raise ValueError(_("truncated or malformed PE header"))

    def _parse(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError(_("not a Windows executable"))
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError(_("invalid PE header"))
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError(_("only 64-bit PE files are supported"))
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
        self.pdata_rva, self.pdata_size = 0, 0
        if ndirs > 3:
            self.pdata_rva, self.pdata_size = struct.unpack_from("<II", data, opt + 112 + 24)
        sec = opt + opt_size
        self.sections = []
        for i in range(nsec):
            o = sec + i * 40
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((vaddr, vsize, raddr, rsize))
        self._funcs = None

    def off_to_va(self, off):
        for vaddr, vsize, raddr, rsize in self.sections:
            if raddr <= off < raddr + rsize:
                return self.image_base + vaddr + (off - raddr)
        return None

    def va_to_off(self, va):
        rva = va - self.image_base
        for vaddr, vsize, raddr, rsize in self.sections:
            if vaddr <= rva < vaddr + vsize:
                o = raddr + (rva - vaddr)
                return o if o < raddr + rsize else None
        return None

    def section_of(self, off):
        """(raw_start, raw_end) of the section holding this file offset."""
        for vaddr, vsize, raddr, rsize in self.sections:
            if raddr <= off < raddr + rsize:
                return raddr, raddr + rsize
        return None

    def functions(self):
        """Function ranges from .pdata, sorted. Note this covers only about
        54% of .text, since leaf functions without unwind info are absent, so it
        is good enough to say "this is definitely inside a function" but never
        to say "this address is unreachable"."""
        if self._funcs is not None:
            return self._funcs
        self._funcs = []
        o = self.va_to_off(self.image_base + self.pdata_rva)
        if o is None or not self.pdata_size:
            return self._funcs
        end = min(o + self.pdata_size, len(self.data) - 12)
        for i in range(o, end, 12):
            beg, fin, _ = struct.unpack_from("<III", self.data, i)
            if beg and fin > beg:
                self._funcs.append((self.image_base + beg, self.image_base + fin))
        self._funcs.sort()
        return self._funcs

    def in_function(self, va):
        funcs = self.functions()
        lo, hi = 0, len(funcs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if va < funcs[mid][0]:
                hi = mid - 1
            elif va >= funcs[mid][1]:
                lo = mid + 1
            else:
                return True
        return False


# ==========================================================================
# Byte patterns
# ==========================================================================

def _h(s):
    return bytes.fromhex(s.replace(" ", ""))


# Two budget-table qwords (0x800 and 0x400000) that sit 0x18 before the
# engine's memory template. Neither is a value this tool writes, so this
# stays findable whatever has already been patched.
TEMPLATE_ANCHOR = "00 08 00 00 00 00 00 00 00 00 40 00 00 00 00 00"

# key, pattern, offset of the field inside the pattern, width, description.
# Descriptions stay in English here and go through _() where they are shown.
SITES = [
    ("preset_high",    "B8 00 0C 00 00 C3",           1, 4, '"High" preset value'),
    ("preset_write",   "C7 41 44 00 0C 00 00 C7 41 50 02 00 00 00",
                                                      3, 4, "preset writer"),
    ("preset_menu",    "41 C7 00 00 0C 00 00 8B 13",  3, 4, "menu list entry"),
    ("preset_match",   "3D 00 0C 00 00 75",           1, 4, "preset recogniser"),
    ("setter_ceiling", "41 B8 00 06 00 00 B8 00 10 00 00",
                                                      7, 4, "setter upper clamp"),
    ("vram_code",      "48 B8 00 00 00 80 01 00 00 00",
                                                      2, 8, "assumed VRAM (code)"),
    # The 16-byte template the engine copies over [rcx+0x48] with a 32-byte
    # `vmovups`, which lands on TWO fields: +0x48 the assumed VRAM, +0x50 the
    # per-frame arena. Both are patched here, and both are addressed through
    # the same anchor, sixteen bytes of budget table that sit just before it.
    #
    # The anchor is deliberately NOT the template's own bytes. Those used to
    # be the pattern, and they carry both values, so writing either one made
    # the site unfindable and blinded locate() on a file patched with the
    # other. The anchor carries nothing anybody writes.
    ("vram_template",  TEMPLATE_ANCHOR, 0x18, 8, "assumed VRAM (template)"),
    ("arena_template", TEMPLATE_ANCHOR, 0x20, 8, "per-frame arena (template)"),
]

# cmovs rdx,rax / shl ebx,0x14 / mov rax,[rcx]: the 32-bit shift and enough
# context after it to be unique. The first 7 bytes get replaced by the detour.
PAT_DETOUR = _h("48 0F 48 D0 C1 E3 14 48 8B 01")
# vdivss xmm1, xmm0, [rip+disp32]: the mip bias division, found by scanning
# forward from the setter clamp rather than by its own (non-unique) pattern.
PAT_VDIVSS = _h("C5 FA 5E 0D")
# mov [rdi+0x48], rax: anchor for reading back the assumed VRAM of a file
# that is already patched (its immediate no longer matches vram_code).
PAT_VRAM_ANCHOR = _h("48 89 47 48")
PAT_CMOVS = _h("48 0F 48 D0")
PAT_SHL_RBX = _h("48 C1 E3 14")

CAVE_LEN = 13  # cmovs(4) + shl rbx(4) + jmp rel32(5)

# --- the per-frame arena ---------------------------------------------------
#
# mov qword ptr [rdi+0x50], 0x6000000, six bytes ahead of vram_code in the
# same engine constructor: +0x48 is the assumed VRAM, +0x50 the size of the
# arena every frame is built in.
#
# It is NOT located by that pattern, though. The immediate is the thing this
# patch writes, so the pattern stops matching the moment the arena is
# resized, and both the read-back and locate() itself have to keep working on
# a file that has it. The anchor below is the two instructions that follow
# the VRAM store; it is unique in a vanilla file and in a patched one, and it
# carries no value any patch writes.
#
#   45 33 C0           xor r8d, r8d
#   C7 47 58 ...       mov dword ptr [rdi+0x58], 0x2000000
#
# "48 C7 47 50" on its own is no good as an anchor: 49 matches in this build.
# PAT_VRAM_ANCHOR is worse, at 130.
PAT_ARENA_ANCHOR = _h("45 33 C0 C7 47 58 00 00 00 02")
PAT_ARENA_STORE = _h("48 C7 47 50")
ARENA_BACK = 0x12  # anchor start -> the arena immediate


class Edit(object):
    __slots__ = ("off", "old", "new", "desc", "note")

    def __init__(self, off, old, new, desc, note=""):
        self.off, self.old, self.new, self.desc, self.note = off, old, new, desc, note


def find_unique(data, pat):
    """Offset of pat, but only if it occurs exactly once. Ambiguity is a
    refusal, not a coin flip."""
    first = data.find(pat)
    if first < 0:
        return None
    return None if data.find(pat, first + 1) >= 0 else first


def arena_site(data):
    """(file offset of the per-frame arena immediate, error).

    Separate from locate() because it must work whatever else has been
    written: the streaming patch, this one, both, or neither. Ambiguity is a
    refusal here too, and the store opcode is checked so a coincidental
    anchor cannot silently point four bytes at something else.
    """
    at = find_unique(data, PAT_ARENA_ANCHOR)
    if at is None:
        return None, _("cannot find (or found more than one) the per-frame arena")
    off = at - ARENA_BACK
    if off < 4 or data[off - 4:off] != PAT_ARENA_STORE:
        return None, _("the per-frame arena size is not where it should be")
    return off, None


def locate(pe):
    """(sites, error). sites maps key -> (file offset, description)."""
    try:
        return _locate(pe)
    except struct.error:
        return None, _("truncated or malformed PE header")


def _locate(pe):
    d = pe.data
    sites = {}
    for key, pattern, delta, _width, desc in SITES:
        p = find_unique(d, _h(pattern))
        if p is None:
            return None, _("cannot find (or found more than one) '%s'") % _(desc)
        sites[key] = (p + delta, desc)

    # The template's third slot is always zero. Cheap proof that the anchor
    # landed on the template itself and not on a lookalike run of budget
    # numbers somewhere else in .rdata.
    try:
        if struct.unpack_from("<Q", d, sites["vram_template"][0] + 16)[0] != 0:
            return None, _("the memory template is not where it should be")
    except struct.error:
        return None, _("the memory template is not where it should be")

    det = find_unique(d, PAT_DETOUR)
    if det is None:
        return None, _("cannot find the MB->bytes conversion")
    sites["detour"] = (det, _("MB->bytes conversion, 32-bit to 64-bit"))

    # The mip bias division lives a few instructions after the setter clamp.
    # Its own opcode is far too common to search for on its own, so it is
    # located relative to a site we already trust.
    base = sites["setter_ceiling"][0] - 7
    k = d[base:base + 80].find(PAT_VDIVSS)
    if k < 0:
        return None, _("cannot find the mip bias division")
    ins = base + k
    va = pe.off_to_va(ins)
    if va is None:
        return None, _("the mip bias division falls outside the file")
    rel = struct.unpack_from("<i", d, ins + 4)[0]
    off = pe.va_to_off(va + 8 + rel)
    if off is None or struct.unpack_from("<f", d, off)[0] <= 0:
        return None, _("the mip bias constant is not recognisable")
    sites["mip_divisor"] = (off, _("mip bias divisor"))

    arena, err = arena_site(d)
    if err:
        return None, err
    sites["arena_size"] = (arena, _("per-frame arena size"))
    return sites, None


def find_cave(pe, detour_off, need=CAVE_LEN):
    """int3 padding in the detour's section, outside every .pdata function.

    On a hit, walk back to the first 0xCC of the run. The 0x100-byte scan
    window can open mid-padding, and taking whatever it lands on makes the
    patch non-reproducible.
    """
    d = pe.data
    span = pe.section_of(detour_off)
    if span is None:
        return None
    lo, hi = span

    for radius in range(0x100, 0x20000, 0x100):
        for start in (detour_off - radius, detour_off + radius):
            a, b = max(lo, start), min(hi, start + 0x100)
            i = a
            while i < b:
                if d[i] != 0xCC:
                    i += 1
                    continue
                cand = i
                while cand > lo and d[cand - 1] == 0xCC:
                    cand -= 1
                j = i
                while j < hi and d[j] == 0xCC:
                    j += 1
                if j - cand >= need + 2:
                    va1 = pe.off_to_va(cand)
                    va2 = pe.off_to_va(cand + need - 1)
                    if (va1 is not None and va2 is not None
                            and not pe.in_function(va1) and not pe.in_function(va2)):
                        return cand
                i = j
    return None


def cave_body(cave_va, return_va):
    """cmovs rdx,rax / shl rbx,0x14 / jmp back.

    Both relocated instructions are register-only, so the cave having no
    unwind info cannot matter. rel32 runs from the end of the jmp, so the +5
    covers opcode and displacement and `body` must not already include them.
    """
    body = PAT_CMOVS + PAT_SHL_RBX
    end_of_jmp = cave_va + len(body) + 5
    return body + b"\xE9" + struct.pack("<i", return_va - end_of_jmp)


def detour_body(detour_va, cave_va):
    """jmp to the cave, then two nops to fill out the 7 bytes we overwrite."""
    return b"\xE9" + struct.pack("<i", cave_va - (detour_va + 5)) + b"\x90\x90"


# ==========================================================================
# The numbers
# ==========================================================================

def r128(mb):
    """The engine rounds the budget DOWN to a multiple of 128 MB
    (`and rbx, 0xFFFFFFFFF8000000`). Ask for 4095 and you get 3968. The old
    "4095 MB" patch delivered 3968 MB for months without anyone noticing."""
    return int(mb) // 128 * 128


def setter_ceiling(mb):
    """The clamp has to sit above what we ask for. A fixed 16384 works only
    while the budget stays below it; on a 24 GB card the ceiling itself would
    start cutting again."""
    return max(16384, mb + 2048)


def mip_divisor(mb, bias=0.0):
    """Divisor that leaves the derived mip bias at `bias`.

    The setter computes min(1.0, 1.0 - (mb - 1536) / 1280.0) and the consumer
    truncates it to an integer mip level. Design range 1536 -> +1, 2816 -> 0,
    4096 -> -1; left at 1280.0 a large budget gives -7 at 12288. 0.0 is the
    engine's neutral, -1.0 the strongest it asks for itself.
    """
    if mb <= 1536:
        return 1280.0
    return (mb - 1536) / (1.0 - bias)


def mip_bias_of(mb, divisor):
    """What the engine will actually compute, and what it truncates to."""
    if not divisor:
        return 0.0
    return min(1.0, 1.0 - (mb - 1536) / divisor)


def render_target_estimate(width=0, height=0):
    """Roughly what the options screen charges for render targets."""
    mpx = (width * height) / 1000000.0 if width and height else DEFAULT_MPX
    return max(256, int(RENDER_TARGET_MB_PER_MPX * mpx))


def menu_required_mb(mb, width=0, height=0):
    """What the game's options screen will report as required."""
    return MENU_BASE_MB + render_target_estimate(width, height) + mb


def nominal_vram_mb(dedicated_mb):
    """Card size rounded up to a whole GB.

    DXGI reports 15995 for a 16 GB card, the registry 16303. The engine takes
    min(real VRAM, this), so anything at or above the real size is equivalent.
    """
    if dedicated_mb <= 0:
        return 0
    return max(1024, ((dedicated_mb + 1023) // 1024) * 1024)


def recommend(available_mb, width=0, height=0):
    """Budget that makes both figures on the options screen read alike.

    Steps are 128 MB and the screen shows tenths of a GB, so flooring loses a
    whole step and rounding overshoots on some cards. Take the largest step
    whose displayed requirement fits the displayed available.

    Whether matching them buys any budget is unmeasured; `measure` answers it.
    """
    room = available_mb - MENU_BASE_MB - render_target_estimate(width, height)
    floor = r128(room)
    shown = round(available_mb / 1024.0, 1)
    for candidate in (floor + 128, floor):
        if candidate >= 1536 and round(
                menu_required_mb(candidate, width, height) / 1024.0, 1) <= shown:
            return candidate
    return max(1536, floor)


def screen_reading(mb, available_mb, width=0, height=0):
    """The "required / available" pair the options screen will show.

    Quoted next to every budget because the two are easy to confuse: 14208 MB
    of streaming reads as 14.9 GB there, the screen having added render
    targets and the 600 MB base.
    """
    if not available_mb:
        return None
    return "%.1f GB / %.1f GB" % (menu_required_mb(mb, width, height) / 1024.0,
                                  available_mb / 1024.0)


def fit_budget(current_mb, required_gb, available_gb):
    """The budget that makes the two figures on the options screen meet.

    Needs no model at all: the screen already did the arithmetic. Whatever the
    render targets and the base actually cost, they are the same in both terms,
    so the slack is simply the difference between the two numbers shown."""
    slack_mb = int(round((available_gb - required_gb) * 1024))
    return r128(max(1536, current_mb + slack_mb))


# ==========================================================================
# Building the patch
# ==========================================================================

ENGINE_FLOOR_MB = 1536          # the engine's own lower clamp
MAX_BUDGET_MB = 262144          # 256 GB: far past any card, keeps the u32 sane

# The per-frame arena. Plain system RAM, not VRAM: raising it costs exactly
# that many more bytes and nothing else.
STOCK_ARENA_MB = 96             # what the engine builds it at
MIN_ARENA_MB = 96               # passing the stock size is how you turn it off
MAX_ARENA_MB = 512
DEFAULT_ARENA_MB = 192
# The store is `mov r/m64, imm32`, which SIGN-extends: 2048 MB (0x80000000)
# and up would arrive as a negative size. The ceiling above is far below that,
# and this is the reason it cannot simply be raised.
ARENA_IMM_MAX_MB = 2047


def check_arena(arena_mb):
    """Error string, or None."""
    if not MIN_ARENA_MB <= arena_mb <= MAX_ARENA_MB:
        return _("the frame arena must be between %d and %d MB") % (MIN_ARENA_MB,
                                                                    MAX_ARENA_MB)
    if arena_mb > ARENA_IMM_MAX_MB:
        return _("the frame arena cannot go past %d MB: the instruction "
                 "sign-extends") % ARENA_IMM_MAX_MB
    return None


def check_values(mb, vram_mb, bias=0.0, arena_mb=None):
    """Error string, or None. The last gate before any byte is computed.

    Lives here rather than in the argument parser so every entry point is
    covered: a budget of 0 once got written straight through, and a negative
    one reached struct.pack and came out as a traceback.
    """
    if not ENGINE_FLOOR_MB <= mb <= MAX_BUDGET_MB:
        return _("budget must be between %d and %d MB") % (ENGINE_FLOOR_MB,
                                                           MAX_BUDGET_MB)
    if not ENGINE_FLOOR_MB <= vram_mb <= MAX_BUDGET_MB:
        return _("assumed VRAM must be between %d and %d MB") % (ENGINE_FLOOR_MB,
                                                                 MAX_BUDGET_MB)
    # At 1.0 the divisor is zero and above it goes negative, which flips the
    # bias positive. Below -8 the engine clamps anyway.
    if not -8.0 <= bias < 1.0:
        return _("mip bias must be under 1.0 and no lower than -8.0")
    if arena_mb is not None:
        return check_arena(arena_mb)
    return None


def plan(pe, sites, mb, vram_mb, bias=0.0, arena_mb=None):
    """(edits, error). Nothing is written here.

    arena_mb left at None means the per-frame arena is not touched at all: it
    is a separate patch on a separate field, and leaving it out has to produce
    byte-for-byte the same file as before it existed.
    """
    bad = check_values(mb, vram_mb, bias, arena_mb)
    if bad:
        return None, bad
    d = pe.data
    edits = []

    def imm(key, new):
        off, desc = sites[key]
        edits.append(Edit(off, d[off:off + len(new)], new, desc))

    for key in ("preset_high", "preset_write", "preset_menu", "preset_match"):
        imm(key, struct.pack("<I", mb))
    imm("setter_ceiling", struct.pack("<I", setter_ceiling(mb)))
    for key in ("vram_code", "vram_template"):
        imm(key, struct.pack("<Q", vram_mb * 1024 * 1024))
    imm("mip_divisor", struct.pack("<f", mip_divisor(mb, bias)))
    if arena_mb is not None:
        # BOTH writers, or neither. The constructor stores the immediate and
        # the template is copied over it straight afterwards, so patching the
        # immediate alone changes nothing at all: measured, not assumed.
        imm("arena_size", struct.pack("<I", arena_mb * 1024 * 1024))
        imm("arena_template", struct.pack("<Q", arena_mb * 1024 * 1024))

    detour_off = sites["detour"][0]
    cave_off = find_cave(pe, detour_off)
    if cave_off is None:
        return None, _("cannot find a safe code cave for the detour")
    cave_va = pe.off_to_va(cave_off)
    detour_va = pe.off_to_va(detour_off)
    if cave_va is None or detour_va is None:
        return None, _("the detour or the cave falls outside the file")

    edits.append(Edit(cave_off, d[cave_off:cave_off + CAVE_LEN],
                      cave_body(cave_va, detour_va + 7), _("relocated 64-bit shift")))
    edits.append(Edit(detour_off, d[detour_off:detour_off + 7],
                      detour_body(detour_va, cave_va), _("detour to the cave")))

    for e in edits:
        if len(e.old) != len(e.new):
            return None, _("internal error: '%s' would change length") % _(e.desc)
    return edits, None


def apply_edits(data, edits):
    """(patched bytes, error). Every site must still hold what the plan
    saw, or nothing is written at all. Accepting a site that already holds the
    new value would let a half-patched file through."""
    out = bytearray(data)
    for e in edits:
        if bytes(out[e.off:e.off + len(e.old)]) != e.old:
            return None, _("ABORTED at '%s': the bytes are not what was expected (file 0x%X)") % (
                _(e.desc), e.off)
        out[e.off:e.off + len(e.new)] = e.new
    return bytes(out), None


def build(data, mb, vram_mb, bias=0.0, arena_mb=None):
    """Full pipeline over a buffer: (patched bytes, edits, error).

    This is the function the tests pin to the measured MD5s."""
    try:
        pe = PE(data)
    except ValueError as exc:
        return None, None, str(exc)
    sites, err = locate(pe)
    if err:
        return None, None, err
    edits, err = plan(pe, sites, mb, vram_mb, bias, arena_mb)
    if err:
        return None, None, err
    out, err = apply_edits(data, edits)
    if err:
        return None, None, err
    return out, edits, None


# ==========================================================================
# Reading the state of a file
# ==========================================================================

VANILLA, PATCHED, UNKNOWN = "vanilla", "patched", "unknown"


def read_state(path):
    """(state, reason, pe, sites)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        pe = PE(data)
    except (OSError, ValueError) as exc:
        return UNKNOWN, str(exc), None, None
    sites, reason = locate(pe)
    if sites:
        return VANILLA, None, pe, sites
    # Our own detour is a 64-bit shl preceded by the cmovs and followed by a
    # jmp. The stock executable never has that shape.
    i = 0
    while True:
        i = data.find(PAT_SHL_RBX, i)
        if i < 0:
            break
        if i >= 4 and data[i - 4:i] == PAT_CMOVS and i + 4 < len(data) and data[i + 4] == 0xE9:
            return PATCHED, None, pe, None
        i += 1
    return UNKNOWN, reason, pe, None


def vram_from_exe(pe):
    """Assumed-VRAM immediate read back through its anchor, so it works on a
    patched file too."""
    d = pe.data
    i = 0
    while True:
        i = d.find(PAT_VRAM_ANCHOR, i)
        if i < 0:
            return None
        if i >= 10 and d[i - 10:i - 8] == b"\x48\xB8":
            return struct.unpack_from("<Q", d, i - 8)[0] // (1024 * 1024)
        i += 1


def arena_pair(data):
    """(constructor size, template size) in MB, either None if unreadable.

    Two writers hit the same field. The constructor stores its immediate
    first, then the template is copied over it, so the template is the one
    that decides. They are read separately because a file where they disagree
    is a half-applied patch worth reporting rather than averaging away.
    """
    ctor = tpl = None
    off, err = arena_site(data)
    if not err:
        try:
            ctor = struct.unpack_from("<I", data, off)[0] // (1024 * 1024)
        except struct.error:
            pass
    at = find_unique(data, _h(TEMPLATE_ANCHOR))
    if at is not None:
        try:
            tpl = struct.unpack_from("<Q", data, at + 0x20)[0] // (1024 * 1024)
        except struct.error:
            pass
    return ctor, tpl


def arena_from_exe(data):
    """The per-frame arena size the engine will actually use, in MB, or None.

    The template wins, so that is what is reported."""
    _ctor, tpl = arena_pair(data)
    return tpl


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_bytes(data):
    return hashlib.md5(data).hexdigest()


# ==========================================================================
# Windows: processes, GPU, game folder
# ==========================================================================

def _k32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_char * 260)]


def _pids_named(name=b"ds.exe"):
    """PIDs of processes with this image name, or None if we could not look."""
    if os.name != "nt":
        return None
    try:
        k32 = _k32()
        snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snap == -1:
            return None
        out = []
        entry = _PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32First(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == name:
                out.append(entry.th32ProcessID)
            ok = k32.Process32Next(snap, ctypes.byref(entry))
        k32.CloseHandle(snap)
        return out
    except OSError:
        return None


def _process_path(pid):
    try:
        k32 = _k32()
        # PROCESS_QUERY_LIMITED_INFORMATION: enough for the image path, and it
        # works across bitness and without elevation.
        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return None
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_uint32(len(buf))
        ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
        k32.CloseHandle(h)
        return buf.value if ok else None
    except OSError:
        return None


def game_running(exe):
    """Whether THIS folder's ds.exe is open. Another installation, or a test
    scratch folder, must not block us. When we cannot tell, we say yes: that
    is the safe side of the answer."""
    if os.name != "nt":
        return False
    pids = _pids_named()
    if pids is None:
        return True
    if not pids:
        return False
    try:
        target = os.path.normcase(os.path.abspath(exe))
    except OSError:
        return True
    for pid in pids:
        path = _process_path(pid)
        if path is None or os.path.normcase(os.path.abspath(path)) == target:
            return True
    return False


class _GUID(ctypes.Structure):
    _fields_ = [("d1", ctypes.c_uint32), ("d2", ctypes.c_uint16),
                ("d3", ctypes.c_uint16), ("d4", ctypes.c_ubyte * 8)]

    def __init__(self, text):
        super(_GUID, self).__init__()
        text = text.replace("-", "")
        self.d1 = int(text[0:8], 16)
        self.d2 = int(text[8:12], 16)
        self.d3 = int(text[12:16], 16)
        for i in range(8):
            self.d4[i] = int(text[16 + i * 2:18 + i * 2], 16)


class _VIDEO_MEMORY_INFO(ctypes.Structure):
    _fields_ = [("Budget", ctypes.c_uint64), ("CurrentUsage", ctypes.c_uint64),
                ("AvailableForReservation", ctypes.c_uint64),
                ("CurrentReservation", ctypes.c_uint64)]


class _ADAPTER_DESC1(ctypes.Structure):
    _fields_ = [("Description", ctypes.c_wchar * 128),
                ("VendorId", ctypes.c_uint32), ("DeviceId", ctypes.c_uint32),
                ("SubSysId", ctypes.c_uint32), ("Revision", ctypes.c_uint32),
                ("DedicatedVideoMemory", ctypes.c_size_t),
                ("DedicatedSystemMemory", ctypes.c_size_t),
                ("SharedSystemMemory", ctypes.c_size_t),
                ("AdapterLuid", ctypes.c_int64), ("Flags", ctypes.c_uint32)]


def _com(obj, index, argtypes, *args):
    """Call vtable slot `index` on a COM object.

    argtypes must be spelled out. They cannot be derived from the values,
    since byref() returns a CArgObject that is not a valid argtype.
    """
    vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(vtbl[index])
    return fn(obj, *args)


def dxgi_memory():
    """(name, dedicated MB, available MB) of the best hardware adapter.

    "Available" is the DXGI Budget: what Windows grants right now, roughly 5%
    under the dedicated figure, and the same number the game displays.
    (None, 0, 0) when DXGI is unavailable.
    """
    if os.name != "nt":
        return None, 0, 0
    iid_factory = _GUID("770aae78-f26f-4dba-a829-253c83d1b387")
    iid_adapter3 = _GUID("645967A4-1392-4310-A798-8053CE3E93FD")
    mb = 1024 * 1024
    best = (None, 0, 0)
    try:
        dxgi = ctypes.WinDLL("dxgi")
        factory = ctypes.c_void_p()
        if dxgi.CreateDXGIFactory1(ctypes.byref(iid_factory),
                                   ctypes.byref(factory)) != 0:
            return best
    except OSError:
        return best
    try:
        index = 0
        while True:
            adapter = ctypes.c_void_p()
            # IDXGIFactory1::EnumAdapters1 is vtable slot 12.
            if _com(factory, 12, [ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
                    ctypes.c_uint32(index), ctypes.byref(adapter)) != 0:
                break
            index += 1
            try:
                desc = _ADAPTER_DESC1()
                _com(adapter, 10, [ctypes.POINTER(_ADAPTER_DESC1)],
                     ctypes.byref(desc))                        # GetDesc1
                # Flag 2 is DXGI_ADAPTER_FLAG_SOFTWARE: the Basic Render
                # Driver reports a plausible budget and no real memory at all.
                if desc.Flags & 2:
                    continue
                dedicated = int(desc.DedicatedVideoMemory) // mb
                if dedicated <= best[1]:
                    continue
                adapter3 = ctypes.c_void_p()
                if _com(adapter, 0, [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)],
                        ctypes.byref(iid_adapter3),
                        ctypes.byref(adapter3)) != 0:           # QueryInterface
                    best = (desc.Description, dedicated, 0)
                    continue
                try:
                    info = _VIDEO_MEMORY_INFO()
                    # IDXGIAdapter3::QueryVideoMemoryInfo, slot 14.
                    # Node 0, segment 0 = DXGI_MEMORY_SEGMENT_GROUP_LOCAL.
                    if _com(adapter3, 14,
                            [ctypes.c_uint32, ctypes.c_uint32,
                             ctypes.POINTER(_VIDEO_MEMORY_INFO)],
                            ctypes.c_uint32(0), ctypes.c_uint32(0),
                            ctypes.byref(info)) == 0:
                        best = (desc.Description, dedicated, int(info.Budget) // mb)
                    else:
                        best = (desc.Description, dedicated, 0)
                finally:
                    _com(adapter3, 2, [])                       # Release
            finally:
                _com(adapter, 2, [])
    except (OSError, ValueError, AttributeError):
        pass
    finally:
        try:
            _com(factory, 2, [])
        except OSError:
            pass
    return best


def gpu_vram():
    """(name, VRAM in MB) of the card with the most memory.

    The registry reports the real usable figure, which is a little under the
    marketing number: 16303 MB on a 16 GB card, not 16384."""
    best_name, best_mb = None, 0
    if os.name == "nt":
        try:
            import winreg
            key = (r"SYSTEM\CurrentControlSet\Control\Class"
                   r"\{4d36e968-e325-11ce-bfc1-08002be10318}")
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as root:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    if not sub.isdigit():
                        continue
                    try:
                        with winreg.OpenKey(root, sub) as node:
                            try:
                                name = winreg.QueryValueEx(node, "DriverDesc")[0]
                            except OSError:
                                name = None
                            try:
                                raw = winreg.QueryValueEx(
                                    node, "HardwareInformation.qwMemorySize")[0]
                            except OSError:
                                continue
                            if isinstance(raw, bytes):
                                raw = int.from_bytes(raw[:8], "little")
                            mb = int(raw) // (1024 * 1024)
                    except OSError:
                        continue
                    if mb > best_mb:
                        best_name, best_mb = name, mb
        except (ImportError, OSError):
            pass

    if best_mb < 1024:
        try:
            import subprocess
            kwargs = {}
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                kwargs = {"startupinfo": si, "creationflags": 0x08000000}
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=20, **kwargs).stdout
            for line in out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > best_mb:
                    best_name, best_mb = parts[0], int(parts[1])
        except (OSError, ValueError):
            pass
    return best_name, best_mb


def gpu_memory():
    """(name, dedicated MB, available MB), DXGI first.

    DXGI is what the game itself queries. The registry knows only the
    dedicated size, so without DXGI the available figure falls back to 93% of
    it, measured on the one card this was calibrated against.
    """
    name, dedicated, available = dxgi_memory()
    if available:
        return name, dedicated, available
    reg_name, reg_mb = gpu_vram()
    if not reg_mb:
        return name or reg_name, dedicated, 0
    return (name or reg_name), max(dedicated, reg_mb), int(reg_mb * 0.93)


def _is_game_folder(folder):
    return bool(folder) and os.path.isfile(os.path.join(folder, "ds.exe"))


def _tidy(path):
    """Steam stores its paths with forward slashes and arbitrary casing, and
    Windows hands back whatever casing the caller used. Left alone the game
    folder prints with a lowercase drive and lowercase Program Files, which
    looks broken next to what Explorer shows. Rebuild every component from
    what the filesystem actually reports."""
    path = os.path.abspath(path)
    drive, rest = os.path.splitdrive(path)
    out = drive.upper() + os.sep
    for part in [p for p in rest.split(os.sep) if p]:
        try:
            real = next((e for e in os.listdir(out) if e.lower() == part.lower()), None)
        except OSError:
            real = None
        out = os.path.join(out, real or part)
    return out


def _steam_libraries():
    libs = []
    if os.name != "nt":
        return libs
    roots = []
    try:
        import winreg
        for hive, key in ((winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam")):
            try:
                with winreg.OpenKey(hive, key) as node:
                    for name in ("SteamPath", "InstallPath"):
                        try:
                            value = winreg.QueryValueEx(node, name)[0]
                            if value:
                                roots.append(value)
                        except OSError:
                            pass
            except OSError:
                pass
    except (ImportError, OSError):
        return libs

    for root in roots:
        libs.append(os.path.join(root, "steamapps"))
        vdf = os.path.join(root, "steamapps", "libraryfolders.vdf")
        if not os.path.isfile(vdf):
            continue
        try:
            with open(vdf, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        # Steam writes its paths with escaped backslashes, and sometimes with
        # forward slashes. Without normalising, the folder shows up on screen
        # with both separators mixed together.
        for m in re.finditer(r'"path"\s+"([^"]+)"', text):
            libs.append(os.path.join(m.group(1).replace("\\\\", "\\"), "steamapps"))
    return libs


def _epic_folders():
    if os.name != "nt":
        return
    base = os.environ.get("ProgramData")
    if not base:
        return
    man = os.path.join(base, "Epic", "EpicGamesLauncher", "Data", "Manifests")
    if not os.path.isdir(man):
        return
    for item in glob.glob(os.path.join(man, "*.item")):
        try:
            with open(item, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = re.search(r'"InstallLocation"\s*:\s*"([^"]+)"', text)
        if m:
            yield m.group(1).replace("\\\\", "\\")


def find_game():
    """Next to this script, then Steam libraries, then Epic manifests.

    The Epic branch has never been exercised on a real Epic install.
    """
    here = os.path.dirname(os.path.abspath(sys.argv[0] or __file__))
    if _is_game_folder(here):
        return _tidy(here)

    libs = _steam_libraries()
    for lib in libs:
        cand = os.path.join(lib, "common", "DEATH STRANDING DIRECTORS CUT")
        if _is_game_folder(cand):
            return _tidy(cand)
    # Only once every library has been checked by name: a renamed or relocated
    # install. This can also match the base game, which is unsupported, but
    # locate() refuses anything whose patterns do not line up, so it is safe.
    for lib in libs:
        try:
            entries = os.listdir(os.path.join(lib, "common"))
        except OSError:
            continue
        for sub in sorted(entries):
            cand = os.path.join(lib, "common", sub)
            if _is_game_folder(cand):
                return _tidy(cand)

    for folder in _epic_folders():
        if _is_game_folder(folder):
            return _tidy(folder)
        try:
            for sub in os.listdir(folder):
                cand = os.path.join(folder, sub)
                if _is_game_folder(cand):
                    return _tidy(cand)
        except OSError:
            pass
    return None


# ==========================================================================
# settings.cfg
# ==========================================================================

# Handled as bytes throughout. Decoding and re-encoding would rewrite line
# endings and mangle anything that is not clean UTF-8; the file has to come
# back byte for byte on revert.
RE_STREAM_MB = re.compile(rb'("streaming_memory_mb"\s+")(\d+)(")')


def read_cfg(folder):
    """(streaming_mb, width, height). Zeros when the file is not there yet."""
    path = os.path.join(folder, "settings.cfg")
    if not os.path.isfile(path):
        return 0, 0, 0
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return 0, 0, 0

    def num(key):
        m = re.search(b'"' + key + rb'"\s+"(\d+)"', raw)
        return int(m.group(1)) if m else 0

    return num(b"streaming_memory_mb"), num(b"rendering_width"), num(b"rendering_height")


def write_cfg(folder, mb):
    """(ok, error). Makes exactly one backup, with a fixed name, the first
    time. Dated copies piled up and quietly recorded how often the tool had
    been run."""
    cfg = os.path.join(folder, "settings.cfg")
    if not os.path.isfile(cfg):
        return False, _("settings.cfg does not exist yet")
    try:
        with open(cfg, "rb") as fh:
            raw = fh.read()
        backup = os.path.join(folder, BACKUP_CFG)
        if not os.path.isfile(backup):
            shutil.copy2(cfg, backup)
            _make_writable(backup)
        new, n = RE_STREAM_MB.subn(
            lambda m: m.group(1) + str(mb).encode("ascii") + m.group(3), raw)
        if n != 1:
            return False, _("streaming_memory_mb not found in settings.cfg")
        _write_atomic(cfg, new)
        return True, None
    except OSError as exc:
        return False, str(exc)


def restore_cfg(folder):
    """Put settings.cfg back exactly as it was. Better than writing 3072 by
    hand: that is the "High" preset value, not necessarily what this
    installation had."""
    backup = os.path.join(folder, BACKUP_CFG)
    cfg = os.path.join(folder, "settings.cfg")
    if not os.path.isfile(backup):
        return False
    try:
        _copy_atomic(backup, cfg)
        return True
    except OSError:
        return False


# ==========================================================================
# Safe file writing
# ==========================================================================

def _make_writable(path):
    """A copy drags the read-only attribute along with it, and a read-only
    backup refuses to be deleted on revert."""
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def _write_atomic(path, data):
    """Write beside the target and rename over it in one step. If anything
    fails halfway the target is untouched, never a half-written ds.exe."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        _remove_quietly(tmp)


def _copy_atomic(src, dst):
    tmp = dst + ".tmp"
    try:
        shutil.copy2(src, tmp)
        _make_writable(tmp)
        os.replace(tmp, dst)
    finally:
        _remove_quietly(tmp)


def _remove_quietly(path):
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def remove_traces(folder, log):
    """Leave the machine as we found it. Returns how many files went away."""
    n = 0
    targets = [os.path.join(folder, BACKUP_EXE), os.path.join(folder, BACKUP_CFG)]
    # Dated cfg copies left behind by earlier versions of this tool.
    targets += sorted(glob.glob(os.path.join(folder, "settings.cfg.*.bak")))
    for path in targets:
        if not os.path.isfile(path):
            continue
        try:
            _make_writable(path)
            os.remove(path)
            log.append(_("Deleted: ") + os.path.basename(path))
            n += 1
        except OSError as exc:
            log.append(_("Could not delete %s: %s") % (os.path.basename(path), exc))
    return n


# ==========================================================================
# Actions
# ==========================================================================

def _guard(fn, log):
    """Turn disk failures into messages. Without this, a game folder without
    write permission (the normal case under Program Files, and typical of
    Epic installs) just crashed the script."""
    try:
        return fn()
    except PermissionError:
        log.append(_("Windows will not let me write to the game folder."))
        log.append(_("Close this and run it again from an Administrator terminal."))
        log.append(_("That is normal when the game lives under Program Files (Epic, for example)."))
        return False
    except OSError as exc:
        log.append(_("Could not write the file: %s") % exc)
        log.append(_("If you run an antivirus, it may be blocking it."))
        return False


def do_apply(folder, mb, vram_mb, bias=0.0, log=None, screen=None, arena_mb=None):
    log = log if log is not None else []
    return _guard(lambda: _apply_inner(folder, mb, vram_mb, bias, log, screen,
                                       arena_mb), log), log


def _apply_inner(folder, mb, vram_mb, bias, log, screen=None, arena_mb=None):
    exe = os.path.join(folder, "ds.exe")
    backup = os.path.join(folder, BACKUP_EXE)

    if game_running(exe):
        log.append(_("The game is running. Close it and try again."))
        return False

    state, reason, pe, sites = read_state(exe)

    # The frame arena is a separate patch on a separate field. Restoring from
    # the backup below wipes it, so whatever is set now has to be carried
    # across unless this run is changing it on purpose.
    had_arena = arena_from_exe(pe.data) if pe is not None else None
    if arena_mb is None and had_arena not in (None, STOCK_ARENA_MB):
        arena_mb = had_arena
        log.append(_("Keeping the frame arena at %d MB.") % had_arena)

    if state == PATCHED:
        if not os.path.isfile(backup):
            log.append(_("Already patched, and I cannot find the backup."))
            log.append(_("Use 'Verify integrity of game files' in Steam, then run this again."))
            return False
        _copy_atomic(backup, exe)
        log.append(_("Already patched: starting again from %s.") % BACKUP_EXE)
        state, reason, pe, sites = read_state(exe)

    if state != VANILLA:
        log.append(_("I do not recognise this ds.exe (%s).") % (reason or state))
        log.append(_("It may be a game version this tool does not support yet."))
        return False

    current_md5 = md5_file(exe)
    # A file whose only difference is an arena we enlarged ourselves is still
    # the build this was measured on, so put the stock size back before
    # comparing. Otherwise every arena user gets a false "unknown build".
    as_stock = bytearray(pe.data)
    _aoff, _aerr = arena_site(as_stock)
    if _aerr is None:
        as_stock[_aoff:_aoff + 4] = struct.pack("<I", STOCK_ARENA_MB * 1024 * 1024)
    if md5_bytes(bytes(as_stock)) != KNOWN_VANILLA_MD5:
        log.append(_("NOTE: this is not the build this patch was measured on."))
        log.append(_("  found    %s") % current_md5)
        log.append(_("  measured %s  (%s)") % (KNOWN_VANILLA_MD5, KNOWN_BUILD))
        log.append(_("  Every site was still found by signature, so the patch applies,"))
        log.append(_("  but nobody has measured the result on this build."))

    edits, err = plan(pe, sites, mb, vram_mb, bias, arena_mb)
    if err:
        log.append(err)
        return False

    if not os.path.isfile(backup):
        _copy_atomic(exe, backup)
        # A truncated backup is worse than no backup: revert would copy it over
        # ds.exe, both hashes would agree, and it would then be deleted.
        backup_md5 = md5_file(backup)
        if backup_md5 != current_md5:
            _remove_quietly(backup)
            log.append(_("Could not make a reliable backup. Leaving ds.exe alone."))
            return False
        log.append(_("  [ OK ]  Backup made of ds.exe"))
    else:
        log.append(_("  [ OK ]  Backup already there, left alone"))

    with open(exe, "rb") as fh:
        data = fh.read()
    patched, err = apply_edits(data, edits)
    if err:
        log.append(err)
        return False
    _write_atomic(exe, patched)

    log.append(_("  [ OK ]  ds.exe patched in %d places") % len(edits))

    ok, err = write_cfg(folder, mb)
    if ok:
        log.append(_("  [ OK ]  settings.cfg set to %d MB") % mb)
    else:
        log.append("WARNING: " + (err or _("could not write settings.cfg")))
        log.append(_("  Start the game once, set Texture Streaming to High, quit, and re-run this."))

    divisor = mip_divisor(mb, bias)
    level = int(mip_bias_of(mb, divisor))
    rule = "  " + "=" * 64
    log.append("")
    log.append(rule)
    log.append(_("   DONE"))
    log.append(_("   Textures       %d MB   (%.1f times the stock %d MB)")
               % (mb, mb / float(STOCK_BUDGET_MB), STOCK_BUDGET_MB))
    if screen:
        log.append(_("   In the game    %s") % screen)
    if arena_mb is not None and arena_mb != STOCK_ARENA_MB:
        log.append(_("   Frame arena    %d MB   (stock %d MB, costs that much RAM)")
                   % (arena_mb, STOCK_ARENA_MB))
    log.append(rule)
    # Silent when it is right. This is the one that ruins textures when it is
    # wrong, and saying "level 0" every single time teaches people to skip it.
    if level != 0:
        log.append("")
        log.append(_("   WARNING: mip level %d. Textures will look WORSE than stock.")
                   % level)
        log.append(_("   Run apply again; something did not take."))
    log.append("")
    log.append(_("   NOW    Open the game and load a save."))
    log.append("")
    log.append(_("   THEN   Come back here for \"Read the real budget\", to see how"))
    log.append(_("          much the engine actually handed out."))
    return True


def do_arena(folder, arena_mb, log=None):
    log = log if log is not None else []
    return _guard(lambda: _arena_inner(folder, arena_mb, log), log), log


def _arena_inner(folder, arena_mb, log):
    """Resize the per-frame arena on its own.

    Deliberately not routed through apply: this touches four bytes of a field
    the streaming patch never reads or writes, so it must work on a stock
    ds.exe and on a patched one alike, and leave whatever it finds alone.
    """
    exe = os.path.join(folder, "ds.exe")
    backup = os.path.join(folder, BACKUP_EXE)

    bad = check_arena(arena_mb)
    if bad:
        log.append(bad)
        return False
    if game_running(exe):
        log.append(_("The game is running. Close it and try again."))
        return False
    if not os.path.isfile(exe):
        log.append(_("There is no ds.exe in %s") % folder)
        return False

    with open(exe, "rb") as fh:
        data = fh.read()
    off, err = arena_site(data)
    at = find_unique(data, _h(TEMPLATE_ANCHOR))
    if err or at is None:
        log.append(err or _("cannot find (or found more than one) the memory template"))
        log.append(_("Either this is a game version this tool does not know, or"))
        log.append(_("something else has already modified ds.exe."))
        return False
    tpl_off = at + 0x20

    ctor_now, tpl_now = arena_pair(data)
    if ctor_now == arena_mb and tpl_now == arena_mb:
        log.append(_("The frame arena is already %d MB. Nothing to do.") % arena_mb)
        return True

    # Same contract as apply: a verified backup exists before anything is
    # written, because this is the file the game needs to start.
    if not os.path.isfile(backup):
        _copy_atomic(exe, backup)
        if md5_file(backup) != md5_file(exe):
            _remove_quietly(backup)
            log.append(_("Could not make a reliable backup. Leaving ds.exe alone."))
            return False
        log.append(_("  [ OK ]  Backup made of ds.exe"))

    edits = [
        Edit(off, data[off:off + 4], struct.pack("<I", arena_mb * 1024 * 1024),
             _("per-frame arena size")),
        Edit(tpl_off, data[tpl_off:tpl_off + 8],
             struct.pack("<Q", arena_mb * 1024 * 1024),
             _("per-frame arena (template)")),
    ]
    patched, err = apply_edits(data, edits)
    if err:
        log.append(err)
        return False
    _write_atomic(exe, patched)

    log.append(_("  [ OK ]  Frame arena %d MB -> %d MB")
               % (tpl_now if tpl_now is not None else STOCK_ARENA_MB, arena_mb))
    log.append("")
    if arena_mb == STOCK_ARENA_MB:
        log.append(_("   Back to the stock size. The streaming patch, if you have"))
        log.append(_("   one, is untouched."))
        return True
    log.append(_("   That costs %d MB more system RAM, and nothing else.")
               % (arena_mb - STOCK_ARENA_MB))
    log.append("")
    log.append(_("   Measured in a running game: the engine really does build"))
    log.append(_("   the arena at this size, and the capacity it reports moves"))
    log.append(_("   with it."))
    return True


def do_revert(folder, log=None):
    log = log if log is not None else []
    return _guard(lambda: _revert_inner(folder, log), log), log


def _revert_inner(folder, log):
    exe = os.path.join(folder, "ds.exe")
    backup = os.path.join(folder, BACKUP_EXE)

    if game_running(exe):
        log.append(_("The game is running. Close it first."))
        return False
    if not os.path.isfile(backup):
        log.append(_("There is no backup to restore from."))
        log.append(_("Use 'Verify integrity of game files' in Steam to get a clean ds.exe."))
        return False

    # Check the backup really is an unpatched ds.exe BEFORE restoring it.
    # Restoring a bad backup and then deleting it would leave the game broken
    # with nothing left to recover from.
    state, reason, _pe, _sites = read_state(backup)
    if state != VANILLA:
        log.append(_("The backup is not a recognisable original ds.exe. Touching nothing."))
        if reason:
            log.append("  " + reason)
        log.append(_("Use 'Verify integrity of game files' in Steam."))
        return False

    _copy_atomic(backup, exe)
    log.append(_("ds.exe restored from %s") % BACKUP_EXE)

    # The backup only goes away once the restored file matches it. If the copy
    # went wrong, the backup is the only thing saving this installation.
    h_exe, h_backup = md5_file(exe), md5_file(backup)
    if h_exe != h_backup:
        log.append(_("The restored file does not match the backup. Deleting nothing."))
        log.append(_("  ds.exe          %s") % h_exe)
        log.append("  %s %s" % (BACKUP_EXE, h_backup))
        return False
    log.append(_("MD5 verified:   %s") % h_exe)

    if restore_cfg(folder):
        log.append(_("settings.cfg returned to its original contents"))
    else:
        ok, _err = write_cfg(folder, 3072)
        if ok:
            log.append(_("settings.cfg    streaming_memory_mb = 3072 (stock 'High' value)"))

    # Cleaned up last: write_cfg above may have just created a fresh backup.
    n = remove_traces(folder, log)
    log.append(_("No trace left: %d file(s) removed. You can delete this script now.") % n
               if n else _("Nothing left to clean up."))
    return True


STOCK_BUDGET_MB = 3072
STOCK_VRAM_MB = 6144


def _check(log, ok, label, value="", *notes):
    log.append("  %-7s %-34s %s" % ("OK" if ok else "PROBLEM", label, value))
    for note in notes:
        log.append("          " + note)


def do_verify(folder, log=None, detail=False, hint=True):
    """Report whether the patch is in and healthy.

    With the backup present it doubles as the map: locate() on the pristine
    file yields the offsets, which are then read out of the patched one. No
    address is hardcoded.
    """
    log = log if log is not None else []
    exe = os.path.join(folder, "ds.exe")
    me = os.path.basename(sys.argv[0])
    if not os.path.isfile(exe):
        log.append(_("There is no ds.exe in %s") % folder)
        return False, log

    state, reason, pe, _sites = read_state(exe)
    cfg_mb, width, height = read_cfg(folder)
    backup = os.path.join(folder, BACKUP_EXE)

    if state == VANILLA:
        # The frame arena lives on a field the streaming sites never touch, so
        # it can be raised on a file that is otherwise completely stock.
        # Calling that "the stock ds.exe" would deny a change that is there.
        arena = arena_from_exe(pe.data) if pe is not None else None
        if arena not in (None, STOCK_ARENA_MB):
            log.append(_("Streaming NOT patched, but the frame arena IS raised."))
            log.append(_("Frame arena: %d MB, up from the stock %d MB.")
                       % (arena, STOCK_ARENA_MB))
            log.append("")
        else:
            log.append(_("NOT PATCHED. This is the stock ds.exe."))
        log.append(_("Texture streaming is capped at %d MB.") % STOCK_BUDGET_MB)
        log.append("")
        log.append(_("To patch it, with the game closed:"))
        log.append(_("  python %s apply") % me)
        log.append("")
        log.append(_("If you had patched it before, Steam's 'Verify integrity of game"))
        log.append(_("files' undoes it silently. That is almost always what happened."))
        _verify_detail(log, exe, state, cfg_mb, width, height, detail, hint=hint)
        return False, log

    if state == UNKNOWN:
        log.append(_("UNRECOGNISED ds.exe. I will not touch it."))
        if reason:
            log.append("  %s" % reason)
        log.append("")
        log.append(_("Either this is a game version newer than this tool, or something"))
        log.append(_("else has already modified ds.exe. Use Steam's 'Verify integrity"))
        log.append(_("of game files' to get a clean one."))
        _verify_detail(log, exe, state, cfg_mb, width, height, detail, hint=hint)
        return False, log

    # --- patched -----------------------------------------------------------
    if not os.path.isfile(backup):
        assumed = vram_from_exe(pe) if pe else None
        log.append(_("PATCHED, but %s is missing.") % BACKUP_EXE)
        log.append("")
        log.append(_("Without the backup I cannot check every field, and 'revert' has"))
        log.append(_("nothing to restore from. Assumed VRAM reads as %s MB.")
                   % (assumed if assumed is not None else "?"))
        log.append(_("Use Steam's 'Verify integrity of game files' to get back to stock."))
        _verify_detail(log, exe, state, cfg_mb, width, height, detail, hint=hint)
        return True, log

    bstate, _r, _bpe, bsites = read_state(backup)
    if bstate != VANILLA or pe is None:
        log.append(_("PATCHED, but %s is not a recognisable stock ds.exe.") % BACKUP_EXE)
        log.append(_("'revert' will refuse to use it. Verify your game files in Steam."))
        _verify_detail(log, exe, state, cfg_mb, width, height, detail, hint=hint)
        return True, log

    values = _installed_values(pe, bsites)
    budget = values["budgets"][0]
    problems, body = _verify_checks(values, cfg_mb, me)

    if problems:
        log.append(_("PATCHED, but something is off: %s.") % ", ".join(problems))
    else:
        log.append(_("PATCHED and healthy."))
        log.append(_("Texture streaming budget: %d MB, %.1fx the stock %d MB.")
                   % (budget, budget / float(STOCK_BUDGET_MB), STOCK_BUDGET_MB))
    log.append("")
    log.extend(body)
    if not problems:
        log.append("")
        log.append(_("Nothing to do. Load a save, then run this to see what the engine"))
        log.append(_("really handed out:  python %s measure") % me)
    _verify_detail(log, exe, state, cfg_mb, width, height, detail,
                   divisor=values["divisor"], bias=values["bias"], hint=hint)
    return True, log


def _installed_values(pe, bsites):
    """Every patched field read back, using the backup's offsets as the map."""
    d = pe.data

    def u32(key):
        return struct.unpack_from("<I", d, bsites[key][0])[0]

    def u64mb(key):
        return struct.unpack_from("<Q", d, bsites[key][0])[0] // (1024 * 1024)

    budgets = [u32(k) for k in
               ("preset_high", "preset_write", "preset_menu", "preset_match")]
    divisor = struct.unpack_from("<f", d, bsites["mip_divisor"][0])[0]
    return {"budgets": budgets,
            "ceiling": u32("setter_ceiling"),
            "vrams": [u64mb("vram_code"), u64mb("vram_template")],
            "divisor": divisor,
            "bias": mip_bias_of(budgets[0], divisor),
            "arena": u64mb("arena_template"),
            "arena_ctor": u32("arena_size") // (1024 * 1024),
            "detour_ok": d[bsites["detour"][0]] == 0xE9}


def _verify_checks(values, cfg_mb, me):
    """(problems, lines), one entry per site. Each failure carries its fix."""
    problems, body = [], []
    budgets, budget = values["budgets"], values["budgets"][0]
    ceiling, vrams = values["ceiling"], values["vrams"]
    level = int(values["bias"])

    agree = len(set(budgets)) == 1
    _check(body, agree, _("budget set in all 4 places"),
           "%d MB" % budget if agree else _("they disagree: %s") % budgets)
    if not agree:
        problems.append(_("the four preset sites do not match"))

    if cfg_mb == budget:
        _check(body, True, _("settings.cfg agrees"), "%d MB" % cfg_mb)
    else:
        _check(body, False, _("settings.cfg says"), "%s MB" % (cfg_mb or "nothing"),
               _("The exe is still patched, so the game will keep asking for"),
               _("what the exe says. Put the two back in step with:"),
               _("  python %s apply --mb %d") % (me, budget))
        problems.append(_("settings.cfg was reset"))

    _check(body, ceiling > budget, _("setter clamp above the budget"), "%d MB" % ceiling)
    if ceiling <= budget:
        problems.append(_("the clamp would cut the budget"))

    vram_ok = len(set(vrams)) == 1 and vrams[0] > STOCK_VRAM_MB
    _check(body, vram_ok, _("assumed VRAM raised from %d MB") % STOCK_VRAM_MB,
           "%d MB" % vrams[0] if len(set(vrams)) == 1
           else _("code %d / template %d") % tuple(vrams))
    if not vram_ok:
        problems.append(_("the assumed VRAM is not raised in both places"))

    if level == 0:
        _check(body, True, _("mip bias neutral"), _("level 0  <- the important one"))
    else:
        _check(body, False, _("mip bias"), _("level %d") % level,
               _("A negative level forces finer mips on everything, which makes"),
               _("textures look WORSE than stock. Re-run apply to fix the divisor:"),
               _("  python %s apply") % me)
        problems.append(_("the mip bias is not neutral"))

    _check(body, values["detour_ok"], _("64-bit conversion detour in place"),
           _("yes") if values["detour_ok"] else _("missing"))
    if not values["detour_ok"]:
        problems.append(_("the detour is missing"))

    # A separate, optional patch: stock is a perfectly fine state, so neither
    # value is ever a problem. Reported because it is invisible otherwise.
    arena, arena_ctor = values["arena"], values["arena_ctor"]
    if arena != arena_ctor:
        # Only reachable from a half-applied patch: the two writers must
        # agree or the template silently wins and the other value is a lie.
        _check(body, False, _("frame arena"),
               _("constructor %d MB, template %d MB") % (arena_ctor, arena),
               _("Those must match. Re-run:  python %s arena --mb %d") % (me, arena))
        problems.append(_("the two frame arena writers disagree"))
    else:
        _check(body, True, _("frame arena"),
               _("%d MB (stock)") % arena if arena == STOCK_ARENA_MB
               else _("%d MB, raised from %d MB") % (arena, STOCK_ARENA_MB))
    return problems, body


def _verify_detail(log, exe, state, cfg_mb, width, height, detail,
                   divisor=None, bias=None, hint=True):
    if not detail:
        if not hint:
            return
        log.append("")
        log.append(_("(for the raw offsets and hashes:  python %s verify --detail)")
                   % os.path.basename(sys.argv[0]))
        return
    log.append("")
    log.append(_("  ds.exe        %s") % exe)
    log.append("  MD5           %s" % md5_file(exe))
    log.append(_("  state         %s") % state)
    log.append(_("  settings.cfg  streaming_memory_mb = %s") % (cfg_mb or _("not set")))
    if width and height:
        log.append(_("                rendering %dx%d") % (width, height))
    if divisor is not None:
        log.append(_("  mip divisor   %.1f  ->  bias %.3f  ->  level %d")
                   % (divisor, bias, int(bias)))


# ==========================================================================
# Reading the real budget out of the running game
# ==========================================================================
#
# ReadProcessMemory only: nothing injected, nothing installed. These offsets
# are not pattern-matched and belong to build dsq 179/4027081 alone.
#
#   engine  = *(void**)(base + 0x4F6D430)
#   budget  = *(uint64*)(engine + 0x2CD28 + 0x10)   bytes, the actual proof
#   request =  (uint32 )(engine + 0x5BA694)         MB, what the setter wrote

ENGINE_PTR_RVA = 0x4F6D430
FIELD_REQUEST_MB = 0x5BA694
FIELD_POOL = 0x2CD28
FIELD_POOL_BUDGET = 0x10


class _MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("th32ModuleID", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32), ("GlblcntUsage", ctypes.c_uint32),
                ("ProccntUsage", ctypes.c_uint32),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", ctypes.c_uint32), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]


def _module_base(pid, name=b"ds.exe"):
    k32 = _k32()
    for _ in range(12):  # the snapshot fails while the process is still starting
        snap = k32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid)
        if snap != -1:
            entry = _MODULEENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            ok = k32.Module32First(snap, ctypes.byref(entry))
            while ok:
                if entry.szModule.lower() == name:
                    base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
                    k32.CloseHandle(snap)
                    return base
                ok = k32.Module32Next(snap, ctypes.byref(entry))
            k32.CloseHandle(snap)
        time.sleep(0.5)
    return None


def _snapshot():
    """(pid, base, engine, request_mb, budget_bytes) or None."""
    pids = _pids_named()
    if not pids:
        return None
    pid = pids[0]
    base = _module_base(pid)
    if not base:
        return None
    k32 = _k32()
    handle = k32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not handle:
        return None
    try:
        def read(addr, n):
            buf = (ctypes.c_ubyte * n)()
            got = ctypes.c_size_t(0)
            if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, n,
                                         ctypes.byref(got)):
                return None
            return bytes(buf[:got.value])

        raw = read(base + ENGINE_PTR_RVA, 8)
        if not raw:
            return None
        engine = int.from_bytes(raw, "little")
        if not engine:
            return None
        raw_mb = read(engine + FIELD_REQUEST_MB, 4)
        raw_budget = read(engine + FIELD_POOL + FIELD_POOL_BUDGET, 8)
        if not raw_mb or not raw_budget:
            return None
        budget = int.from_bytes(raw_budget, "little")
        if not budget:
            return None
        return pid, base, engine, int.from_bytes(raw_mb, "little"), budget
    finally:
        k32.CloseHandle(handle)


def do_measure(wait_minutes=0):
    wait_minutes = max(0, wait_minutes)
    if os.name != "nt":
        print(_("measure only works on Windows."))
        return 1
    if wait_minutes:
        print(_("Watching for up to %d minutes. Start the game and LOAD A SAVE.") % wait_minutes)
        print(_("(in the main menu the streaming pool is not initialised yet)"))
        sys.stdout.flush()
        deadline = time.time() + wait_minutes * 60
        seen = False
        while time.time() < deadline:
            shot = _snapshot()
            if shot:
                _report_measure(shot)
                return 0
            if _pids_named() and not seen:
                seen = True
                print(_("ds.exe found, waiting for the streaming pool to come up..."))
                sys.stdout.flush()
            time.sleep(3)
        print(_("Timed out without a reading. The pool never initialised."))
        return 1

    shot = _snapshot()
    if not shot:
        print(_("ds.exe is not running, or has not initialised yet."))
        print(_("Start the game, load a save, and run this again, or use --wait 20."))
        print(_("If the game IS running, try an Administrator terminal."))
        return 1
    _report_measure(shot)
    return 0


def _report_measure(shot):
    pid, base, engine, request_mb, budget = shot
    mb = 1024 * 1024
    print("=" * 68)
    print(_("ds.exe  PID %d   base 0x%X   (ASLR slide 0x%X)") % (pid, base, base - 0x140000000))
    print(_("engine object                    = 0x%X") % engine)
    print(_("streaming_memory_mb field        = %d MB") % request_mb)
    print(_("EFFECTIVE BUDGET (pool+0x10)     = %d bytes = %.0f MB") % (budget, budget / mb))
    print("=" * 68)
    if budget >= request_mb * mb * 0.98:
        print(_("Working. The engine took the full %.0f MB.") % (budget / mb))
    elif request_mb >= 8192:
        print(_("The patch is in: the field says %d MB, so the clamps are open.") % request_mb)
        print(_("But the pool only took %.0f MB, which means the available-memory")
              % (budget / mb))
        print(_("limit is what is cutting it now, not the patch."))
        print(_("Size your mod against %.0f MB, not %d.") % (budget / mb, request_mb))
    else:
        print(_("The field is only %d MB: part of the patch is not applied.") % request_mb)
        print(_("Run:  python %s verify") % os.path.basename(sys.argv[0]))


# ==========================================================================
# Command line
# ==========================================================================

def clean_folder(raw):
    """A game folder out of whatever the user typed, or None.

    Dragging a folder onto a console pastes it in quotes, people reasonably
    point at ds.exe itself rather than the folder holding it, and some will
    pick the Steam library instead of the game inside it. All three work.
    """
    path = raw.strip().strip('"').strip("'").strip()
    if not path:
        return None
    path = path.rstrip("\\/") or path
    if os.path.isfile(path) and os.path.basename(path).lower() == "ds.exe":
        path = os.path.dirname(path)
    if _is_game_folder(path):
        return _tidy(path)
    try:
        for sub in sorted(os.listdir(path)):
            candidate = os.path.join(path, sub)
            if _is_game_folder(candidate):
                return _tidy(candidate)
    except OSError:
        pass
    return None


def ask_for_folder():
    """Autodetection missed, so let them point at it. Interactive runs only:
    a dead end is no use to someone who never opened a terminal."""
    print()
    print(_("I could not find the game on this machine."))
    print(_("Find the folder that holds ds.exe and drag it onto this window,"))
    print(_("or paste the path. Press Enter on its own to quit."))
    while True:
        raw = _ask(_("Game folder: "))
        if not raw:
            return None
        folder = clean_folder(raw)
        if folder:
            print(_("Found it: %s") % folder)
            return folder
        print(_("No ds.exe in there, and none in the folders inside it."))


def resolve_folder(args, log):
    folder = args.game or find_game()
    if not folder and _interactive():
        folder = ask_for_folder()
    if not folder:
        log.append(_("Could not find Death Stranding Director's Cut."))
        log.append(_("Pass the folder explicitly, for example:"))
        log.append(_("  --game \"...\\steamapps\\common\\DEATH STRANDING DIRECTORS CUT\""))
        log.append(_("Or drop this script into the game folder and run it there."))
        return None
    folder = _tidy(folder)
    if not _is_game_folder(folder):
        log.append(_("No ds.exe in %s") % folder)
        return None
    return folder


def _rule(title=""):
    print()
    print(title)
    print("-" * 68)


def cmd_status(args):
    log = []
    me = os.path.basename(sys.argv[0])
    print(_("DSDC Streaming Memory Unlock %s") % VERSION)
    print("=" * 68)

    name, dedicated, available = gpu_memory()
    folder = resolve_folder(args, log)
    cfg_mb, width, height = read_cfg(folder) if folder else (0, 0, 0)

    print(_("  Graphics card   %s") % (name or _("could not detect")))
    if dedicated or available:
        print(_("  Video memory    %d MB on the card, %d MB Windows lets a game use")
              % (dedicated, available))
    else:
        print(_("  Video memory    not detected. Pass --vram yourself"))
    if folder:
        print(_("  Game folder     %s") % folder)
    if width and height:
        print(_("  Resolution      %d x %d") % (width, height))

    if not folder:
        print()
        for line in log:
            print(line)
        return 1

    _rule(_("STATUS"))
    _ok, vlog = do_verify(folder, [], hint=False)
    for line in vlog:
        print(line)

    # The menu lists the same verbs, so show one or the other, never both.
    if _interactive():
        return _menu(folder, dedicated, available, width, height)

    _rule(_("COMMANDS"))
    rows = [("apply", _("patch the game, sized from your card")),
            ("verify", _("check what is actually installed")),
            ("measure", _("read the real budget out of the running game")),
            ("fit", _("match the two figures in the game's own menu")),
            ("arena", _("resize the per-frame arena (advanced)")),
            ("revert", _("undo everything, leave no trace"))]
    for cmd, what in rows:
        print(_("  python %s %-9s %s") % (me, cmd, what))
    print()
    print(_("  Add --help to any of them for its options."))
    print()
    print(_("  Unofficial and unaffiliated with Kojima Productions, 505 Games or"))
    print(_("  Sony. It patches your own ds.exe and redistributes nothing."))

    if available:
        mb = recommend(available, width, height)
        print()
        print(_("  'apply' with no arguments would ask for %d MB on this machine.") % mb)
        print(_("  That is sized so the game's menu reports a requirement that fits"))
        print(_("  inside the %d MB it has available.") % available)

    return 0


def cmd_fit(args):
    """Take the two figures off the game's own options screen and say what
    budget makes them meet. Exact, because the screen already did the
    arithmetic: whatever the render targets really cost, that cost is in
    both terms and cancels out."""
    log = []
    folder = resolve_folder(args, log)
    if not folder:
        for line in log:
            print(line)
        return 1
    me = os.path.basename(sys.argv[0])
    cfg_mb, _w, _h = read_cfg(folder)
    current = args.current or cfg_mb
    if not current:
        print(_("I need the budget those two figures were taken at."))
        print(_("Pass it with --current, for example:  --current 15360"))
        return 2

    slack_gb = args.available - args.required
    print(_("Your options screen reads:"))
    print(_("  required   %.1f GB") % args.required)
    print(_("  available  %.1f GB") % args.available)
    print(_("with the streaming budget at %d MB.") % current)
    print()
    if abs(slack_gb) < 0.05:
        print(_("Those already match, within what one decimal place can show."))
        print(_("Nothing to change."))
        return 0

    new_mb = fit_budget(current, args.required, args.available)
    print(_("It is %s by %.1f GB, about %d MB.")
          % ("over" if slack_gb < 0 else "under", abs(slack_gb),
             abs(int(slack_gb * 1024))))
    print()
    print(_("Set the budget to %d MB and the two figures should meet:") % new_mb)
    print(_("  python %s apply --mb %d") % (me, new_mb))
    print()
    print(_("The screen only shows one decimal, so this lands within about"))
    print(_("50 MB, under the 128 MB the engine rounds to anyway."))
    return 0


def cmd_apply(args):
    log = []

    # Offline mode: build from one file to another, touching no installation.
    if args.source or args.out:
        if not (args.source and args.out):
            print(_("--from and --out must be used together."))
            return 2
        if args.mb is None or args.vram is None:
            print(_("--from/--out need explicit --mb and --vram."))
            return 2
        bad = check_values(args.mb, args.vram, args.mipbias, args.arena)
        if bad:
            print(bad)
            return 2
        try:
            with open(args.source, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(_("Cannot read %s: %s") % (args.source, exc))
            return 1
        patched, edits, err = build(data, args.mb, args.vram, args.mipbias, args.arena)
        if err:
            print(err)
            return 1
        if args.dry_run:
            _print_edits(edits)
            return 0
        _write_atomic(args.out, patched)
        print("%s  ->  %s" % (args.source, args.out))
        print(_("MD5 %s   (%d sites)") % (md5_bytes(patched), len(edits)))
        return 0

    folder = resolve_folder(args, log)
    if not folder:
        for line in log:
            print(line)
        return 1

    _name, dedicated, available = gpu_memory()
    _cfg_mb, width, height = read_cfg(folder)

    # Two different figures on purpose. The clamp we write into the engine is
    # the size of the card, because the engine takes min(real, that) and a
    # bigger number simply loses the min. The budget is sized against what
    # Windows actually makes available, because that is the number the game's
    # own options screen checks against.
    vram = args.vram
    if vram is None:
        vram = nominal_vram_mb(dedicated) or available
        if not vram:
            print(_("Could not detect your card. Pass the numbers yourself, for"))
            print(_("example:  --vram 16303 --mb 14080"))
            return 2
    if args.mb is not None:
        mb = args.mb
    else:
        mb = recommend(available or vram, width, height)

    bad = check_values(mb, vram, args.mipbias, args.arena)
    if bad:
        print(bad)
        return 2

    if mb < STOCK_BUDGET_MB:
        print(_("NOTE: %d MB is BELOW the stock %d MB. That makes things worse,")
              % (mb, STOCK_BUDGET_MB))
        print(_("      not better, and at the 1536 MB floor the mip bias goes to +1."))

    if mb % 128:
        print(_("NOTE: %d MB is not a multiple of 128. The engine rounds down, so you")
              % mb)
        print(_("      would actually get %d MB. Using %d instead.") % (r128(mb), r128(mb)))
        mb = r128(mb)

    if args.dry_run:
        exe = os.path.join(folder, "ds.exe")
        state, reason, pe, sites = read_state(exe)
        if state != VANILLA:
            print(_("ds.exe is %s%s. Nothing to preview.")
                  % (state, " (%s)" % reason if reason else ""))
            return 1
        edits, err = plan(pe, sites, mb, vram, args.mipbias, args.arena)
        if err:
            print(err)
            return 1
        print(_("Dry run: %d MB budget, %d MB assumed VRAM. Nothing written.\n") % (mb, vram))
        _print_edits(edits)
        return 0

    ok, log = do_apply(folder, mb, vram, args.mipbias, log,
                       screen=screen_reading(mb, available, width, height),
                       arena_mb=arena_to_use(folder, args.arena))
    for line in log:
        print(line)
    if ok:
        print()
        print(_("   NOTE   Verifying game files in Steam silently undoes this."))
    return 0 if ok else 1


# Labels rather than a disassembler: the bytes are fixed and known, so naming
# them costs nothing and keeps the script dependency-free.
INSTRUCTION_LABELS = {
    "480f48d048c1e314": _("cmovs rdx,rax / shl rbx,0x14"),
    "480f48d0c1e314": _("cmovs rdx,rax / shl ebx,0x14   <- 32-bit, the bug"),
}


def _print_edits(edits):
    def short(raw):
        text = raw.hex(" ")
        return text if len(text) <= 23 else text[:20] + "..."

    print("  %-30s %-10s %-24s %s" % (_("site"), _("file off"), _("old"), _("new")))
    notes = []
    for e in edits:
        print("  %-30s 0x%08X %-24s %s"
              % (_(e.desc), e.off, short(e.old), short(e.new)))
        for label, raw in (("old", e.old), ("new", e.new)):
            text = INSTRUCTION_LABELS.get(raw[:8].hex())
            if text:
                notes.append("    %s %s: %s" % (e.desc, label, text))
    total = sum(1 for e in edits for a, b in zip(e.old, e.new) if a != b)
    print(_("\n  %d sites, %d bytes changed") % (len(edits), total))
    if notes:
        print()
        for line in notes:
            print(line)


def cmd_revert(args):
    log = []
    folder = resolve_folder(args, log)
    if not folder:
        for line in log:
            print(line)
        return 1
    ok, log = do_revert(folder, log)
    for line in log:
        print(line)
    return 0 if ok else 1


def cmd_arena(args):
    log = []
    # Checked here so a bad --mb exits 2 like every other bad argument, and
    # again inside do_arena so the menu and any other caller are covered too.
    bad = check_arena(args.mb)
    if bad:
        print(bad)
        return 2
    folder = resolve_folder(args, log)
    if not folder:
        for line in log:
            print(line)
        return 1
    ok, log = do_arena(folder, args.mb, log)
    for line in log:
        print(line)
    return 0 if ok else 1


def cmd_verify(args):
    log = []
    folder = resolve_folder(args, log)
    if not folder:
        for line in log:
            print(line)
        return 1
    ok, log = do_verify(folder, [], detail=args.detail)
    for line in log:
        print(line)
    return 0 if ok else 1


def cmd_measure(args):
    return do_measure(args.wait)


# Set by --interactive. RUN_ME.cmd always passes it.
_INTERACTIVE = False


def _double_clicked():
    """Whether Windows made this console just for us. A weak guess.

    Measured in fresh consoles: python counts 1, py -3 counts 2, a .cmd
    launcher counts 2. A default install registers .py to py.exe, which stays
    attached, so a real double-click usually counts 2. --interactive is the
    reliable signal; this covers the case where python.exe is the handler.
    """
    if os.name != "nt":
        return False
    try:
        if not sys.stdout.isatty():
            return False
        k32 = _k32()
        k32.GetConsoleProcessList.argtypes = [ctypes.POINTER(ctypes.c_uint32),
                                              ctypes.c_uint32]
        buf = (ctypes.c_uint32 * 4)()
        return 0 < k32.GetConsoleProcessList(buf, 4) <= 1
    except (OSError, AttributeError, ValueError):
        return False


def _interactive():
    """Whether to show the menu and hold the window open.

    --interactive wins outright. Second-guessing it with isatty() is what made
    this unreliable before, so that guard applies only to the weak
    double-click guess, keeping a redirected run from blocking on input.
    """
    if _INTERACTIVE:
        return True
    if not _double_clicked():
        return False
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(prompt):
    """input() that treats a closed stdin as 'quit' rather than crashing."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _confirm(plan):
    """Print what is about to happen, then require an explicit y.
    Anything else, a bare Enter included, means no."""
    print()
    for line in plan:
        print("  " + line)
    print()
    return _ask(_("Press [y] to go ahead, anything else to cancel: ")).lower() == "y"


def arena_to_use(folder, asked=None):
    """The arena size a plain 'apply' should write.

    Patching is one action from the user's side, so apply covers both fields
    rather than leaving the arena as a second errand. `asked` wins when it is
    given (including the stock size, which is how you decline); otherwise a
    size already chosen is kept, so re-running never quietly shrinks it.

    This lives at the command layer on purpose. plan() and build() keep None
    meaning "do not touch this field", which is what the pinned MD5s rely on.
    """
    if asked is not None:
        return asked
    try:
        with open(os.path.join(folder, "ds.exe"), "rb") as fh:
            current = arena_from_exe(fh.read())
    except OSError:
        current = None
    if current not in (None, STOCK_ARENA_MB):
        return current
    return DEFAULT_ARENA_MB


def installed_budget(folder):
    """The budget currently written into ds.exe, or None if it cannot be read
    back. Needs the backup, which is what supplies the offsets."""
    backup = os.path.join(folder, BACKUP_EXE)
    if not os.path.isfile(backup):
        return None
    state, _r, pe, _s = read_state(os.path.join(folder, "ds.exe"))
    if state != PATCHED or pe is None:
        return None
    bstate, _r2, _bpe, bsites = read_state(backup)
    if bstate != VANILLA or not bsites:
        return None
    try:
        return struct.unpack_from("<I", pe.data, bsites["preset_high"][0])[0]
    except (struct.error, KeyError):
        return None


def _menu_actions(folder, dedicated, available, width, height):
    """The things worth doing right now, most useful first.

    Built from the state already detected, so the menu never offers an action
    that would only fail. Each entry carries the real subcommand it stands for,
    so using the menu teaches the command line instead of hiding it."""
    me = os.path.basename(sys.argv[0])
    vram = nominal_vram_mb(dedicated) or available
    want = recommend(available or vram, width, height) if vram else 0
    state, _reason, pe, _sites = read_state(os.path.join(folder, "ds.exe"))
    cfg_mb, _w, _h = read_cfg(folder)
    have = installed_budget(folder)
    arena_now = arena_from_exe(pe.data) if pe is not None else None
    actions = []

    def apply_at(mb):
        def run():
            # Plain language on purpose. What the engine gets told about the
            # card, and which byte goes where, belongs in --dry-run and
            # `verify --detail`, not in front of someone deciding yes or no.
            reading = screen_reading(mb, available, width, height)
            arena = arena_to_use(folder)
            plan = [_("Textures: %d MB instead of %d MB. %.1f times more.")
                    % (mb, STOCK_BUDGET_MB, mb / float(STOCK_BUDGET_MB))]
            if reading:
                plan.append(_("In the game's graphics options you will see %s.")
                            % reading)
            if arena != STOCK_ARENA_MB:
                plan.append(_("Frame memory: %d MB instead of %d MB, which is what")
                            % (arena, STOCK_ARENA_MB))
                plan.append(_("kills the game in mirrors. Costs that much plain RAM."))
            plan += [
                _("I copy ds.exe and settings.cfg first, before touching anything."),
                _("All of this undoes from this same menu, whenever you want.")]
            if not _confirm(plan):
                print(_("Nothing changed."))
                return
            print()
            for line in do_apply(folder, mb, vram, screen=reading, arena_mb=arena)[1]:
                print(line)
        return run

    if state == VANILLA and want:
        actions.append((_("Patch the game (%d MB)") % want, "apply", apply_at(want)))
    elif state == PATCHED:
        if have and cfg_mb and cfg_mb != have:
            actions.append((_("Put settings.cfg back to %d MB") % have,
                            "apply --mb %d" % have, apply_at(have)))
        actions.append((_("Read the real budget from the running game"), "measure",
                        lambda: do_measure(0)))
        # Only ever offered as an increase. Whether making the options screen's
        # two figures meet actually buys any effective budget has never been
        # measured: every measured configuration came out under its request
        # either way, so pressing someone to lower a working install would be
        # acting on a theory. `fit` is there for anyone who wants to try it.
        if want and have and want > have:
            actions.append((_("Raise the budget to %d MB") % want,
                            "apply --mb %d" % want, apply_at(want)))
        elif have and arena_now == STOCK_ARENA_MB:
            # Patched by a version that predates the frame memory patch. Not a
            # second thing to decide: it is the same apply, finishing the job.
            actions.append((_("Finish patching (frame memory, %d MB)")
                            % DEFAULT_ARENA_MB,
                            "apply --mb %d" % have, apply_at(have)))

    actions.append((_("Check what is installed"), "verify",
                    lambda: [print(x) for x in do_verify(folder, [])[1]]))

    # The frame arena is deliberately NOT a menu entry of its own. Patching is
    # one decision from the user's side; splitting it into "patch" and "also
    # patch the other thing" made the menu read like the second one was
    # optional homework. It rides along with apply above, and `arena --mb 96`
    # on the command line is there for anyone who wants it off.

    if state == PATCHED or have:
        def fit():
            print()
            print(_("  Open the game's graphics options and read the two figures"))
            print(_("  next to 'available graphics memory'."))
            req = _ask(_("  The first one, in GB (e.g. 16.0): "))
            avail = _ask(_("  The second one, in GB (e.g. 14.9): "))
            try:
                req, avail = float(req.replace(",", ".")), float(avail.replace(",", "."))
            except ValueError:
                print(_("  Those did not look like numbers. Nothing changed."))
                return
            base = have or cfg_mb
            if not base:
                print(_("  I cannot tell what budget those were read at."))
                return
            target = fit_budget(base, req, avail)
            print()
            print(_("  At %d MB those two meet at %d MB.") % (base, target))
            if target != base:
                apply_at(target)()
            else:
                print(_("  That is what you already have. Nothing to change."))
        actions.append((_("Match the figures in the game's own menu"), "fit", fit))

    def switch():
        global LANG
        LANG = "es" if LANG == "en" else "en"
    actions.append((_("Switch language (English / Espanol)"), "--lang", switch))

    if os.path.isfile(os.path.join(folder, BACKUP_EXE)):
        def revert():
            if not _confirm([_("Restore ds.exe and settings.cfg exactly as they were,"),
                             _("then delete the backups.")]):
                print(_("Nothing changed."))
                return
            print()
            for line in do_revert(folder)[1]:
                print(line)
        actions.append((_("Undo everything"), "revert", revert))
    return actions


def _menu(folder, dedicated, available, width, height):
    """One double-click covers the whole lifecycle, not just the first patch."""
    me = os.path.basename(sys.argv[0])
    while True:
        actions = _menu_actions(folder, dedicated, available, width, height)
        print()
        print(_("WHAT DO YOU WANT TO DO?"))
        print("-" * 68)
        for i, (label, cmd, _run) in enumerate(actions, 1):
            tag = _("  <- suggested") if i == 1 and len(actions) > 1 else ""
            print("  %d) %-44s (%s)%s" % (i, label, cmd, tag))
        print(_("  0) Quit and change nothing"))
        reading = screen_reading(recommend(available, width, height),
                                 available, width, height) if available else None
        if reading:
            print()
            print(_("  Your card has room for %d MB of textures. In the game's")
                  % recommend(available, width, height))
            print(_("  graphics options that shows up as %s.") % reading)
        print()
        choice = _ask(_("Press [0-%d] and Enter: ") % len(actions))
        if choice in ("", "0", "q"):
            print(_("Nothing changed."))
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(actions):
            print(_("That was not one of the numbers."))
            continue
        print()
        actions[int(choice) - 1][2]()
        print()
        print("-" * 68)
        if _ask(_("Press [y] for the menu again, anything else to quit: ")) \
                .lower() != "y":
            print()
            print(_("Every one of those is a command you can also type directly,"))
            print(_("for example:  python %s verify") % me)
            return 0


def _lang_from_argv(argv):
    """--lang has to be read before argparse is built, not after it parses:
    every help string goes through _(), and those are evaluated while the
    parser is being constructed."""
    for i, a in enumerate(argv):
        if a.startswith("--lang="):
            return a.split("=", 1)[1].lower()
        if a == "--lang" and i + 1 < len(argv):
            return argv[i + 1].lower()
    return None


def main(argv=None):
    global LANG
    raw = list(sys.argv[1:] if argv is None else argv)
    asked = _lang_from_argv(raw)
    LANG = asked if asked in ("en", "es") else detect_language()

    p = argparse.ArgumentParser(
        prog="dsdc_streaming_unlock.py",
        description=_("Raise the texture streaming budget of Death Stranding "
                    "Director's Cut by patching your own ds.exe."),
        epilog=_("With no subcommand, prints what it found and what it would do."))
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    p.add_argument("--interactive", action="store_true",
                   help=_("show a menu instead of expecting subcommands, and hold "
                        "the window open at the end. RUN_ME.cmd passes this"))
    p.add_argument("--game", metavar="FOLDER",
                   help=_("game folder (default: autodetect). Also accepted by "
                        "each subcommand"))
    p.add_argument("--lang", choices=("en", "es"),
                   help=_("output language (default: taken from Windows)"))
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--game", metavar="FOLDER",
                        help=_("game folder (default: autodetect)"))
        return sp

    common(sub.add_parser("status", help=_("show what is installed (default)")))

    ap = common(sub.add_parser("apply", help=_("patch ds.exe")))
    ap.add_argument("--mb", type=int,
                    help=_("streaming budget in MB, multiple of 128 (default: "
                         "sized so the game's menu reports a requirement that "
                         "fits the memory Windows makes available)"))
    ap.add_argument("--vram", type=int,
                    help=_("VRAM to make the engine assume, in MB "
                         "(default: the size of your card)"))
    ap.add_argument("--mipbias", type=float, default=0.0, metavar="B",
                    help=_("advanced: resulting mip bias. 0.0 (default) is the "
                         "engine's own neutral; -1.0 is the strongest it ever "
                         "asks for itself, at more streaming cost"))
    ap.add_argument("--arena", type=int, metavar="MB",
                    help=_("per-frame arena size in MB (%d-%d). Patched together "
                         "with the budget, at %d by default, or whatever you "
                         "already had. Pass %d to leave it at the stock size")
                    % (MIN_ARENA_MB, MAX_ARENA_MB, DEFAULT_ARENA_MB,
                       STOCK_ARENA_MB))
    ap.add_argument("--dry-run", action="store_true",
                    help=_("show every edit without writing anything"))
    ap.add_argument("--from", dest="source", metavar="FILE",
                    help=_("advanced: patch this file instead of the installed game"))
    ap.add_argument("--out", metavar="FILE",
                    help=_("advanced: write the result here (use with --from)"))

    arp = common(sub.add_parser(
        "arena", help=_("change just the per-frame arena, without re-running apply")))
    arp.add_argument("--mb", type=int, default=DEFAULT_ARENA_MB, metavar="MB",
                     help=_("new size in MB (%d-%d, default %d). Pass %d to put "
                          "the stock size back")
                     % (MIN_ARENA_MB, MAX_ARENA_MB, DEFAULT_ARENA_MB, STOCK_ARENA_MB))

    common(sub.add_parser("revert", help=_("restore ds.exe and settings.cfg, leave no trace")))
    vp = common(sub.add_parser("verify", help=_("check what is actually patched")))
    vp.add_argument("--detail", action="store_true",
                    help=_("also print the raw offsets, hashes and numbers"))

    fp = common(sub.add_parser(
        "fit", help=_("match the two figures shown in the game's options screen")))
    fp.add_argument("--required", type=float, required=True, metavar="GB",
                    help=_("the first figure the game shows, in GB"))
    fp.add_argument("--available", type=float, required=True, metavar="GB",
                    help=_("the second figure the game shows, in GB"))
    fp.add_argument("--current", type=int, metavar="MB",
                    help=_("budget those figures were read at "
                         "(default: whatever settings.cfg says)"))

    mp = sub.add_parser("measure",
                        help=_("read the real budget out of the running game (read-only)"))
    mp.add_argument("--wait", type=int, default=0, metavar="MINUTES",
                    help=_("wait this long for the game to come up and take one reading"))

    # --lang is read out of argv further up, so it takes effect wherever it
    # appears. argparse still has to be told to accept it after a subcommand
    # as well; what it stores here is never read.
    for sp in sub.choices.values():
        sp.add_argument("--lang", choices=("en", "es"),
                        help=_("output language (default: taken from Windows)"))

    args = p.parse_args(argv)
    if getattr(args, "interactive", False):
        global _INTERACTIVE
        _INTERACTIVE = True
    if args.cmd in (None, "status"):
        if not hasattr(args, "game"):
            args.game = None
        return cmd_status(args)
    return {"apply": cmd_apply, "revert": cmd_revert, "verify": cmd_verify,
            "measure": cmd_measure, "fit": cmd_fit, "arena": cmd_arena}[args.cmd](args)



# ========================================================================
# Spanish
# ========================================================================
#
# English is the source text and the key. A test walks the AST and fails if
# any _() literal is missing from here, so a half-translated build cannot
# ship. Subcommand names (apply, verify, fit, measure, revert) are never
# translated: they are what you type.

SPANISH = {
    'I could not find the game on this machine.': 'No pude encontrar el juego en esta maquina.',
    'Find the folder that holds ds.exe and drag it onto this window,': 'Busca la carpeta donde esta ds.exe y arrastrala a esta ventana,',
    'or paste the path. Press Enter on its own to quit.': 'o pega la ruta. Pulsa Enter a secas para salir.',
    'Game folder: ': 'Carpeta del juego: ',
    'Found it: %s': 'Encontrada: %s',
    'No ds.exe in there, and none in the folders inside it.': 'Ahi no hay ds.exe, ni en las carpetas que contiene.',
    'STATUS': 'ESTADO',
    'COMMANDS': 'COMANDOS',
    '  Video memory    %d MB on the card, %d MB Windows lets a game use':
        '  Memoria video    %d MB en la tarjeta, %d MB que Windows deja usar',
    'NOTE: %d MB is BELOW the stock %d MB. That makes things worse,':
        'NOTA: %d MB esta POR DEBAJO de los %d MB de fabrica. Eso empeora las',
    '      not better, and at the 1536 MB floor the mip bias goes to +1.':
        '      cosas, y en el piso de 1536 MB el sesgo de mip se va a +1.',
    'budget must be between %d and %d MB':
        'el presupuesto tiene que estar entre %d y %d MB',
    'assumed VRAM must be between %d and %d MB':
        'la VRAM asumida tiene que estar entre %d y %d MB',
    'mip bias must be under 1.0 and no lower than -8.0':
        'el sesgo de mip tiene que ser menor que 1.0 y no bajar de -8.0',
    'Cannot read %s: %s': 'No puedo leer %s: %s',
    'truncated or malformed PE header': 'cabecera PE truncada o mal formada',
    '  [ OK ]  Backup made of ds.exe':
        '  [ OK ]  Copia de seguridad de ds.exe',
    '  [ OK ]  Backup already there, left alone':
        '  [ OK ]  La copia de seguridad ya estaba, no la toco',
    '  [ OK ]  ds.exe patched in %d places':
        '  [ OK ]  ds.exe parcheado en %d sitios',
    '  [ OK ]  settings.cfg set to %d MB':
        '  [ OK ]  settings.cfg puesto en %d MB',
    '   DONE': '   LISTO',
    '   Textures       %d MB   (%.1f times the stock %d MB)':
        '   Texturas       %d MB   (%.1f veces los %d MB de fabrica)',
    '   In the game    %s': '   En el juego    %s',
    '   WARNING: mip level %d. Textures will look WORSE than stock.':
        '   AVISO: nivel de mip %d. Las texturas se veran PEOR que sin parche.',
    '   Run apply again; something did not take.':
        '   Vuelve a correr apply; algo no entro.',
    '   NOW    Open the game and load a save.':
        '   AHORA  Abre el juego y carga una partida.',
    '   THEN   Come back here for "Read the real budget", to see how':
        '   LUEGO  Vuelve aqui a "Leer el presupuesto real", para ver cuanta',
    '          much the engine actually handed out.':
        '          memoria te dio el motor de verdad.',
    '   NOTE   Verifying game files in Steam silently undoes this.':
        '   OJO    Verificar los archivos en Steam deshace esto sin avisar.',
    '  Unofficial and unaffiliated with Kojima Productions, 505 Games or':
        '  No oficial, sin relacion con Kojima Productions, 505 Games ni Sony.',
    '  Sony. It patches your own ds.exe and redistributes nothing.':
        '  Parchea tu propio ds.exe y no redistribuye nada.',
    'Textures: %d MB instead of %d MB. %.1f times more.':
        'Texturas: %d MB en vez de %d MB. %.1f veces mas.',
    "In the game's graphics options you will see %s.":
        'En las opciones graficas del juego veras %s.',
    'I copy ds.exe and settings.cfg first, before touching anything.':
        'Copio ds.exe y settings.cfg antes de tocar nada.',
    'All of this undoes from this same menu, whenever you want.':
        'Todo esto se deshace desde este mismo menu, cuando quieras.',
    "  Your card has room for %d MB of textures. In the game's":
        '  En tu tarjeta caben %d MB de texturas. En las opciones',
    '  graphics options that shows up as %s.':
        '  graficas del juego eso se ve como %s.',
    'yes': 'si',
    'missing': 'falta',
    'output language (default: taken from Windows)':
        'idioma de la salida (por defecto: el de Windows)',
    'Switch language (English / Espanol)':
        'Cambiar idioma (English / Espanol)',
    'DSDC Streaming Memory Unlock %s': 'DSDC Streaming Memory Unlock %s',
    '  Graphics card   %s': '  Tarjeta grafica  %s',
    '  Video memory    not detected. Pass --vram yourself':
        '  Memoria video    sin detectar. Pasa --vram a mano',
    '  Game folder     %s': '  Carpeta juego    %s',
    '  Resolution      %d x %d': '  Resolucion       %d x %d',
    '  python %s %-9s %s': '  python %s %-9s %s',
    '  Add --help to any of them for its options.':
        '  Anade --help a cualquiera para ver sus opciones.',
    "  'apply' with no arguments would ask for %d MB on this machine.":
        "  'apply' sin argumentos pediria %d MB en esta maquina.",
    "  That is sized so the game's menu reports a requirement that fits":
        '  Ese valor esta calculado para que lo que el menu del juego pide',
    '  inside the %d MB it has available.':
        '  quepa en los %d MB disponibles.',
    'could not detect': 'sin detectar',
    'patch the game, sized from your card':
        'parchea el juego segun tu tarjeta',
    'check what is actually installed':
        'comprueba que hay instalado de verdad',
    'read the real budget out of the running game':
        'lee el presupuesto real del juego en marcha',
    "match the two figures in the game's own menu":
        'cuadra las dos cifras del menu del juego',
    'undo everything, leave no trace': 'deshace todo, sin dejar rastro',
    'NOT PATCHED. This is the stock ds.exe.':
        'SIN PARCHEAR. Este es el ds.exe de fabrica.',
    'Texture streaming is capped at %d MB.':
        'El streaming de texturas esta limitado a %d MB.',
    'To patch it, with the game closed:':
        'Para parchearlo, con el juego cerrado:',
    '  python %s apply': '  python %s apply',
    "If you had patched it before, Steam's 'Verify integrity of game":
        "Si ya lo habias parcheado, 'Verificar integridad de los archivos'",
    "files' undoes it silently. That is almost always what happened.":
        'de Steam lo deshace en silencio. Casi siempre es eso lo que paso.',
    'UNRECOGNISED ds.exe. I will not touch it.':
        'ds.exe NO RECONOCIDO. No lo voy a tocar.',
    'Either this is a game version newer than this tool, or something':
        'O es una version del juego mas nueva que esta herramienta, o algo',
    "else has already modified ds.exe. Use Steam's 'Verify integrity":
        "mas ya modifico ds.exe. Usa 'Verificar integridad de los archivos'",
    "of game files' to get a clean one.":
        'en Steam para conseguir uno limpio.',
    'PATCHED, but %s is missing.': 'PARCHEADO, pero falta %s.',
    "Without the backup I cannot check every field, and 'revert' has":
        "Sin el respaldo no puedo comprobar todos los campos, y 'revert' no",
    'nothing to restore from. Assumed VRAM reads as %s MB.':
        'tiene de donde restaurar. La VRAM asumida marca %s MB.',
    "Use Steam's 'Verify integrity of game files' to get back to stock.":
        "Usa 'Verificar integridad de los archivos' en Steam para volver a cero.",
    'PATCHED, but %s is not a recognisable stock ds.exe.':
        'PARCHEADO, pero %s no es un ds.exe original reconocible.',
    "'revert' will refuse to use it. Verify your game files in Steam.":
        "'revert' se negara a usarlo. Verifica los archivos en Steam.",
    'budget set in all 4 places': 'presupuesto en los 4 sitios',
    'they disagree: %s': 'no coinciden: %s',
    'the four preset sites do not match':
        'los cuatro sitios de preset no coinciden',
    'settings.cfg agrees': 'settings.cfg concuerda',
    'settings.cfg says': 'settings.cfg dice',
    'settings.cfg was reset': 'settings.cfg fue reseteado',
    'setter clamp above the budget': 'tope del setter por encima',
    'the clamp would cut the budget': 'el tope recortaria el presupuesto',
    'assumed VRAM raised from %d MB': 'VRAM asumida subida desde %d MB',
    'code %d / template %d': 'codigo %d / plantilla %d',
    'the assumed VRAM is not raised in both places':
        'la VRAM asumida no esta subida en los dos sitios',
    'mip bias neutral': 'sesgo de mip neutro',
    'level 0  <- the important one': 'nivel 0  <- el que importa',
    'mip bias': 'sesgo de mip',
    'level %d': 'nivel %d',
    'A negative level forces finer mips on everything, which makes':
        'Un nivel negativo fuerza mips mas finos en todo, y las texturas',
    'textures look WORSE than stock. Re-run apply to fix the divisor:':
        'salen PEOR que sin parche. Vuelve a correr apply para corregirlo:',
    'the mip bias is not neutral': 'el sesgo de mip no es neutro',
    '64-bit conversion detour in place': 'detour de 64 bits en su sitio',
    'the detour is missing': 'falta el detour',
    'PATCHED, but something is off: %s.': 'PARCHEADO, pero algo va mal: %s.',
    'PATCHED and healthy.': 'PARCHEADO y en orden.',
    'Texture streaming budget: %d MB, %.1fx the stock %d MB.':
        'Presupuesto de streaming: %d MB, %.1f veces los %d MB de fabrica.',
    'Nothing to do. Load a save, then run this to see what the engine':
        'Nada que hacer. Carga una partida y corre esto para ver lo que el',
    'really handed out:  python %s measure':
        'motor entrego de verdad:  python %s measure',
    '(for the raw offsets and hashes:  python %s verify --detail)':
        '(offsets y hashes en crudo:  python %s verify --detail)',
    'There is no ds.exe in %s': 'No hay ningun ds.exe en %s',
    'No ds.exe in %s': 'No hay ds.exe en %s',
    '  ds.exe        %s': '  ds.exe        %s',
    '  state         %s': '  estado        %s',
    '  settings.cfg  streaming_memory_mb = %s':
        '  settings.cfg  streaming_memory_mb = %s',
    '                rendering %dx%d': '                resolucion %dx%d',
    '  mip divisor   %.1f  ->  bias %.3f  ->  level %d':
        '  divisor mip   %.1f  ->  sesgo %.3f  ->  nivel %d',
    'not set': 'sin valor',
    'The game is running. Close it and try again.':
        'El juego esta abierto. Cierralo y vuelve a intentarlo.',
    'The game is running. Close it first.':
        'El juego esta abierto. Cierralo primero.',
    'Already patched, and I cannot find the backup.':
        'Ya esta parcheado y no encuentro el respaldo.',
    "Use 'Verify integrity of game files' in Steam, then run this again.":
        "Usa 'Verificar integridad de los archivos' en Steam y repite esto.",
    'Already patched: starting again from %s.':
        'Ya estaba parcheado: parto de nuevo desde %s.',
    'I do not recognise this ds.exe (%s).': 'No reconozco este ds.exe (%s).',
    'It may be a game version this tool does not support yet.':
        'Puede ser una version del juego que esta herramienta aun no soporta.',
    'NOTE: this is not the build this patch was measured on.':
        'NOTA: este no es el build sobre el que se midio el parche.',
    '  found    %s': '  encontrado %s',
    '  measured %s  (%s)': '  medido     %s  (%s)',
    '  Every site was still found by signature, so the patch applies,':
        '  Todos los sitios se encontraron por firma, asi que el parche entra,',
    '  but nobody has measured the result on this build.':
        '  pero nadie ha medido el resultado en este build.',
    'Could not make a reliable backup. Leaving ds.exe alone.':
        'No pude crear un respaldo fiable. No toco ds.exe.',
    '  Start the game once, set Texture Streaming to High, quit, and re-run this.':
        '  Abre el juego una vez, pon Memoria para transmision en Alta, sal y repite.',
    'could not write settings.cfg': 'no pude escribir settings.cfg',
    'There is no backup to restore from.':
        'No hay respaldo del que restaurar.',
    "Use 'Verify integrity of game files' in Steam to get a clean ds.exe.":
        "Usa 'Verificar integridad de los archivos' en Steam para un ds.exe limpio.",
    'The backup is not a recognisable original ds.exe. Touching nothing.':
        'El respaldo no es un ds.exe original reconocible. No toco nada.',
    "Use 'Verify integrity of game files' in Steam.":
        "Usa 'Verificar integridad de los archivos' en Steam.",
    'ds.exe restored from %s': 'ds.exe restaurado desde %s',
    'The restored file does not match the backup. Deleting nothing.':
        'La copia no coincide con el respaldo. No borro nada.',
    '  ds.exe          %s': '  ds.exe          %s',
    'MD5 verified:   %s': 'MD5 verificado: %s',
    'settings.cfg returned to its original contents':
        'settings.cfg devuelto a su contenido original',
    "settings.cfg    streaming_memory_mb = 3072 (stock 'High' value)":
        "settings.cfg    streaming_memory_mb = 3072 (valor de fabrica de 'Alta')",
    'No trace left: %d file(s) removed. You can delete this script now.':
        'Sin rastro: %d archivo(s) retirados. Ya puedes borrar este script.',
    'Nothing left to clean up.': 'No quedaba nada que limpiar.',
    'Deleted: ': 'Borrado: ',
    'Could not delete %s: %s': 'No pude borrar %s: %s',
    'Windows will not let me write to the game folder.':
        'Windows no me deja escribir en la carpeta del juego.',
    'Close this and run it again from an Administrator terminal.':
        'Cierra esto y vuelve a abrirlo desde una terminal como administrador.',
    'That is normal when the game lives under Program Files (Epic, for example).':
        'Es lo normal si el juego esta en Archivos de programa (Epic, por ejemplo).',
    'Could not write the file: %s': 'No pude escribir el archivo: %s',
    'If you run an antivirus, it may be blocking it.':
        'Si tienes un antivirus, puede estar bloqueandolo.',
    'WHAT DO YOU WANT TO DO?': 'QUE QUIERES HACER?',
    'Patch the game (%d MB)': 'Parchear el juego (%d MB)',
    'Put settings.cfg back to %d MB': 'Devolver settings.cfg a %d MB',
    'Read the real budget from the running game':
        'Leer el presupuesto real del juego en marcha',
    'Raise the budget to %d MB': 'Subir el presupuesto a %d MB',
    'Check what is installed': 'Comprobar que hay instalado',
    "Match the figures in the game's own menu":
        'Cuadrar las cifras del menu del juego',
    'Undo everything': 'Deshacer todo',
    '  0) Quit and change nothing': '  0) Salir sin cambiar nada',
    '  <- suggested': '  <- sugerido',
    'Press [0-%d] and Enter: ': 'Pulsa [0-%d] y Enter: ',
    'That was not one of the numbers.': 'Eso no era ninguno de los numeros.',
    'Nothing changed.': 'No se cambio nada.',
    'Press [y] for the menu again, anything else to quit: ':
        'Pulsa [y] para volver al menu, cualquier otra cosa para salir: ',
    'Every one of those is a command you can also type directly,':
        'Cada una de esas es un comando que tambien puedes teclear,',
    'for example:  python %s verify': 'por ejemplo:  python %s verify',
    'Press [y] to go ahead, anything else to cancel: ':
        'Pulsa [y] para continuar, cualquier otra cosa para cancelar: ',
    'Restore ds.exe and settings.cfg exactly as they were,':
        'Restaurar ds.exe y settings.cfg exactamente como estaban,',
    'then delete the backups.': 'y despues borrar los respaldos.',
    "  Open the game's graphics options and read the two figures":
        '  Abre las opciones graficas del juego y lee las dos cifras',
    "  next to 'available graphics memory'.":
        "  que salen en 'memoria grafica disponible'.",
    '  The first one, in GB (e.g. 16.0): ':
        '  La primera, en GB (p. ej. 16.0): ',
    '  The second one, in GB (e.g. 14.9): ':
        '  La segunda, en GB (p. ej. 14.9): ',
    '  Those did not look like numbers. Nothing changed.':
        '  Eso no parecian numeros. No se cambio nada.',
    '  I cannot tell what budget those were read at.':
        '  No puedo saber con que presupuesto se leyeron esas cifras.',
    '  At %d MB those two meet at %d MB.':
        '  Con %d MB, esas dos cuadran en %d MB.',
    '  That is what you already have. Nothing to change.':
        '  Eso es lo que ya tienes. Nada que cambiar.',
    'Your options screen reads:': 'Tu pantalla de opciones dice:',
    '  required   %.1f GB': '  requerido   %.1f GB',
    '  available  %.1f GB': '  disponible  %.1f GB',
    'with the streaming budget at %d MB.':
        'con el presupuesto de streaming en %d MB.',
    'Those already match, within what one decimal place can show.':
        'Ya coinciden, dentro de lo que un decimal puede mostrar.',
    'Nothing to change.': 'Nada que cambiar.',
    'It is %s by %.1f GB, about %d MB.':
        'Se pasa %s por %.1f GB, unos %d MB.',
    'Set the budget to %d MB and the two figures should meet:':
        'Pon el presupuesto en %d MB y las dos cifras deberian cuadrar:',
    '  python %s apply --mb %d': '  python %s apply --mb %d',
    'The screen only shows one decimal, so this lands within about':
        'La pantalla solo da un decimal, asi que esto acierta dentro de unos',
    '50 MB, under the 128 MB the engine rounds to anyway.':
        '50 MB, por debajo de los 128 MB a los que el motor redondea igual.',
    'I need the budget those two figures were taken at.':
        'Necesito el presupuesto con el que se leyeron esas dos cifras.',
    'Pass it with --current, for example:  --current 15360':
        'Pasalo con --current, por ejemplo:  --current 15360',
    'measure only works on Windows.': 'measure solo funciona en Windows.',
    'Watching for up to %d minutes. Start the game and LOAD A SAVE.':
        'Vigilando hasta %d minutos. Abre el juego y CARGA UNA PARTIDA.',
    '(in the main menu the streaming pool is not initialised yet)':
        '(en el menu principal el pool de streaming aun no esta inicializado)',
    'ds.exe found, waiting for the streaming pool to come up...':
        'ds.exe detectado, esperando a que arranque el pool de streaming...',
    'Timed out without a reading. The pool never initialised.':
        'Se acabo el tiempo sin lectura. El pool nunca llego a inicializarse.',
    'ds.exe is not running, or has not initialised yet.':
        'ds.exe no esta corriendo, o aun no ha inicializado.',
    'Start the game, load a save, and run this again, or use --wait 20.':
        'Abre el juego, carga partida y repite esto, o usa --wait 20.',
    'If the game IS running, try an Administrator terminal.':
        'Si el juego SI esta abierto, prueba una terminal como administrador.',
    'ds.exe  PID %d   base 0x%X   (ASLR slide 0x%X)':
        'ds.exe  PID %d   base 0x%X   (desplazamiento ASLR 0x%X)',
    'engine object                    = 0x%X':
        'objeto del motor                 = 0x%X',
    'streaming_memory_mb field        = %d MB':
        'campo streaming_memory_mb        = %d MB',
    'EFFECTIVE BUDGET (pool+0x10)     = %d bytes = %.0f MB':
        'PRESUPUESTO EFECTIVO (pool+0x10) = %d bytes = %.0f MB',
    'Working. The engine took the full %.0f MB.':
        'Funciona. El motor tomo los %.0f MB completos.',
    'The patch is in: the field says %d MB, so the clamps are open.':
        'El parche entro: el campo dice %d MB, o sea que los topes estan abiertos.',
    'But the pool only took %.0f MB, which means the available-memory':
        'Pero el pool solo tomo %.0f MB, o sea que lo que recorta ahora es el',
    'limit is what is cutting it now, not the patch.':
        'limite de memoria disponible, no el parche.',
    'Size your mod against %.0f MB, not %d.':
        'Dimensiona tu mod contra %.0f MB, no contra %d.',
    'The field is only %d MB: part of the patch is not applied.':
        'El campo solo dice %d MB: parte del parche no esta aplicada.',
    'Run:  python %s verify': 'Corre:  python %s verify',
    '"High" preset value': 'valor del preset "Alta"',
    'preset writer': 'escritor de presets',
    'menu list entry': 'entrada de la lista del menu',
    'preset recogniser': 'reconocedor del preset',
    'setter upper clamp': 'tope superior del setter',
    'assumed VRAM (code)': 'VRAM asumida (codigo)',
    'assumed VRAM (template)': 'VRAM asumida (plantilla)',
    'MB->bytes conversion, 32-bit to 64-bit':
        'conversion MB->bytes, de 32 a 64 bits',
    'mip bias divisor': 'divisor del sesgo de mip',
    'relocated 64-bit shift': 'shl de 64 bits reubicado',
    'detour to the cave': 'detour hacia el hueco',
    'cmovs rdx,rax / shl rbx,0x14': 'cmovs rdx,rax / shl rbx,0x14',
    'cmovs rdx,rax / shl ebx,0x14   <- 32-bit, the bug':
        'cmovs rdx,rax / shl ebx,0x14   <- 32 bits, el fallo',
    'not a Windows executable': 'no es un ejecutable de Windows',
    'invalid PE header': 'cabecera PE invalida',
    'only 64-bit PE files are supported': 'solo se soportan PE de 64 bits',
    "cannot find (or found more than one) '%s'":
        "no encuentro (o esta repetido) '%s'",
    'cannot find the MB->bytes conversion':
        'no encuentro la conversion MB->bytes',
    'cannot find the mip bias division':
        'no encuentro la division del sesgo de mip',
    'the mip bias division falls outside the file':
        'la division del sesgo de mip cae fuera del archivo',
    'the mip bias constant is not recognisable':
        'la constante del sesgo de mip no es reconocible',
    'cannot find a safe code cave for the detour':
        'no encuentro un hueco de codigo seguro para el detour',
    'the detour or the cave falls outside the file':
        'el detour o el hueco cae fuera del archivo',
    "internal error: '%s' would change length":
        "error interno: '%s' cambiaria de longitud",
    "ABORTED at '%s': the bytes are not what was expected (file 0x%X)":
        "ABORTADO en '%s': los bytes no son los esperados (archivo 0x%X)",
    'settings.cfg does not exist yet': 'settings.cfg todavia no existe',
    'streaming_memory_mb not found in settings.cfg':
        'no encontre streaming_memory_mb en settings.cfg',
    "Could not find Death Stranding Director's Cut.":
        "No pude encontrar Death Stranding Director's Cut.",
    'Pass the folder explicitly, for example:':
        'Pasa la carpeta a mano, por ejemplo:',
    '  --game "...\\steamapps\\common\\DEATH STRANDING DIRECTORS CUT"':
        '  --game "...\\steamapps\\common\\DEATH STRANDING DIRECTORS CUT"',
    'Or drop this script into the game folder and run it there.':
        'O deja este script dentro de la carpeta del juego y ejecutalo ahi.',
    '--from and --out must be used together.': '--from y --out van juntos.',
    '--from/--out need explicit --mb and --vram.':
        '--from/--out necesitan --mb y --vram explicitos.',
    'MD5 %s   (%d sites)': 'MD5 %s   (%d sitios)',
    'Could not detect your card. Pass the numbers yourself, for':
        'No pude detectar tu tarjeta. Pasa los numeros a mano, por',
    'example:  --vram 16303 --mb 14080': 'ejemplo:  --vram 16303 --mb 14080',
    'NOTE: %d MB is not a multiple of 128. The engine rounds down, so you':
        'NOTA: %d MB no es multiplo de 128. El motor redondea hacia abajo, o sea',
    '      would actually get %d MB. Using %d instead.':
        '      que te daria %d MB. Uso %d en su lugar.',
    'ds.exe is %s%s. Nothing to preview.':
        'ds.exe esta %s%s. Nada que previsualizar.',
    'Dry run: %d MB budget, %d MB assumed VRAM. Nothing written.\n':
        'Simulacion: presupuesto %d MB, VRAM asumida %d MB. No se escribe nada.\n',
    'site': 'sitio',
    'file off': 'offset',
    'old': 'viejo',
    'new': 'nuevo',
    '\n  %d sites, %d bytes changed': '\n  %d sitios, %d bytes cambiados',
    "Raise the texture streaming budget of Death Stranding Director's Cut by patching your own ds.exe.":
        "Sube el presupuesto de streaming de texturas de Death Stranding Director's Cut parcheando tu propio ds.exe.",
    'With no subcommand, prints what it found and what it would do.':
        'Sin subcomando, imprime lo que encontro y lo que haria.',
    'show a menu instead of expecting subcommands, and hold the window open at the end. RUN_ME.cmd passes this':
        'muestra un menu en vez de esperar subcomandos, y deja la ventana abierta al final. RUN_ME.cmd lo pasa siempre',
    'game folder (default: autodetect). Also accepted by each subcommand':
        'carpeta del juego (por defecto: se detecta sola). Tambien la aceptan los subcomandos',
    'game folder (default: autodetect)':
        'carpeta del juego (por defecto: se detecta sola)',
    'show what is installed (default)':
        'muestra que hay instalado (por defecto)',
    'patch ds.exe': 'parchea ds.exe',
    "streaming budget in MB, multiple of 128 (default: sized so the game's menu reports a requirement that fits the memory Windows makes available)":
        'presupuesto de streaming en MB, multiplo de 128 (por defecto: calculado para que lo que pide el menu del juego quepa en la memoria que Windows concede)',
    'VRAM to make the engine assume, in MB (default: the size of your card)':
        'VRAM que el motor debe asumir, en MB (por defecto: el tamano de tu tarjeta)',
    "advanced: resulting mip bias. 0.0 (default) is the engine's own neutral; -1.0 is the strongest it ever asks for itself, at more streaming cost":
        'avanzado: sesgo de mip resultante. 0.0 (por defecto) es el neutro del propio motor; -1.0 es el maximo que el juego se pide a si mismo, a mas coste de streaming',
    'show every edit without writing anything':
        'muestra cada cambio sin escribir nada',
    'advanced: patch this file instead of the installed game':
        'avanzado: parchea este archivo en vez del juego instalado',
    'advanced: write the result here (use with --from)':
        'avanzado: escribe el resultado aqui (con --from)',
    'restore ds.exe and settings.cfg, leave no trace':
        'restaura ds.exe y settings.cfg, sin dejar rastro',
    'check what is actually patched':
        'comprueba que esta parcheado de verdad',
    'also print the raw offsets, hashes and numbers':
        'imprime ademas los offsets, hashes y numeros en crudo',
    "match the two figures shown in the game's options screen":
        'cuadra las dos cifras de la pantalla de opciones del juego',
    'the first figure the game shows, in GB':
        'la primera cifra que muestra el juego, en GB',
    'the second figure the game shows, in GB':
        'la segunda cifra que muestra el juego, en GB',
    'budget those figures were read at (default: whatever settings.cfg says)':
        'presupuesto con el que se leyeron esas cifras (por defecto: lo que diga settings.cfg)',
    'read the real budget out of the running game (read-only)':
        'lee el presupuesto real del juego en marcha (solo lectura)',
    'wait this long for the game to come up and take one reading':
        'espera este tiempo a que arranque el juego y toma una lectura',
    '\nPress Enter to close...': '\nPulsa Enter para cerrar...',

    # --- el arena por frame (v2.0) ---
    'The exe is still patched, so the game will keep asking for':
        'El exe sigue parcheado, asi que el juego va a seguir pidiendo',
    'what the exe says. Put the two back in step with:':
        'lo que dice el exe. Para ponerlos de acuerdo otra vez:',
    '   Measured in a running game: the engine really does build':
        '   Medido en el juego en marcha: el motor construye de verdad',
    '   the arena at this size, and the capacity it reports moves':
        '   el arena de este tamano, y la capacidad que reporta se mueve',
    '   with it.':
        '   con el.',
    'change just the per-frame arena, without re-running apply':
        'cambiar solo el arena por frame, sin repetir todo el apply',
    'per-frame arena size in MB (%d-%d). Patched together with the budget, at %d by default, or whatever you already had. Pass %d to leave it at the stock size':
        'tamano del arena por frame en MB (%d-%d). Se parchea junto con el presupuesto, a %d por defecto, o lo que ya tuvieras. Pon %d para dejarlo en el de fabrica',
    'Frame memory: %d MB instead of %d MB, which is what':
        'Memoria de frame: %d MB en vez de %d MB, que es lo que',
    'kills the game in mirrors. Costs that much plain RAM.':
        'mata el juego en los espejos. Cuesta esa RAM normal.',
    'Finish patching (frame memory, %d MB)':
        'Terminar de parchear (memoria de frame, %d MB)',
    'per-frame arena (template)':
        'arena por frame (template)',
    'the two frame arena writers disagree':
        'los dos escritores del arena por frame no coinciden',
    'the memory template is not where it should be':
        'el template de memoria no esta donde deberia',
    'cannot find (or found more than one) the memory template':
        'no encuentro (o encontre mas de uno) el template de memoria',
    'constructor %d MB, template %d MB':
        'constructor %d MB, template %d MB',
    'Those must match. Re-run:  python %s arena --mb %d':
        'Tienen que coincidir. Vuelve a ejecutar:  python %s arena --mb %d',
    'per-frame arena size':
        'tamano del arena por frame',
    'frame arena':
        'arena por frame',
    'cannot find (or found more than one) the per-frame arena':
        'no encuentro (o encontre mas de uno) el arena por frame',
    'the per-frame arena size is not where it should be':
        'el tamano del arena por frame no esta donde deberia',
    'the frame arena must be between %d and %d MB':
        'el arena por frame tiene que estar entre %d y %d MB',
    'the frame arena cannot go past %d MB: the instruction sign-extends':
        'el arena por frame no puede pasar de %d MB: la instruccion extiende el signo',
    'Either this is a game version this tool does not know, or':
        'O esta es una version del juego que esta herramienta no conoce, o',
    'something else has already modified ds.exe.':
        'alguna otra cosa ya modifico el ds.exe.',
    '  [ OK ]  Frame arena %d MB -> %d MB':
        '  [ OK ]  Arena por frame %d MB -> %d MB',
    '   Back to the stock size. The streaming patch, if you have':
        '   De vuelta al tamano de fabrica. El parche de streaming, si lo',
    '   one, is untouched.':
        '   tienes, queda intacto.',
    '   That costs %d MB more system RAM, and nothing else.':
        '   Eso cuesta %d MB mas de RAM del sistema, y nada mas.',
    'resize the per-frame arena (advanced)':
        'cambiar el tamano del arena por frame (avanzado)',
    'Keeping the frame arena at %d MB.':
        'Mantengo el arena por frame en %d MB.',
    '   Frame arena    %d MB   (stock %d MB, costs that much RAM)':
        '   Arena x frame  %d MB   (de fabrica %d MB, cuesta esa RAM)',
    'The frame arena is already %d MB. Nothing to do.':
        'El arena por frame ya esta en %d MB. No hay nada que hacer.',
    'Streaming NOT patched, but the frame arena IS raised.':
        'El streaming NO esta parcheado, pero el arena por frame SI esta ampliado.',
    '%d MB (stock)':
        '%d MB (de fabrica)',
    '%d MB, raised from %d MB':
        '%d MB, ampliado desde %d MB',
    'new size in MB (%d-%d, default %d). Pass %d to put the stock size back':
        'tamano nuevo en MB (%d-%d, por defecto %d). Pon %d para devolver el de fabrica',
    'Frame arena: %d MB, up from the stock %d MB.':
        'Arena por frame: %d MB, frente a los %d MB de fabrica.',
}

if __name__ == "__main__":
    try:
        _code = main()
    except SystemExit as _exc:          # argparse: --help, --version, bad flags
        _code = _exc.code
    # When --interactive came from RUN_ME.cmd, the launcher does the pausing --
    # and it pauses even if this crashed outright, which a pause down here
    # would not. The weak double-click guess is left as the fallback for
    # someone running the .py directly.
    if _double_clicked() and not _INTERACTIVE:
        try:
            input(_("\nPress Enter to close..."))
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(_code)
