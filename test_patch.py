#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for dsdc_streaming_unlock.

    python -m unittest -v                 everything that needs no game file
    set DSDC_VANILLA=<path to ds.exe>     plus the byte-identity tests

An unpatched ds.exe is 86 MB and is not ours to ship, so it is not in this
repo. Point DSDC_VANILLA at your own, or drop a copy at fixtures/ds.exe.

The tests that run without it cover both bugs this patcher has shipped: the
code cave's return jump landing a byte early, and the setter ceiling pinned
at a flat 16384. Neither needs the executable to reproduce.
"""

import ast
import contextlib
import getpass
import io
import os
import re
import shutil
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsdc_streaming_unlock as dsu

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "dsdc_streaming_unlock.py")
LAUNCHER = os.path.join(HERE, "RUN_ME.cmd")

VANILLA_MD5 = "e379c9366feea0a4d235a54efe678a88"

# Measured, not derived. Each of these is a real ds.exe that was built, hashed,
# and in two cases actually run.
FIXTURES = {
    (14336, 16303): "f1c4252fe2041a15c456f93db3295394",
    (15360, 16303): "43c7ce2ec07dc08919b59a7fd82fb088",
}

SAMPLE_CFG = (b'"rendering_width" "2560"\r\n'
              b'"rendering_height" "1440"\r\n'
              b'"hdr" "1"\r\n'
              b'"streaming_memory_mb" "3072"\r\n'
              b'"wait_vsync" "0"\r\n')


def vanilla_path():
    env = os.environ.get("DSDC_VANILLA")
    if env and os.path.isfile(env):
        return env
    local = os.path.join(HERE, "fixtures", "ds.exe")
    return local if os.path.isfile(local) else None


VANILLA = vanilla_path()
needs_exe = unittest.skipIf(
    VANILLA is None,
    "no vanilla ds.exe: set DSDC_VANILLA or place one at fixtures/ds.exe")


# ==========================================================================
# Arithmetic. No game file needed.
# ==========================================================================

class TestNumbers(unittest.TestCase):

    def test_r128_rounds_down_to_the_engine_granularity(self):
        # The engine ANDs the budget with 0xFFFFFFFFF8000000. This is why the
        # old "4095 MB" patch actually delivered 3968 MB for months.
        self.assertEqual(dsu.r128(4095), 3968)
        self.assertEqual(dsu.r128(4096), 4096)
        self.assertEqual(dsu.r128(12288), 12288)
        self.assertEqual(dsu.r128(15403), 15360)

    def test_setter_ceiling_rises_with_the_budget(self):
        # A flat 16384 here is the regression that made the C# port emit
        # different bytes from the Python original for any budget over 14336.
        self.assertEqual(dsu.setter_ceiling(12288), 16384)
        self.assertEqual(dsu.setter_ceiling(14336), 16384)
        self.assertEqual(dsu.setter_ceiling(15360), 17408)
        self.assertEqual(dsu.setter_ceiling(24576), 26624)
        for mb in (1536, 8192, 15360, 24576, 32768):
            self.assertGreater(dsu.setter_ceiling(mb), mb,
                               "the clamp must sit above the request")

    def test_mip_divisor_lands_the_bias_on_the_engine_neutral(self):
        divisor = dsu.mip_divisor(12288, 0.0)
        self.assertEqual(divisor, 10752.0)
        self.assertAlmostEqual(dsu.mip_bias_of(12288, divisor), 0.0, places=6)
        self.assertEqual(int(dsu.mip_bias_of(12288, divisor)), 0)

    def test_mip_divisor_honours_an_explicit_bias(self):
        for mb in (8192, 12288, 15360):
            for want in (0.0, -0.5, -1.0):
                got = dsu.mip_bias_of(mb, dsu.mip_divisor(mb, want))
                self.assertAlmostEqual(got, want, places=5)

    def test_mip_divisor_leaves_small_budgets_alone(self):
        self.assertEqual(dsu.mip_divisor(1536, 0.0), 1280.0)
        self.assertEqual(dsu.mip_divisor(1024, 0.0), 1280.0)

    def test_the_stock_divisor_is_the_trap(self):
        # This is why the mip fix is not optional. With 1280.0 left in place,
        # a big budget drives the bias far negative, which pins mip 0 on
        # everything and makes textures worse than stock.
        self.assertEqual(int(dsu.mip_bias_of(4095, 1280.0)), 0)
        self.assertEqual(int(dsu.mip_bias_of(8192, 1280.0)), -4)
        self.assertEqual(int(dsu.mip_bias_of(12288, 1280.0)), -7)

    def test_recommend_matches_the_two_figures_on_screen(self):
        # The requirement is stated in what the player sees. The options screen
        # shows one decimal, the budget moves in 128 MB steps, and those do not
        # line up, so the rule is the largest step whose displayed
        # requirement does not exceed the displayed available.
        for available, w, h in ((15227, 2560, 1440), (15227, 3840, 2160),
                                (8100, 1920, 1080), (11500, 2560, 1440),
                                (23000, 3840, 2160), (31000, 2560, 1440)):
            mb = dsu.recommend(available, w, h)
            self.assertEqual(mb % 128, 0)
            self.assertGreaterEqual(mb, 1536)
            if mb == 1536:
                continue
            shown_req = round(dsu.menu_required_mb(mb, w, h) / 1024.0, 1)
            shown_avail = round(available / 1024.0, 1)
            self.assertLessEqual(
                shown_req, shown_avail,
                "%d MB at %dx%d would show %.1f / %.1f, over budget"
                % (mb, w, h, shown_req, shown_avail))

    def test_recommend_matches_the_measured_machine(self):
        # 15227 MB available at 2560x1440 -> 14208 MB, and the game's options
        # screen then reads 14.9 GB / 14.9 GB.
        self.assertEqual(dsu.recommend(15227, 2560, 1440), 14208)
        self.assertEqual(round(dsu.menu_required_mb(14208, 2560, 1440) / 1024.0, 1),
                         round(15227 / 1024.0, 1))

    def test_recommend_does_not_throw_away_a_whole_step(self):
        # Flooring the division lands the requirement a tenth low: 14080 showed
        # 14.8 / 14.9 while the point was to make them match.
        self.assertNotEqual(dsu.recommend(15227, 2560, 1440), 14080)

    def test_recommend_leaves_more_room_at_higher_resolution(self):
        self.assertGreater(dsu.recommend(15227, 1920, 1080),
                           dsu.recommend(15227, 3840, 2160),
                           "4K render targets cost more, so less is left")

    def test_the_screen_reading_is_quoted_next_to_every_budget(self):
        # 14208 MB of streaming reads as 14.9 GB on the game's screen, because
        # that screen counts render targets and a 600 MB base too. Quoting the
        # budget alone made people think the tool had not updated.
        self.assertEqual(dsu.screen_reading(14208, 15227, 2560, 1440),
                         "14.9 GB / 14.9 GB")
        self.assertIsNone(dsu.screen_reading(14208, 0, 2560, 1440))

    def test_nominal_vram_rounds_up_to_the_size_on_the_box(self):
        # DXGI reports 15995 for a 16 GB card, the registry 16303. The engine
        # takes min(real, this), so any value at or above the real size behaves
        # identically, and the round one is what the owner believes they have.
        self.assertEqual(dsu.nominal_vram_mb(15995), 16384)
        self.assertEqual(dsu.nominal_vram_mb(16303), 16384)
        self.assertEqual(dsu.nominal_vram_mb(12282), 12288)
        self.assertEqual(dsu.nominal_vram_mb(8176), 8192)
        self.assertEqual(dsu.nominal_vram_mb(24564), 24576)
        self.assertEqual(dsu.nominal_vram_mb(0), 0)
        for real in range(1024, 49152, 97):
            self.assertGreaterEqual(dsu.nominal_vram_mb(real), real,
                                    "must never sit below the real card")

    def test_check_values_refuses_what_would_corrupt_the_patch(self):
        # Each of these reached the byte writer once. A budget of 0 was
        # written straight through; -500 came out of struct.pack as a
        # traceback; a mip bias of 5 made the divisor negative and flipped the
        # bias positive, which is the failure this tool exists to avoid.
        for mb, vram, bias in ((0, 16384, 0.0), (-500, 16384, 0.0),
                               (100, 16384, 0.0), (99999999, 16384, 0.0),
                               (14208, 0, 0.0), (14208, -1, 0.0),
                               (14208, 16384, 5.0), (14208, 16384, 1.0),
                               (14208, 16384, -99.0)):
            self.assertIsNotNone(dsu.check_values(mb, vram, bias),
                                 "accepted mb=%s vram=%s bias=%s" % (mb, vram, bias))
        for mb, vram, bias in ((1536, 1536, 0.0), (14208, 16384, 0.0),
                               (14208, 16384, -1.0), (262144, 262144, 0.999)):
            self.assertIsNone(dsu.check_values(mb, vram, bias),
                              "rejected mb=%s vram=%s bias=%s" % (mb, vram, bias))

    def test_the_mip_bias_lands_on_zero_for_every_usable_budget(self):
        # At the 1536 MB floor the divisor
        # cannot be solved and the engine's own +1 stands, which is why the
        # sweep starts above it.
        for mb in range(1664, 32769, 128):
            self.assertEqual(int(dsu.mip_bias_of(mb, dsu.mip_divisor(mb, 0.0))), 0,
                             "%d MB leaves the bias off neutral" % mb)
        self.assertEqual(int(dsu.mip_bias_of(1536, dsu.mip_divisor(1536, 0.0))), 1)

    def test_fit_closes_the_gap_the_menu_shows(self):
        # 16.0 required / 14.9 available at 15360 MB: over by 1.1 GB.
        self.assertEqual(dsu.fit_budget(15360, 16.0, 14.9), 14208)

    def test_fit_raises_the_budget_when_there_is_room_to_spare(self):
        self.assertGreater(dsu.fit_budget(10240, 12.0, 14.9), 10240)

    def test_fit_is_a_no_op_when_the_figures_already_match(self):
        self.assertEqual(dsu.fit_budget(14208, 14.9, 14.9), 14208)

    def test_fit_never_goes_below_the_engine_floor(self):
        self.assertEqual(dsu.fit_budget(4096, 16.0, 1.0), 1536)


# ==========================================================================
# The detour. No game file needed.
# ==========================================================================

class TestDetourEncoding(unittest.TestCase):

    @staticmethod
    def _jmp_target(body, jmp_at, base_va):
        """Decode an E9 rel32 the way the CPU does: from the end of the jmp."""
        assert body[jmp_at] == 0xE9, "expected a jmp opcode"
        rel = struct.unpack_from("<i", body, jmp_at + 1)[0]
        return base_va + jmp_at + 5 + rel

    def test_cave_returns_to_the_exact_return_address(self):
        # Counting the E9 opcode twice used to land this one byte early,
        # in the middle of an instruction, which crashes the game.
        cave_va, return_va = 0x14199E85E, 0x14199E933
        body = dsu.cave_body(cave_va, return_va)
        self.assertEqual(len(body), dsu.CAVE_LEN)
        self.assertEqual(body[:4], dsu.PAT_CMOVS)
        self.assertEqual(body[4:8], dsu.PAT_SHL_RBX, "the shift must be 64-bit")
        self.assertEqual(self._jmp_target(body, 8, cave_va), return_va)

    def test_cave_return_holds_for_any_placement(self):
        for cave_va in (0x140001000, 0x14199E85E, 0x141FFFFF0):
            for delta in (-0x10000, -0xCE, 0x40, 0x8000):
                return_va = cave_va + delta
                body = dsu.cave_body(cave_va, return_va)
                self.assertEqual(self._jmp_target(body, 8, cave_va), return_va)

    def test_detour_jumps_to_the_cave_and_pads_to_seven(self):
        detour_va, cave_va = 0x14199E92C, 0x14199E85E
        body = dsu.detour_body(detour_va, cave_va)
        self.assertEqual(len(body), 7, "must be exactly as long as what it replaces")
        self.assertEqual(body[5:], b"\x90\x90")
        self.assertEqual(self._jmp_target(body, 0, detour_va), cave_va)

    def test_the_round_trip_lands_after_the_replaced_bytes(self):
        # Together the two jumps must skip the 7 overwritten bytes and
        # resume at the instruction that follows them.
        detour_va, cave_va = 0x14199E92C, 0x14199E85E
        detour = dsu.detour_body(detour_va, cave_va)
        self.assertEqual(self._jmp_target(detour, 0, detour_va), cave_va)
        cave = dsu.cave_body(cave_va, detour_va + 7)
        self.assertEqual(self._jmp_target(cave, 8, cave_va), detour_va + 7)


class _FakePE(object):
    """Enough of PE for find_cave: a flat buffer that is all one section, with
    no functions in it."""

    def __init__(self, data, funcs=()):
        self.data = data
        self.funcs = funcs

    def section_of(self, off):
        return (0, len(self.data))

    def off_to_va(self, off):
        return 0x140001000 + off

    def in_function(self, va):
        return any(a <= va < b for a, b in self.funcs)


class TestCaveSelection(unittest.TestCase):

    def test_takes_the_first_byte_of_the_padding_run(self):
        # The scan window is 0x100 bytes wide and can open in the middle of a
        # run. Taking the first 0xCC seen inside the window makes the result
        # depend on where the window happened to land, and the patch stops being
        # reproducible, and in the real executable it picked the byte after
        # the one the measured patch uses.
        data = bytearray(b"\x90" * 0x800)
        run_start, run_len = 0x300, 24
        data[run_start:run_start + run_len] = b"\xCC" * run_len
        detour = 0x400
        got = dsu.find_cave(_FakePE(bytes(data)), detour)
        self.assertEqual(got, run_start)

    def test_run_must_be_long_enough(self):
        data = bytearray(b"\x90" * 0x800)
        data[0x300:0x30A] = b"\xCC" * 10          # too short for 13 + margin
        long_start = 0x500
        data[long_start:long_start + 20] = b"\xCC" * 20
        self.assertEqual(dsu.find_cave(_FakePE(bytes(data)), 0x400), long_start)

    def test_skips_padding_that_lives_inside_a_function(self):
        data = bytearray(b"\x90" * 0x1000)
        inside, outside = 0x300, 0x600
        data[inside:inside + 20] = b"\xCC" * 20
        data[outside:outside + 20] = b"\xCC" * 20
        va = 0x140001000
        pe = _FakePE(bytes(data), funcs=[(va + inside - 8, va + inside + 40)])
        self.assertEqual(dsu.find_cave(pe, 0x400), outside)

    def test_returns_none_when_there_is_no_room(self):
        self.assertIsNone(dsu.find_cave(_FakePE(b"\x90" * 0x800), 0x400))


# ==========================================================================
# Fit to publish. No game file needed.
# ==========================================================================

class TestPublishable(unittest.TestCase):

    def setUp(self):
        with io.open(SCRIPT, encoding="utf-8") as fh:
            self.source = fh.read()

    def test_no_absolute_paths(self):
        # The tool this replaced had a drive path and a sys.path.insert into a
        # private folder baked in. No exceptions here: every path comes from
        # detection, an environment variable, or --game.
        offenders = []
        for m in re.finditer(r'["\'][A-Za-z]:[\\/]', self.source):
            line = self.source[:m.start()].count("\n") + 1
            offenders.append("line %d: %s" % (line, m.group(0)))
        self.assertEqual(offenders, [], "absolute path baked into the source")

    def test_no_sys_path_manipulation(self):
        self.assertNotIn("sys.path.insert", self.source)
        self.assertNotIn("sys.path.append", self.source)

    def test_nothing_identifies_the_machine_it_was_built_on(self):
        # Taken from the environment rather than written down, so this checks
        # whoever is running it instead of one particular author, and so the
        # test itself does not become the leak it is looking for.
        low = self.source.lower()
        for needle in (getpass.getuser(), socket.gethostname(),
                       os.path.expanduser("~"), tempfile.gettempdir()):
            if needle and len(needle) > 2:
                self.assertNotIn(needle.lower(), low, "leaks %r" % needle)
        for needle in ("libdir", "gmail.com", "c:\\users", "/home/",
                       "appdata\\local", "onedrive"):
            self.assertNotIn(needle, low, "leaks %r" % needle)

    def test_nothing_reaches_the_network(self):
        # No sockets, no HTTP, no telemetry. The only outside call is
        # nvidia-smi, run locally to read the card.
        low = self.source.lower()
        for needle in ("socket", "urllib", "http.client", "requests",
                       "smtplib", "ftplib", "telnetlib", "webbrowser"):
            self.assertNotIn(needle, low, "reaches the network via %r" % needle)
        self.assertNotIn("://", self.source.replace("MB->bytes", ""),
                         "carries a URL")
        commands = re.findall(r'subprocess\.\w+\(\s*\[([^\]]*)\]', self.source)
        for call in commands:
            self.assertIn("nvidia-smi", call, "runs something else: %s" % call)

    def test_imports_are_standard_library_only(self):
        allowed = {
            "argparse", "ast", "ctypes", "glob", "hashlib", "os", "re",
            "shutil", "stat", "struct", "subprocess", "sys", "time", "winreg",
        }
        tree = ast.parse(self.source)
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        extra = found - allowed
        self.assertEqual(extra, set(), "third-party import: %s" % sorted(extra))

    def test_no_asserts_used_as_control_flow(self):
        # Asserts vanish under python -O, taking their check with them.
        tree = ast.parse(self.source)
        lines = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        self.assertEqual(lines, [], "assert used at line(s) %s" % lines)

    def test_tidy_recovers_the_real_casing_of_a_path(self):
        # The Steam registry hands back paths in whatever case it feels like,
        # and Windows accepts them, so the game folder printed on screen came
        # out as a lowercase 'program files (x86)'.
        root = tempfile.mkdtemp(prefix="dsdc_case_")
        try:
            os.makedirs(os.path.join(root, "Program Files (X86)", "Steam"))
            asked = os.path.join(root, "program files (x86)", "steam")
            self.assertTrue(dsu._tidy(asked).endswith(
                os.path.join("Program Files (X86)", "Steam")))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_tidy_passes_through_a_path_that_is_not_there(self):
        made_up = os.path.join(tempfile.gettempdir(), "no_such_dir_9182", "nope")
        self.assertTrue(dsu._tidy(made_up).lower().endswith("nope"))

    def test_reading_the_gpu_never_raises(self):
        # Hand-rolled COM vtable calls into dxgi.dll. It has to come back
        # empty-handed on a machine without DXGI, not take the tool down.
        name, dedicated, available = dsu.dxgi_memory()
        self.assertTrue(name is None or isinstance(name, str))
        self.assertGreaterEqual(dedicated, 0)
        self.assertGreaterEqual(available, 0)
        name, dedicated, available = dsu.gpu_memory()
        self.assertGreaterEqual(dedicated, 0)
        self.assertGreaterEqual(available, 0)
        if available and dedicated:
            self.assertLessEqual(available, dedicated,
                                 "Windows never offers more than the card has")

    def test_the_double_click_probe_never_raises(self):
        # It pokes at the Win32 console API, which is absent or unusual under
        # a test runner, a pipe, or a non-Windows CI box.
        self.assertIn(dsu._double_clicked(), (True, False))

    def test_the_launcher_passes_interactive(self):
        # Measured: launched from a .cmd, GetConsoleProcessList returns 2, so
        # _double_clicked() is False. A launcher that forgot --interactive
        # would show no menu and no pause: the window would scroll past and
        # close, which is worse than no launcher at all.
        with io.open(LAUNCHER, encoding="ascii") as fh:
            text = fh.read()
        self.assertIn("dsdc_streaming_unlock.py", text)
        self.assertIn("--interactive", text)

    def test_the_launcher_cannot_patch_on_its_own(self):
        # It must never pass a write subcommand. The game gets modified only
        # after the user picks it from the menu and confirms.
        with io.open(LAUNCHER, encoding="ascii") as fh:
            body = "\n".join(l for l in fh.read().splitlines()
                             if not l.strip().lower().startswith("rem"))
        for verb in (" apply", " revert", "--mb"):
            self.assertNotIn(verb, body, "the launcher must not run '%s'" % verb.strip())

    def test_the_launcher_touches_nothing_outside_the_folder(self):
        # The project's promise is no registry, no network, no installers.
        # A downloaded .cmd is already the shape of malware; keeping it inert
        # and readable is the whole defence.
        with io.open(LAUNCHER, encoding="ascii") as fh:
            body = "\n".join(l for l in fh.read().splitlines()
                             if not l.strip().lower().startswith("rem")).lower()
        for verb in ("reg ", "regedit", "winget", "curl", "certutil", "bitsadmin",
                     "powershell", "mshta", "wscript", "schtasks", "assoc", "ftype",
                     "del ", "rmdir", "attrib", "icacls"):
            self.assertNotIn(verb, body, "launcher uses '%s'" % verb.strip())

    def test_the_launcher_is_ascii_and_crlf(self):
        # cmd.exe on a non-UTF-8 code page mangles anything else, and a .cmd
        # with bare LF endings can fail in confusing ways.
        with open(LAUNCHER, "rb") as fh:
            raw = fh.read()
        raw.decode("ascii")
        self.assertEqual(raw.count(b"\n"), raw.count(b"\r\n"), "every line needs CRLF")

    def test_interactive_honours_the_explicit_flag(self):
        # The flag has to win over the isatty()/console-count guesswork, which
        # is what made this unreliable before.
        self.assertFalse(dsu._INTERACTIVE, "must default off")
        dsu._INTERACTIVE = True
        try:
            self.assertTrue(dsu._interactive())
        finally:
            dsu._INTERACTIVE = False

    def _translatable(self):
        """Every string the source passes through _().

        Most are literals at the call site. The SITES descriptions are not:
        they stay English in the table and go through _() where they are
        shown, so they have to be added by hand.
        """
        out = [site[4] for site in dsu.SITES]
        for node in ast.walk(ast.parse(self.source)):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "id", None) == "_"
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                out.append(node.args[0].value)
        return out

    def test_every_translatable_string_has_spanish(self):
        missing = sorted(set(self._translatable()) - set(dsu.SPANISH))
        self.assertEqual(missing, [], "untranslated: %s" % missing[:5])

    def test_the_spanish_table_has_no_dead_entries(self):
        dead = sorted(set(dsu.SPANISH) - set(self._translatable()))
        self.assertEqual(dead, [], "no longer used: %s" % dead[:5])

    def test_translations_keep_the_same_format_specifiers(self):
        # The one that actually bites: a stray or missing %d makes the string
        # blow up at runtime in Spanish only, on a machine you cannot see.
        spec = re.compile(r"%[-+ #0-9.*]*[diouxXeEfFgGcrsa%]")
        for english, spanish in dsu.SPANISH.items():
            self.assertEqual(spec.findall(english), spec.findall(spanish),
                             "format mismatch for %r" % english)

    def test_every_translation_actually_formats(self):
        # Exercise the substitution itself, so a %s the compiler cannot see is
        # still caught.
        spec = re.compile(r"%[-+ #0-9.*]*([diouxXeEfFgGcrsa])")
        sample = {"d": 1, "i": 1, "o": 1, "u": 1, "x": 1, "X": 1, "c": 65,
                  "e": 1.0, "E": 1.0, "f": 1.0, "F": 1.0, "g": 1.0, "G": 1.0,
                  "s": "x", "r": "x", "a": "x"}
        for english, spanish in dsu.SPANISH.items():
            kinds = spec.findall(spanish)
            if not kinds:
                continue
            args = tuple(sample[k] for k in kinds)
            try:
                spanish % args
            except (TypeError, ValueError) as exc:
                self.fail("%r does not format: %s" % (spanish, exc))

    def test_subcommand_names_are_never_translated(self):
        # They are what the user types. Translating them would print a command
        # that does not exist.
        for verb in ("apply", "verify", "measure", "fit", "revert", "status"):
            self.assertNotIn(verb, dsu.SPANISH,
                             "'%s' is a command, not prose" % verb)

    def test_check_labels_fit_their_column(self):
        # do_verify lays the checks out with %-34s. A longer label shunts the
        # value column and the block stops reading as a table.
        labels = ["budget set in all 4 places", "settings.cfg agrees",
                  "settings.cfg says", "setter clamp above the budget",
                  "mip bias neutral", "mip bias",
                  "64-bit conversion detour in place"]
        for label in labels:
            for text in (label, dsu.SPANISH.get(label, label)):
                self.assertLessEqual(len(text), 34, "%r overflows" % text)

    def test_spanish_is_ascii(self):
        # cmd.exe on a non-UTF-8 code page (the default on a lot of Spanish
        # Windows installs) turns accented characters into mojibake, and the
        # console this runs in is not ours to configure. Unaccented Spanish is
        # plainer than garbled Spanish.
        for english, spanish in dsu.SPANISH.items():
            try:
                spanish.encode("ascii")
            except UnicodeEncodeError:
                self.fail("non-ASCII in the translation of %r: %r"
                          % (english, spanish))

    def test_edit_labels_fit_the_dry_run_column(self):
        # _print_edits lays the table out with %-30s. A longer label shunts
        # the offsets and the table stops lining up.
        labels = [site[4] for site in dsu.SITES]
        labels += ["relocated 64-bit shift", "detour to the cave"]
        for label in labels:
            for text in (label, dsu.SPANISH.get(label, label)):
                self.assertLessEqual(len(text), 30, "%r overflows" % text)

    def test_language_detection_never_raises(self):
        self.assertIn(dsu.detect_language(), ("en", "es"))

    def test_switching_language_changes_the_output(self):
        self.assertEqual(dsu.LANG, "en", "English is the default in tests")
        self.assertEqual(dsu._("Nothing changed."), "Nothing changed.")
        dsu.LANG = "es"
        try:
            self.assertEqual(dsu._("Nothing changed."), "No se cambio nada.")
            self.assertEqual(dsu._("not in the table"), "not in the table")
        finally:
            dsu.LANG = "en"

    def test_lang_is_read_before_argparse_builds_its_help(self):
        # argparse evaluates help= while the parser is constructed, which is
        # before parse_args. Reading --lang afterwards would leave every help
        # string in the wrong language.
        self.assertEqual(dsu._lang_from_argv(["--lang", "es"]), "es")
        self.assertEqual(dsu._lang_from_argv(["--lang=es", "apply"]), "es")
        self.assertIsNone(dsu._lang_from_argv(["apply", "--mb", "8192"]))

    def test_the_disclaimer_is_present_everywhere_it_belongs(self):
        # A legal notice that quietly disappears in a refactor is worse than
        # one that was never written, so it is pinned in all three places a
        # reader can land: the file header, the README, and the screen the
        # tool prints when you just run it.
        with io.open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        for text in (self.source, readme):
            # Whitespace collapsed: a line wrap should not break a legal check.
            low = " ".join(text.lower().split())
            # "not affiliated" or "unaffiliated": the wording is free, the
            # content is not.
            self.assertIn("affiliat", low)
            for company in ("kojima productions", "505 games", "sony"):
                self.assertIn(company, low, "missing %r" % company)
            self.assertIn("no game files are redistributed", low)
        shown = " ".join(
            n.args[0].value for n in ast.walk(ast.parse(self.source))
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_"
            and n.args and isinstance(n.args[0], ast.Constant)
            and isinstance(n.args[0].value, str)).lower()
        self.assertIn("kojima productions", shown,
                      "the status screen must say it too")

    def test_prompts_bracket_the_key_you_press(self):
        # "Type y to go ahead" reads as part of the sentence; the y disappears
        # into it. "[y]" reads as a key. Spanish makes it worse, since "y" is
        # the word "and", so the brackets are all that separates them.
        def literal(node):
            # _ask(_("...")) and _ask(_("...") % x) both reach the same string.
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                node = node.left
            if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                return node.args[0].value
            return None

        prompts = [literal(n.args[0])
                   for n in ast.walk(ast.parse(self.source))
                   if isinstance(n, ast.Call)
                   and getattr(n.func, "id", None) == "_ask" and n.args]
        prompts = [p for p in prompts if p]
        self.assertTrue(prompts, "found no prompts, so this walk is wrong")
        for english in ("Press [y] to go ahead, anything else to cancel: ",
                        "Press [y] for the menu again, anything else to quit: ",
                        "Press [0-%d] and Enter: "):
            self.assertIn(english, prompts, "prompt reworded, keep the [y]")
            self.assertIn("[", dsu.SPANISH[english],
                          "the Spanish has to bracket it too")

    def test_the_script_compiles_and_help_works(self):
        compile(self.source, SCRIPT, "exec")
        with self.assertRaises(SystemExit) as cm:
            dsu.main(["--version"])
        self.assertEqual(cm.exception.code, 0)


# ==========================================================================
# Byte identity against the measured builds. Needs the vanilla ds.exe.
# ==========================================================================

@needs_exe
class TestAgainstTheRealExecutable(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(VANILLA, "rb") as fh:
            cls.data = fh.read()

    def test_the_fixture_is_the_build_this_was_measured_on(self):
        self.assertEqual(dsu.md5_bytes(self.data), VANILLA_MD5,
                         "DSDC_VANILLA points at a different build; the byte-identity "
                         "tests below only mean anything against %s" % VANILLA_MD5)

    def test_every_site_is_found_exactly_once(self):
        pe = dsu.PE(self.data)
        sites, err = dsu.locate(pe)
        self.assertIsNone(err)
        for key, _pattern, _delta, _width, _desc in dsu.SITES:
            self.assertIn(key, sites)
        self.assertIn("detour", sites)
        self.assertIn("mip_divisor", sites)

    def test_reproduces_the_measured_builds_byte_for_byte(self):
        for (mb, vram), want in sorted(FIXTURES.items()):
            with self.subTest(mb=mb, vram=vram):
                out, edits, err = dsu.build(self.data, mb, vram)
                self.assertIsNone(err)
                self.assertEqual(len(edits), 10)
                self.assertEqual(len(out), len(self.data), "the file must not change size")
                self.assertEqual(dsu.md5_bytes(out), want)

    def test_the_patch_is_thirty_three_bytes(self):
        out, _edits, err = dsu.build(self.data, 14336, 16303)
        self.assertIsNone(err)
        changed = sum(1 for a, b in zip(self.data, out) if a != b)
        self.assertEqual(changed, 33)

    def test_building_is_deterministic(self):
        a, _e, _err = dsu.build(self.data, 14336, 16303)
        b, _e, _err = dsu.build(self.data, 14336, 16303)
        self.assertEqual(dsu.md5_bytes(a), dsu.md5_bytes(b))

    def test_a_patched_file_is_recognised_and_not_re_patched(self):
        out, _edits, _err = dsu.build(self.data, 14336, 16303)
        pe = dsu.PE(out)
        sites, err = dsu.locate(pe)
        self.assertIsNone(sites, "a patched file must not look vanilla")
        self.assertIsNotNone(err)
        _out2, _edits2, err2 = dsu.build(out, 15360, 16303)
        self.assertIsNotNone(err2, "patching an already patched file must fail")

    def test_refuses_an_executable_it_does_not_recognise(self):
        pe = dsu.PE(self.data)
        sites, _err = dsu.locate(pe)
        broken = bytearray(self.data)
        off = sites["setter_ceiling"][0]
        broken[off - 7] ^= 0xFF          # break the pattern, not the field
        _out, _edits, err = dsu.build(bytes(broken), 14336, 16303)
        self.assertIsNotNone(err, "must refuse rather than write blind")

    def test_finds_the_cave_where_the_measured_patch_put_it(self):
        pe = dsu.PE(self.data)
        sites, _err = dsu.locate(pe)
        self.assertEqual(dsu.find_cave(pe, sites["detour"][0]), 0x0199DC5E)


# ==========================================================================
# The apply / revert contract, on a scratch folder. Needs the vanilla ds.exe.
# ==========================================================================

@needs_exe
class TestApplyRevertContract(unittest.TestCase):

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="dsdc_test_")
        self.exe = os.path.join(self.folder, "ds.exe")
        self.cfg = os.path.join(self.folder, "settings.cfg")
        shutil.copy2(VANILLA, self.exe)
        with open(self.cfg, "wb") as fh:
            fh.write(SAMPLE_CFG)

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def _leftovers(self):
        return sorted(f for f in os.listdir(self.folder)
                      if f not in ("ds.exe", "settings.cfg"))

    def test_full_cycle_leaves_no_trace(self):
        ok, log = dsu.do_apply(self.folder, 14336, 16303)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), FIXTURES[(14336, 16303)])
        self.assertTrue(os.path.isfile(os.path.join(self.folder, dsu.BACKUP_EXE)))
        self.assertTrue(os.path.isfile(os.path.join(self.folder, dsu.BACKUP_CFG)))
        self.assertEqual(dsu.read_cfg(self.folder)[0], 14336)

        ok, log = dsu.do_revert(self.folder)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), VANILLA_MD5)
        with open(self.cfg, "rb") as fh:
            self.assertEqual(fh.read(), SAMPLE_CFG, "settings.cfg must come back byte for byte")
        self.assertEqual(self._leftovers(), [])

    def test_the_cfg_keeps_its_line_endings_and_every_other_key(self):
        dsu.do_apply(self.folder, 14336, 16303)
        with open(self.cfg, "rb") as fh:
            raw = fh.read()
        self.assertIn(b'"streaming_memory_mb" "14336"', raw)
        self.assertIn(b'"hdr" "1"', raw)
        self.assertNotIn(b"\n\n", raw)
        self.assertEqual(raw.count(b"\r\n"), SAMPLE_CFG.count(b"\r\n"))

    def test_applying_twice_is_idempotent(self):
        dsu.do_apply(self.folder, 14336, 16303)
        first = dsu.md5_file(self.exe)
        ok, log = dsu.do_apply(self.folder, 14336, 16303)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), first)
        # And the second run must not have overwritten the backup with the
        # patched file it found in place.
        self.assertEqual(dsu.md5_file(os.path.join(self.folder, dsu.BACKUP_EXE)),
                         VANILLA_MD5)

    def test_changing_the_budget_rebuilds_from_the_backup(self):
        dsu.do_apply(self.folder, 14336, 16303)
        ok, log = dsu.do_apply(self.folder, 15360, 16303)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), FIXTURES[(15360, 16303)])

    def test_revert_refuses_a_backup_that_is_not_vanilla(self):
        dsu.do_apply(self.folder, 14336, 16303)
        backup = os.path.join(self.folder, dsu.BACKUP_EXE)
        patched = dsu.md5_file(self.exe)
        shutil.copy2(self.exe, backup)      # a patched file posing as the backup
        ok, log = dsu.do_revert(self.folder)
        self.assertFalse(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), patched, "ds.exe must be untouched")
        self.assertTrue(os.path.isfile(backup), "a suspect backup must not be deleted")

    def test_revert_without_a_backup_changes_nothing(self):
        ok, log = dsu.do_revert(self.folder)
        self.assertFalse(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), VANILLA_MD5)

    def test_revert_clears_dated_backups_left_by_older_versions(self):
        dsu.do_apply(self.folder, 14336, 16303)
        stale = os.path.join(self.folder, "settings.cfg.20260907_113000.bak")
        shutil.copy2(self.cfg, stale)
        ok, _log = dsu.do_revert(self.folder)
        self.assertTrue(ok)
        self.assertEqual(self._leftovers(), [])

    def test_apply_survives_a_missing_cfg(self):
        os.remove(self.cfg)
        ok, log = dsu.do_apply(self.folder, 14336, 16303)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), FIXTURES[(14336, 16303)])
        self.assertTrue(any("WARNING" in line for line in log))

    def test_verify_reads_the_installed_values_back(self):
        dsu.do_apply(self.folder, 14336, 16303)
        ok, log = dsu.do_verify(self.folder)
        text = "\n".join(log)
        self.assertTrue(ok, text)
        self.assertIn("14336 MB", text)
        self.assertIn("16303 MB", text)
        self.assertIn("level 0", text)

    def test_verify_says_plainly_when_nothing_is_patched(self):
        ok, log = dsu.do_verify(self.folder)
        text = "\n".join(log)
        self.assertFalse(ok)
        self.assertIn("NOT PATCHED", text)
        self.assertIn("apply", text, "it has to say what to run")

    def test_verify_calls_a_healthy_patch_healthy(self):
        dsu.do_apply(self.folder, 14336, 16303)
        ok, log = dsu.do_verify(self.folder)
        text = "\n".join(log)
        self.assertTrue(ok, text)
        self.assertIn("PATCHED and healthy", text)
        self.assertNotIn("PROBLEM", text)

    def test_verify_diagnoses_a_cfg_the_game_reset(self):
        # The game rewrites settings.cfg in full on any graphics change, which
        # silently drops the budget back to stock while the exe stays patched.
        # This is the single most likely thing to happen to a user, so it has
        # to name itself and say how to fix it.
        dsu.do_apply(self.folder, 14336, 16303)
        with open(self.cfg, "rb") as fh:
            raw = fh.read()
        with open(self.cfg, "wb") as fh:
            fh.write(raw.replace(b'"14336"', b'"3072"'))
        ok, log = dsu.do_verify(self.folder)
        text = "\n".join(log)
        self.assertTrue(ok, "the exe is still patched")
        self.assertIn("PROBLEM", text)
        self.assertIn("settings.cfg", text)
        self.assertIn("apply --mb 14336", text, "it has to give the exact fix")
        self.assertIn("OK", text, "the sites that are fine must still read OK")

    def test_verify_detail_adds_the_raw_numbers(self):
        dsu.do_apply(self.folder, 14336, 16303)
        _ok, plain = dsu.do_verify(self.folder)
        _ok, full = dsu.do_verify(self.folder, detail=True)
        self.assertNotIn(FIXTURES[(14336, 16303)], "\n".join(plain))
        self.assertIn(FIXTURES[(14336, 16303)], "\n".join(full))

    def test_apply_tells_you_what_to_do_next(self):
        _ok, log = dsu.do_apply(self.folder, 14336, 16303)
        text = "\n".join(log)
        low = text.lower()
        self.assertIn("load a save", low, "it has to say what to do next")
        self.assertIn("real budget", low, "and how to check it actually worked")
        self.assertNotIn("md5", low, "hashes belong in verify --detail, not here")
        self.assertLess(len(log), 18, "this is the wall of text it used to be")

    def test_the_menu_only_offers_what_the_state_allows(self):
        # Vanilla: patching is the point, and there is nothing to undo yet.
        verbs = [a[1] for a in dsu._menu_actions(self.folder, 15995, 15227, 2560, 1440)]
        self.assertIn("apply", verbs)
        self.assertNotIn("revert", verbs, "no backup exists yet")
        self.assertNotIn("measure", verbs, "nothing is patched to measure")

        dsu.do_apply(self.folder, 14336, 16303)

        # Patched: no second 'apply', and undo becomes available.
        verbs = [a[1] for a in dsu._menu_actions(self.folder, 15995, 15227, 2560, 1440)]
        self.assertNotIn("apply", verbs, "it is already patched")
        self.assertIn("measure", verbs)
        self.assertIn("revert", verbs)
        self.assertIn("fit", verbs)

    def test_the_menu_never_proposes_lowering_a_working_install(self):
        # Matching the options screen's two figures is a reasonable theory and
        # an unmeasured one. Nagging someone to drop a budget that already
        # works would be acting on it.
        # Installed above what the card would suggest, which is the
        # case where the old code pressed for a downgrade.
        dsu.do_apply(self.folder, 15360, 16303)
        self.assertLess(dsu.recommend(15227), 15360, "premise of the test")
        verbs = [a[0] for a in dsu._menu_actions(self.folder, 15995, 15227, 2560, 1440)]
        self.assertFalse([v for v in verbs if v.startswith("Raise the budget")],
                         "offered a budget change downward: %s" % verbs)

    def test_the_menu_does_offer_a_genuine_increase(self):
        dsu.do_apply(self.folder, 8192, 16303)
        verbs = [a[0] for a in dsu._menu_actions(self.folder, 15995, 15227, 2560, 1440)]
        self.assertTrue([v for v in verbs if v.startswith("Raise the budget")],
                        "an increase is worth offering: %s" % verbs)

    def test_the_menu_leads_with_fixing_a_reset_cfg(self):
        dsu.do_apply(self.folder, 14336, 16303)
        with open(self.cfg, "rb") as fh:
            raw = fh.read()
        with open(self.cfg, "wb") as fh:
            fh.write(raw.replace(b'"14336"', b'"3072"'))
        first = dsu._menu_actions(self.folder, 15995, 15227, 2560, 1440)[0]
        self.assertIn("settings.cfg", first[0])
        self.assertEqual(first[1], "apply --mb 14336")

    def test_installed_budget_reads_the_patched_value_back(self):
        self.assertIsNone(dsu.installed_budget(self.folder), "nothing patched yet")
        dsu.do_apply(self.folder, 14336, 16303)
        self.assertEqual(dsu.installed_budget(self.folder), 14336)

    def test_a_corrupt_exe_is_a_message_not_a_traceback(self):
        # A ds.exe cut short by an interrupted download used to reach the user
        # as struct.error, which is not a ValueError and so escaped every
        # except in the call chain.
        broken = b"MZ" + bytes(58) + bytes([0x40, 0, 0, 0]) + b"PE" + bytes(10)
        with open(self.exe, "wb") as fh:
            fh.write(broken)
        with self.assertRaises(ValueError):
            dsu.PE(broken)
        state, reason, _pe, _sites = dsu.read_state(self.exe)
        self.assertEqual(state, dsu.UNKNOWN)
        self.assertTrue(reason)
        ok, log = dsu.do_verify(self.folder)
        self.assertFalse(ok)
        self.assertIn("UNRECOGNISED", chr(10).join(log))
        ok, log = dsu.do_apply(self.folder, 14208, 16384)
        self.assertFalse(ok, chr(10).join(log))

    def test_garbage_in_place_of_the_exe_never_raises(self):
        junk_samples = [b"", bytes([0, 255]) * 300, b"not an exe" * 40,
                        b"MZ", b"MZ" + bytes([0xCC]) * 500]
        for junk in junk_samples:
            with open(self.exe, "wb") as fh:
                fh.write(junk)
            dsu.read_state(self.exe)
            dsu.do_verify(self.folder)
            ok, _log = dsu.do_apply(self.folder, 14208, 16384)
            self.assertFalse(ok, "patched %d bytes of junk" % len(junk))

    def test_plan_refuses_bad_values_even_from_inside(self):
        # The command line validates too, but the guard has to live here: the
        # menu and the tests reach plan() without going through argparse.
        with open(VANILLA, "rb") as fh:
            pe = dsu.PE(fh.read())
        sites, _err = dsu.locate(pe)
        for mb, vram, bias in ((0, 16384, 0.0), (14208, 0, 0.0),
                               (14208, 16384, 5.0)):
            edits, err = dsu.plan(pe, sites, mb, vram, bias)
            self.assertIsNone(edits)
            self.assertTrue(err)

    def test_apply_and_revert_survive_ten_rounds(self):
        # Backups get made, checked, restored and deleted every cycle. Byte
        # identity has to hold on all of them, not just the first.
        with open(self.cfg, "rb") as fh:
            cfg0 = fh.read()
        for i in range(10):
            mb = 8192 + i * 128
            ok, log = dsu.do_apply(self.folder, mb, 16384)
            self.assertTrue(ok, "round %d: %s" % (i, chr(10).join(log)))
            self.assertEqual(dsu.installed_budget(self.folder), mb)
            ok, log = dsu.do_revert(self.folder)
            self.assertTrue(ok, "round %d: %s" % (i, chr(10).join(log)))
            self.assertEqual(dsu.md5_file(self.exe), VANILLA_MD5, "round %d" % i)
            with open(self.cfg, "rb") as fh:
                self.assertEqual(fh.read(), cfg0, "round %d" % i)
            self.assertEqual(self._leftovers(), [], "round %d" % i)

    def test_clean_folder_accepts_how_people_actually_type_a_path(self):
        # Dragging a folder onto a console pastes it quoted; plenty of people
        # point at ds.exe instead of the folder; some pick the library folder
        # that contains the game. All three have to land on the same place.
        want = dsu._tidy(self.folder)
        for raw in (self.folder,
                    '"%s"' % self.folder,
                    "'%s'" % self.folder,
                    "  %s  " % self.folder,
                    self.folder + os.sep,
                    os.path.join(self.folder, "ds.exe"),
                    os.path.join(self.folder, "DS.EXE"),
                    os.path.dirname(self.folder)):
            self.assertEqual(dsu.clean_folder(raw), want, "failed on %r" % raw)

    def test_clean_folder_refuses_what_is_not_the_game(self):
        for raw in ("", "   ", '""', os.path.dirname(tempfile.gettempdir()),
                    os.path.join(self.folder, "settings.cfg"),
                    "Z:" + os.sep + "no" + os.sep + "such" + os.sep + "place"):
            self.assertIsNone(dsu.clean_folder(raw), "accepted %r" % raw)

    def test_ask_for_folder_quits_on_an_empty_answer(self):
        # A closed stdin reads as empty, which has to mean quit rather than
        # loop forever asking a question nobody can answer.
        saved = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            self.assertIsNone(dsu.ask_for_folder())
        finally:
            sys.stdin = saved

    def test_ask_for_folder_retries_then_takes_a_good_path(self):
        saved = sys.stdin
        sys.stdin = io.StringIO("nonsense" + chr(10) + self.folder + chr(10))
        try:
            self.assertEqual(dsu.ask_for_folder(), dsu._tidy(self.folder))
        finally:
            sys.stdin = saved

    def test_no_temporary_files_are_left_behind(self):
        dsu.do_apply(self.folder, 14336, 16303)
        self.assertEqual([f for f in os.listdir(self.folder) if f.endswith(".tmp")], [])


class TestTheCommandLineAcceptsLangAnywhere(unittest.TestCase):

    def test_lang_is_accepted_after_the_subcommand(self):
        # The README says --lang works on any of them. argparse only sees the
        # flags a subparser declares, so `verify --lang es` died with
        # "unrecognized arguments" while `--lang es verify` worked. Every
        # command is checked here, including measure, which is the one that
        # does not go through the shared --game helper.
        empty = tempfile.mkdtemp(prefix="dsdc_lang_")
        saved = dsu.LANG
        extra = {"fit": ["--required", "15.9", "--available", "14.9"],
                 "apply": ["--dry-run"]}
        try:
            for cmd in ("status", "apply", "revert", "verify", "fit", "measure"):
                argv = [cmd, "--lang", "es"] + extra.get(cmd, [])
                if cmd != "measure":
                    argv += ["--game", empty]
                noise = io.StringIO()
                try:
                    with contextlib.redirect_stdout(noise), \
                            contextlib.redirect_stderr(noise):
                        dsu.main(argv)
                except SystemExit as exc:
                    self.assertNotEqual(exc.code, 2, "%s rejected --lang:\n%s"
                                        % (cmd, noise.getvalue()))
        finally:
            dsu.LANG = saved
            shutil.rmtree(empty, ignore_errors=True)


# ==========================================================================
# The per-frame arena. A separate patch on a separate field of the same
# engine object, so most of what is worth proving is that it does NOT
# interact with the streaming patch in either direction.
# ==========================================================================

class TestFrameArenaNumbers(unittest.TestCase):
    """No game file needed."""

    def test_the_bounds_are_enforced(self):
        self.assertIsNone(dsu.check_arena(dsu.STOCK_ARENA_MB))
        self.assertIsNone(dsu.check_arena(dsu.DEFAULT_ARENA_MB))
        self.assertIsNone(dsu.check_arena(dsu.MAX_ARENA_MB))
        for bad in (0, -1, 95, dsu.MAX_ARENA_MB + 1, 4096):
            with self.subTest(mb=bad):
                self.assertIsNotNone(dsu.check_arena(bad))

    def test_the_ceiling_stays_clear_of_the_sign_extension(self):
        """`mov r/m64, imm32` sign-extends, so 2048 MB would arrive negative.
        The ceiling has to stay below that with room to spare."""
        self.assertLess(dsu.MAX_ARENA_MB, dsu.ARENA_IMM_MAX_MB)
        self.assertLess(dsu.MAX_ARENA_MB * 1024 * 1024, 0x80000000)

    def test_check_values_rejects_a_bad_arena_too(self):
        self.assertIsNone(dsu.check_values(14336, 16303, 0.0, 192))
        self.assertIsNotNone(dsu.check_values(14336, 16303, 0.0, 4096))
        # ...and says nothing about it when it is not being touched.
        self.assertIsNone(dsu.check_values(14336, 16303, 0.0, None))


@needs_exe
class TestFrameArenaAgainstTheRealExecutable(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(VANILLA, "rb") as fh:
            cls.data = fh.read()

    def test_the_site_is_found_exactly_once_and_reads_the_stock_size(self):
        off, err = dsu.arena_site(self.data)
        self.assertIsNone(err)
        self.assertEqual(off, 0x1999AA3, "the measured file offset")
        self.assertEqual(dsu.arena_from_exe(self.data), dsu.STOCK_ARENA_MB)
        self.assertEqual(dsu.arena_pair(self.data),
                         (dsu.STOCK_ARENA_MB, dsu.STOCK_ARENA_MB))

    def test_the_template_carries_the_arena_size_too(self):
        """The finding that made the first attempt useless: the engine copies
        32 bytes of template over [rcx+0x48], which lands on the assumed VRAM
        AND on the arena size, undoing what the constructor just stored."""
        pe = dsu.PE(self.data)
        sites, _err = dsu.locate(pe)
        vram_at = sites["vram_template"][0]
        arena_at = sites["arena_template"][0]
        self.assertEqual(arena_at - vram_at, 8, "they are adjacent qwords")
        self.assertEqual(
            struct.unpack_from("<Q", self.data, vram_at)[0], 6144 * 1024 * 1024)
        self.assertEqual(
            struct.unpack_from("<Q", self.data, arena_at)[0],
            dsu.STOCK_ARENA_MB * 1024 * 1024)

    def test_both_writers_are_patched_because_one_is_not_enough(self):
        """Patching only the constructor immediate was measured in a running
        game and changed nothing: the template overwrote it. Either both move
        or the patch is a no-op that looks applied."""
        out, _e, err = dsu.build(self.data, 14336, 16303, 0.0, 192)
        self.assertIsNone(err)
        ctor, tpl = dsu.arena_pair(out)
        self.assertEqual(ctor, 192, "the constructor immediate")
        self.assertEqual(tpl, 192, "the template the engine copies over it")

    def test_locate_reports_it_as_a_site(self):
        pe = dsu.PE(self.data)
        sites, err = dsu.locate(pe)
        self.assertIsNone(err)
        self.assertIn("arena_size", sites)
        self.assertEqual(sites["arena_size"][0], 0x1999AA3)

    def test_it_sits_six_bytes_before_the_assumed_vram(self):
        """Not decoration: the two are contiguous fields of the same object,
        and that adjacency is what makes one findable from the other."""
        pe = dsu.PE(self.data)
        sites, _err = dsu.locate(pe)
        self.assertEqual(sites["vram_code"][0] - sites["arena_size"][0], 6)

    def test_leaving_it_out_changes_nothing(self):
        """The whole point of the default. If this ever fails, every pinned
        MD5 in this file is wrong."""
        for (mb, vram), want in sorted(FIXTURES.items()):
            with self.subTest(mb=mb, vram=vram):
                out, edits, err = dsu.build(self.data, mb, vram, 0.0, None)
                self.assertIsNone(err)
                self.assertEqual(len(edits), 10)
                self.assertEqual(dsu.md5_bytes(out), want)

    def test_asking_for_it_adds_two_sites_and_touches_only_those_fields(self):
        plain, _e, _err = dsu.build(self.data, 14336, 16303)
        big, edits, err = dsu.build(self.data, 14336, 16303, 0.0, 192)
        self.assertIsNone(err)
        self.assertEqual(len(edits), 12, "the constructor immediate and the template")
        self.assertEqual(len(big), len(self.data))

        # Counting changed bytes is the wrong test: 96 MB and 192 MB differ in
        # ONE byte, both being whole multiples of 16 MB with three zero bytes
        # below. What matters is that nothing outside the two fields moves.
        pe = dsu.PE(self.data)
        sites, _err2 = dsu.locate(pe)
        ctor = sites["arena_size"][0]
        tpl = sites["arena_template"][0]
        allowed = set(range(ctor, ctor + 4)) | set(range(tpl, tpl + 8))
        moved = [i for i, (a, b) in enumerate(zip(plain, big)) if a != b]
        self.assertTrue(moved, "something must have changed")
        self.assertTrue(set(moved) <= allowed,
                        "only the two arena fields may move, got %r" % moved)
        self.assertEqual(dsu.arena_from_exe(big), 192)

    def test_a_size_that_is_not_a_round_multiple_still_round_trips(self):
        """Guards the test above from being vacuous: 200 MB moves more than
        one byte, so the four-byte field really is being written whole."""
        out, _e, err = dsu.build(self.data, 14336, 16303, 0.0, 200)
        self.assertIsNone(err)
        self.assertEqual(dsu.arena_from_exe(out), 200)
        plain, _e2, _err2 = dsu.build(self.data, 14336, 16303)
        moved = sum(1 for a, b in zip(plain, out) if a != b)
        self.assertGreater(moved, 1)

    def test_the_stock_size_round_trips(self):
        same, _e, err = dsu.build(self.data, 14336, 16303, 0.0, dsu.STOCK_ARENA_MB)
        self.assertIsNone(err)
        self.assertEqual(dsu.md5_bytes(same), FIXTURES[(14336, 16303)],
                         "writing the stock size back must land on the plain build")

    def test_every_size_reads_back_as_itself(self):
        for mb in (96, 128, 192, 256, 384, 512):
            with self.subTest(mb=mb):
                out, _e, err = dsu.build(self.data, 14336, 16303, 0.0, mb)
                self.assertIsNone(err)
                self.assertEqual(dsu.arena_from_exe(out), mb)

    def test_the_anchor_still_finds_it_after_it_has_been_written(self):
        """The reason it is not located by its own value-bearing pattern: that
        pattern stops matching the moment this patch is applied."""
        out, _e, _err = dsu.build(self.data, 14336, 16303, 0.0, 192)
        self.assertEqual(out.count(dsu.PAT_ARENA_ANCHOR), 1)
        off, err = dsu.arena_site(out)
        self.assertIsNone(err)
        self.assertEqual(off, 0x1999AA3)

    def test_an_arena_only_file_stays_fully_locatable(self):
        """The independence requirement, stated as bytes: raising the arena on
        an otherwise stock exe must not blind the rest of the tool."""
        pe = dsu.PE(self.data)
        sites, _err = dsu.locate(pe)
        only = bytearray(self.data)
        off = sites["arena_size"][0]
        tpl = sites["arena_template"][0]
        only[off:off + 4] = struct.pack("<I", 192 * 1024 * 1024)
        only[tpl:tpl + 8] = struct.pack("<Q", 192 * 1024 * 1024)
        only = bytes(only)

        sites2, err = dsu.locate(dsu.PE(only))
        self.assertIsNone(err, "locate() must survive an arena-only patch")
        self.assertEqual(dsu.arena_from_exe(only), 192)
        # And the streaming patch must still apply cleanly on top of it.
        out, edits, err = dsu.build(only, 14336, 16303)
        self.assertIsNone(err)
        self.assertEqual(len(edits), 10)
        self.assertEqual(dsu.arena_from_exe(out), 192, "and must not undo it")

    def test_refuses_when_the_anchor_is_disturbed(self):
        broken = bytearray(self.data)
        at = broken.find(dsu.PAT_ARENA_ANCHOR)
        broken[at + 1] ^= 0xFF
        off, err = dsu.arena_site(bytes(broken))
        self.assertIsNone(off)
        self.assertIsNotNone(err, "must refuse rather than guess an offset")

    def test_refuses_when_the_store_opcode_is_not_there(self):
        """A coincidental anchor must not be allowed to point four bytes at
        whatever happens to sit 0x12 before it."""
        broken = bytearray(self.data)
        off, _err = dsu.arena_site(self.data)
        broken[off - 4] ^= 0xFF          # break the mov, leave the anchor
        off2, err = dsu.arena_site(bytes(broken))
        self.assertIsNone(off2)
        self.assertIsNotNone(err)

    def test_a_second_anchor_is_treated_as_none(self):
        doubled = bytearray(self.data)
        spare = doubled.find(b"\x00" * 64, len(doubled) // 2)
        self.assertGreater(spare, 0)
        doubled[spare:spare + len(dsu.PAT_ARENA_ANCHOR)] = dsu.PAT_ARENA_ANCHOR
        off, err = dsu.arena_site(bytes(doubled))
        self.assertIsNone(off, "ambiguity is a refusal, not a coin flip")
        self.assertIsNotNone(err)


@needs_exe
class TestFrameArenaContract(unittest.TestCase):
    """do_arena on a scratch folder: it never touches a real installation."""

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="dsdc_arena_")
        self.exe = os.path.join(self.folder, "ds.exe")
        self.cfg = os.path.join(self.folder, "settings.cfg")
        shutil.copy2(VANILLA, self.exe)
        with open(self.cfg, "wb") as fh:
            fh.write(SAMPLE_CFG)

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def _leftovers(self):
        return sorted(f for f in os.listdir(self.folder)
                      if f not in ("ds.exe", "settings.cfg"))

    def test_it_backs_up_before_it_writes(self):
        ok, log = dsu.do_arena(self.folder, 192)
        self.assertTrue(ok, "\n".join(log))
        backup = os.path.join(self.folder, dsu.BACKUP_EXE)
        self.assertTrue(os.path.isfile(backup))
        self.assertEqual(dsu.md5_file(backup), VANILLA_MD5)
        with open(self.exe, "rb") as fh:
            self.assertEqual(dsu.arena_from_exe(fh.read()), 192)

    def test_it_is_idempotent(self):
        dsu.do_arena(self.folder, 192)
        first = dsu.md5_file(self.exe)
        ok, log = dsu.do_arena(self.folder, 192)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), first)

    def test_the_stock_size_puts_it_back(self):
        dsu.do_arena(self.folder, 256)
        ok, log = dsu.do_arena(self.folder, dsu.STOCK_ARENA_MB)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), VANILLA_MD5)

    def test_it_refuses_a_size_out_of_range_and_writes_nothing(self):
        before = dsu.md5_file(self.exe)
        ok, log = dsu.do_arena(self.folder, 4096)
        self.assertFalse(ok)
        self.assertEqual(dsu.md5_file(self.exe), before)
        self.assertEqual(self._leftovers(), [], "a refusal must not leave a backup")

    def test_revert_takes_the_arena_with_it(self):
        dsu.do_arena(self.folder, 192)
        ok, log = dsu.do_revert(self.folder)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), VANILLA_MD5)
        self.assertEqual(self._leftovers(), [])

    def test_the_two_patches_do_not_disturb_each_other(self):
        """Either order, same file. This is the independence claim, end to end."""
        dsu.do_apply(self.folder, 14336, 16303)
        ok, log = dsu.do_arena(self.folder, 192)
        self.assertTrue(ok, "\n".join(log))
        streaming_then_arena = dsu.md5_file(self.exe)

        shutil.copy2(VANILLA, self.exe)
        for leftover in self._leftovers():
            os.remove(os.path.join(self.folder, leftover))
        with open(self.cfg, "wb") as fh:
            fh.write(SAMPLE_CFG)

        dsu.do_arena(self.folder, 192)
        ok, log = dsu.do_apply(self.folder, 14336, 16303)
        self.assertTrue(ok, "\n".join(log))
        self.assertEqual(dsu.md5_file(self.exe), streaming_then_arena,
                         "the order the two patches are applied in must not matter")

    def test_apply_keeps_an_arena_that_is_already_set(self):
        """apply restores from the backup before patching, which would wipe
        the arena unless it is deliberately carried across."""
        dsu.do_arena(self.folder, 256)
        ok, log = dsu.do_apply(self.folder, 14336, 16303)
        self.assertTrue(ok, "\n".join(log))
        with open(self.exe, "rb") as fh:
            self.assertEqual(dsu.arena_from_exe(fh.read()), 256)

    def test_apply_can_change_it_on_purpose(self):
        dsu.do_arena(self.folder, 256)
        ok, log = dsu.do_apply(self.folder, 14336, 16303, arena_mb=128)
        self.assertTrue(ok, "\n".join(log))
        with open(self.exe, "rb") as fh:
            self.assertEqual(dsu.arena_from_exe(fh.read()), 128)

    def test_re_applying_streaming_twice_does_not_drift(self):
        dsu.do_arena(self.folder, 192)
        dsu.do_apply(self.folder, 14336, 16303)
        once = dsu.md5_file(self.exe)
        dsu.do_apply(self.folder, 14336, 16303)
        self.assertEqual(dsu.md5_file(self.exe), once)

    def test_a_plain_apply_patches_both_things(self):
        """Patching is one action from the user's side. A bare apply through
        the command layer has to cover the arena too, not leave it as a second
        errand."""
        arena = dsu.arena_to_use(self.folder)
        self.assertEqual(arena, dsu.DEFAULT_ARENA_MB)
        ok, log = dsu.do_apply(self.folder, 14336, 16303, arena_mb=arena)
        self.assertTrue(ok, "\n".join(log))
        with open(self.exe, "rb") as fh:
            self.assertEqual(dsu.arena_pair(fh.read()),
                             (dsu.DEFAULT_ARENA_MB, dsu.DEFAULT_ARENA_MB))

    def test_a_size_already_chosen_is_not_quietly_shrunk(self):
        dsu.do_arena(self.folder, 384)
        self.assertEqual(dsu.arena_to_use(self.folder), 384,
                         "re-running apply must not drop 384 back to the default")

    def test_the_stock_size_can_still_be_asked_for_explicitly(self):
        self.assertEqual(dsu.arena_to_use(self.folder, dsu.STOCK_ARENA_MB),
                         dsu.STOCK_ARENA_MB, "that is how you decline it")
        dsu.do_arena(self.folder, 384)
        self.assertEqual(dsu.arena_to_use(self.folder, 128), 128,
                         "an explicit ask beats what is installed")

    def test_verify_reports_an_arena_only_file_honestly(self):
        dsu.do_arena(self.folder, 192)
        _ok, log = dsu.do_verify(self.folder, [])
        text = "\n".join(log)
        self.assertNotIn("This is the stock ds.exe", text,
                         "it is not stock: the arena has been raised")
        self.assertIn("192", text)


if __name__ == "__main__":
    if VANILLA:
        print("vanilla: %s\n" % VANILLA)
    else:
        print("no vanilla ds.exe, byte-identity tests will skip\n")
    unittest.main(verbosity=2)
