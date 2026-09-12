# DSDC Streaming Memory Unlock

Death Stranding Director's Cut only ever gives its texture streamer 3072 MB,
no matter how much VRAM you have. This raises that, by patching twelve sites
of your own `ds.exe`.

I wrote it for a texture mod. At 3072 MB the streamer throws textures out
about as fast as it loads them, so the mod kept getting *worse* the more I put
into it. This is what came out of working out why.

> Not affiliated with Kojima Productions, 505 Games or Sony.
> No game files are redistributed: this patches the `ds.exe` you already have,
> after backing it up. No warranty, and modifying a game executable is your
> own risk.

## Use it

[**Download the ZIP**](https://github.com/PlushRapier145/dsdc-streaming-unlock/releases/latest/download/dsdc-streaming-unlock.zip),
extract it, double-click `RUN_ME.cmd`.

It finds the game, reads your card, and shows a menu. Nothing is written until
you pick something and confirm. Close the game first.

Don't double-click the `.py` directly. Whether that works depends on a file
association you may not have, and on a normal Python install it runs through
`py.exe`, which makes the window close before you can read it. `RUN_ME.cmd`
just finds a Python and starts the script.

You need **Python 3.8 or newer** ([python.org](https://www.python.org/downloads/),
tick "Add python.exe to PATH"). Nothing else, no `pip install`.

## The trap you need to know about

You cannot get this by editing `settings.cfg`. Four separate things stop you,
and the fourth is the one that costs people days.

When the engine stores the budget it also derives a **mip bias** from the same
number:

```
factor = min(1.0, 1.0 - (mb - 1536) / 1280.0)
```

That gets truncated to an integer and used as a mip level bias. The engine's
own range is 1536 MB → +1, 2816 → 0, 4096 → −1. Push the budget up without
touching it and you get **−4 at 8192 MB, −7 at 12288**. A bias of −7 pins mip 0
on everything at any distance. The streamer can't possibly keep up, so it
thrashes, and your textures end up blurrier than stock and get worse the more
you add.

This script rewrites the divisor so the bias lands on 0, which is the engine's
own neutral. There's no flag to skip it. Raising the budget without this is a
downgrade, not an upgrade.

The other three: the "High" preset asks for 3072 and the setter clamps
anything over 4096; the MB→bytes conversion runs in a 32-bit register so
4096 MB and up become zero and fall to a 1536 MB floor; and the engine never
asks your card anything, assuming a flat 6144 MB from two places in the
binary. `docs/how-it-works.md` has the disassembly if you want it.

## What you actually get

Read out of the running process, not estimated:

| assumed VRAM | asked for | got |
|---|---|---|
| 6144 (stock) | 3072 (stock) | 3072 MB |
| 6144 (stock) | 4095 | 3968 MB. The old "4095" patch never gave 4095 |
| 6144 (stock) | 12288 | 2816 MB, *worse than stock* |
| 14336 | 12288 | 11904 MB |
| 16384 | 14336 | 13440 MB |

The engine always hands out less than you ask for, and no formula I tried fits
all of those. Don't trust a predicted number. Load a save and read the real
one from the menu, or:

```
python dsdc_streaming_unlock.py measure
```

That opens the running game read-only through `ReadProcessMemory`. Nothing is
injected or installed.

## Commands

Every menu item is also a subcommand, if you'd rather type.

| | |
|---|---|
| `apply` | patch everything, sized from your card. `--mb` and `--vram` to override |
| `verify` | what's actually installed, and what's wrong if anything is |
| `measure` | the real budget, from the running game |
| `fit` | match the two figures in the game's own options screen |
| `arena` | change just the per-frame arena, without re-running `apply` |
| `revert` | put everything back |

Add `--help` to any of them. `--lang en` or `--lang es` forces the language;
by default it follows Windows.

Budgets want to be **multiples of 128 MB**. The last thing the engine does is
`and rbx, 0xFFFFFFFFF8000000`, which rounds down. Ask for 4095, get 3968.

## The other ceiling: 96 MB per frame

If the game has ever died on you in a mirror, or with a mod that pushes draw
distance out, this is why.

The engine builds every frame inside a fixed 96 MB block. When something runs
past the end it does not drop anything, it kills the process. A crash log
naming `mov dword ptr [0], 0xDEADCA7` is that, not corrupted memory.

`apply` raises it to 192 MB along with everything else. It costs that much
ordinary system RAM, no video memory.

192 MB is the size this was measured at. To skip it, or to put it back later:

```
python dsdc_streaming_unlock.py apply --arena 96    # leave it alone
python dsdc_streaming_unlock.py arena  --mb 96      # change only this, later
```

`revert` removes everything. `docs/how-it-works.md` has the disassembly.

## Undoing it

`revert`, from the menu or the command line. It restores `ds.exe` and
`settings.cfg` and deletes its own backups.

It checks the backup really is an unpatched `ds.exe` *before* restoring, and
compares MD5s after. If they don't match it deletes nothing and tells you,
because at that point the backup is the only thing saving your install.

Nothing is written outside the game folder. No registry, no `%AppData%`. If
you lose the backup, Steam's "Verify integrity of game files" will fetch a
clean `ds.exe`.

## What quietly undoes it

**Steam's "Verify integrity of game files"** puts the stock `ds.exe` back with
no warning and no symptom. If the game looks worse than you remember, run
`verify` before blaming anything else.

Changing graphics options does not undo it. The game rewrites `settings.cfg`
whole when you touch them, but the patched executable writes the patched
budget back, so it survives.

## What it's been tested on

Steam, build `dsq 179 / 4027081`, vanilla MD5
`e379c9366feea0a4d235a54efe678a88`.

Every site is found by byte pattern, not by fixed offset, so it should survive
game updates while those sequences hold. If a pattern is missing, or turns up
more than once, it refuses to write anything rather than guess.

The Epic build and the base game (not Director's Cut) are untested rather than
unsupported. The patch works on bytes and doesn't care which store the game
came from, but nobody has run it there. Since it won't touch anything it
doesn't recognise, trying costs nothing.

## Tests

```
python -m unittest -v
```

Most of it runs without the game. An unpatched `ds.exe` is 86 MB and isn't
mine to hand out, so the tests that need one skip unless you point
`DSDC_VANILLA` at your own copy or drop it at `fixtures/ds.exe`. Those pin the
output to MD5s that were measured rather than computed.

The suite exists because it earned its place. Both bugs this patcher has ever
shipped were caught by comparing bytes against a build that had actually been
run: a code cave return jump landing one byte early, and a setter clamp pinned
at a flat value instead of scaling. Neither produced a warning, and neither
was visible by reading the code.

## Thanks

To [ShadelessFox](https://github.com/ShadelessFox), for building Decima
Workshop. It is what got me interested in making this and my texture mod in
the first place, and the patience, advice and guidance along the way are why
both exist.

## Licence

MIT, see [LICENSE](LICENSE). PlushRapier145.
