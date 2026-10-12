# Security model

A security plugin that is itself careless would be worse than none. This page
explains how Vigil is built, mapped to the points the Omarchy plugin
marketplace review checks. `tests/test_marketplace_rules.py` enforces the
mechanical ones.

## What runs where

| Part | Runs as | Does |
|---|---|---|
| `Panel.qml` + `Model.js` | you, inside `omarchy-shell` | Draws the shield and panel, starts the helper, validates its output, launches confirmed actions. |
| `bin/vigil` | you, as a child process | Reads local settings and returns one JSON report; performs the six helper actions. |
| Terminal actions | you, in a visible terminal; `sudo` for root steps | Constant scripts from `Model.js`, and Omarchy's own commands. |

Nothing from the plugin folder ever runs as root. There is no sudoers rule,
no polkit policy, no service, no timer and no daemon.

## Input is untrusted

- The helper's stdout is read in raw chunks (`SplitParser` with an empty
  marker) and stopped at 512 KiB; there is no `StdioCollector`. A deadline
  timer sends TERM, then KILL.
- `Model.parseReport` checks every field's type, range and length, rejects
  unknown statuses, categories, duplicate ids, non-integer weights, and
  tool directories other than `/usr/bin` and `/usr/share/omarchy/bin`. A
  report that does not match is rejected whole. Keys are looked up with
  `hasOwnProperty` and collected into `Object.create(null)` maps.
- Every `Text` sets `textFormat: Text.PlainText`. Strings passed to host
  components (tooltip, `PanelHero`, notifications) go through
  `Model.plain`, which removes `<`, `>`, `&`, control and bidi characters
  and caps the length. Notifications contain only a count.
- The IPC target exposes `open`, `close`, `show`, `hide`, `toggle` and
  `refresh`, none with parameters, and is registered only by the copy of the
  widget on the first monitor.

## Commands

- The helper runs only absolute paths, in a new session, with an empty
  environment apart from a fixed `PATH`, `HOME` and `LANG`, a deadline, and
  stdout read incrementally against a byte cap (cap + 1, overflow is a
  failure). Tools it relies on must be root-owned and not group- or
  world-writable, in root-owned directories.
- The panel starts the helper as
  `/usr/bin/python3 -I -S <plugin>/bin/vigil ...` with `clearEnvironment`.
  Helper actions are a closed list of ids, checked on both sides.
- Terminal actions are constant strings in `Model.js`. The report only names
  an action id; an id that is not in the table does nothing. Omarchy tools
  are addressed by absolute path, from one of the two trusted directories.
  Each script prints what it will do and waits for Enter before running.
  `tests/model.test.mjs` runs `bash -n` on every script.

## Files

- Reads open the file once with `O_NONBLOCK` (a planted FIFO cannot hang
  the check), `fstat` that descriptor for a regular file, and read at most
  the cap + 1 bytes from it. Files in `/etc`, `/proc`, `/var` and Vigil's
  own state are opened with `O_NOFOLLOW`. A few reads follow symlinks on
  purpose, with the same type and size limits: the files scanned for
  persistence and the environment files (dotfile managers symlink them, and
  refusing would let a hidden line escape the scan), `shell.json` (for the
  lock timeout), and sysfs entries (sysfs is made of symlinks). Nothing read
  is ever written back or executed.
- Writes (the state file and the opt-out file) walk from your home directory
  one component at a time with `O_NOFOLLOW`, refusing any component that is
  a symlink or not owned by you, then create an exclusive random temporary
  at its final mode, `fsync`, `rename` over the target and `fsync` the
  directory. A symlink planted at the target is replaced, not written
  through; tests plant one and check the victim file is untouched.
- Deletion (thumbnail cache) works relative to held directory descriptors
  and never follows a symlink. The opt-out file is removed only if its bytes
  are exactly what Vigil wrote.

## Network

The helper and panel make no network connections. Actions that do (package
installs, `freshclam`, `arch-audit`, `omarchy-update`) are started by you
and say so on their confirmation.

## Repository hygiene

No agent instruction files, no binaries, no file over 512 KiB, no NUL bytes,
one ID (`io.github.keasbeexd.vigil`) everywhere, versions in the manifest and
helper kept equal, MIT licence, and a Removing section in the README that
names every file Vigil can leave behind.

## Known limits

- Checks read configuration, not live kernel or firewall state that only
  root can see (for example `ufw status`). A check that cannot read
  something says "unknown"; it never assumes the safe answer.
- The startup-file scan is a heuristic. It finds common download-and-run and
  reverse-shell patterns, not obfuscated or novel ones.
- Vigil cannot prove a machine is not compromised. A compromised account can
  lie to any program running as that account, Vigil included.
