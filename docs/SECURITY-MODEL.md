# Security model

A security plugin that is itself careless would be worse than none. This page
explains how Vigil is built, mapped to the points the Omarchy plugin
marketplace review checks. `tests/test_marketplace_rules.py` enforces the
mechanical ones.

## Design rules

These hold for every pillar, now and in later phases:

1. **No root from the plugin.** Root steps are constant scripts from
   `Model.js` (or two constant argvs in the helper), shown in full on a
   confirmation in the panel, then run through `pkexec`, so Omarchy's own
   polkit dialog asks for your password each time. Tools that ask questions
   as they go are Omarchy's own commands in a visible terminal. No root
   helper, sudoers rule, polkit policy, service or timer, ever.
2. **Everything Vigil reads is untrusted**, including its own helper's output,
   other tools' result files and file names (a file name is chosen by whoever
   created the file). It is size-capped, validated and shown as plain text,
   never put into a command or a notification.
3. **Virus scans run as you.** ClamAV scans (Vigil's quick scan and ClamUI)
   never run as root: malware scanners have had parser bugs, and running
   them unprivileged limits what a malicious file can do. The one check
   that needs root, accounts without a password, runs only in a Full scan
   you start, and keeps only account names.
4. **Hand off, don't absorb.** ClamUI keeps quarantine, Bumblebee keeps its
   catalog, Black Ops keeps telemetry blocking. Vigil reads their results and
   opens them; it does not run their code or write their files.
5. **Maintained sources, never executed.** Vigil keeps no threat lists. Data
   comes from the tools of the people who maintain it (arch-audit,
   osv-scanner, ClamAV's freshclam) and one fixed AUR lookup, once a week
   (the `autoUpdate` setting) or when you press Update sources or Full scan. Nothing fetched is
   ever run; results are size-capped and validated like any other input.
6. **Nothing automatic.** Every change is confirmed; notifications carry
   counts only; IPC methods take no parameters.
7. **Removal leaves nothing running.** No units, cron jobs or daemons;
   leftover files are listed in the README.

## What runs where

| Part | Runs as | Does |
|---|---|---|
| `Panel.qml` + `Model.js` | you, inside `omarchy-shell` | Draws the shield and panel, starts the helper, validates its output, launches confirmed actions. |
| `bin/vigil` | you, as a child process | Reads local settings and returns one JSON report; performs the six helper actions. |
| Script actions | root through `pkexec` (Omarchy's password dialog), or you | Constant scripts from `Model.js`, shown on a confirmation first; what they print is shown in the panel. |
| Terminal actions | you, in a visible terminal | Omarchy's own interactive commands, and choosing an SSH passphrase. |
| App actions | you | Open ClamUI with a fixed argv: `/usr/bin/clamui`, or `/usr/bin/flatpak run io.github.linx_systems.ClamUI`. |

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
- Script actions run as `pkexec /usr/bin/env HOME=<your home> /usr/bin/bash
  -c <script>` for root steps, or `/usr/bin/bash -c <script>` as you, with
  a fixed, minimal environment. The script is the constant from `Model.js`
  with its `sudo` prefixes removed; nothing from the report or a file
  reaches it. Steps that would wait for input are not allowed (a test
  checks), and `ufw` runs with `--force` so it never prompts.
- Update sources updates ClamAV's signatures only when you press it (the
  weekly run never asks), with one constant root script through pkexec: if
  ClamAV's update service runs, it is woken with `systemctl kill
  --signal=SIGUSR1` (it then checks at once; a second freshclam would fail
  on the service's log lock), and the script waits up to two minutes for the
  service's journal to report the result; otherwise it runs freshclam.
- Programs Vigil runs must be trusted files, never links. `/usr/bin/python3`
  is a link on Arch, so for Bumblebee's scanner Vigil resolves it and runs
  the target only if it is a trusted `python3.X` file in `/usr/bin`.
- Terminal actions are constant strings in `Model.js`. The report only names
  an action id; an id that is not in the table does nothing. Omarchy tools
  are addressed by absolute path, from one of the two trusted directories.
  Each script prints what it will do and waits for Enter before running.
  `tests/model.test.mjs` runs `bash -n` on every script.
- **Learn more** opens a page with `xdg-open` (root-owned, in `/usr/bin`) as
  a two-element argv, no shell. The URL is a constant from the `DOCS` table
  in `Model.js`, chosen by id; any other id is dropped when the report is
  validated.
- The password check runs `pkexec /usr/bin/awk -F: '$2 == "" { print $1 }'
  /etc/shadow` from the helper, a constant argv (`NO_PASSWORD_ARGV`), only
  when you press Full scan, never in the weekly run. pkexec asks for your
  password through Omarchy's polkit agent, the same dialog Omarchy's own
  commands use. The output (account names only) is validated against the
  account-name pattern and written as you, mode 0600, to the state folder;
  the check keeps only names that also exist in `/etc/passwd`. Cancelling
  the dialog changes nothing and keeps the last result.
- The screen-lock fix runs Omarchy's own `omarchy-shell-config` helper
  (resolved from a trusted directory, no root) with a constant `jq` program,
  the way Omarchy's own commands edit `shell.json`.
- The one script that edits a shared file (Avahi) refuses unless the line
  appears exactly once under `[publish]`, keeps the first original, takes a
  rollback copy from `mktemp` in the same root-owned directory, and restores
  it if the edit does not verify or Avahi does not restart.
- Undo actions are constant scripts too. Each deletes a fixed path only if
  the file's first line is exactly Vigil's marker, read with `head -n 1` and
  compared as a whole string, so a file someone rewrote is left alone. The
  helper offers undo only for files whose first line it has itself read as
  the marker through an `O_NOFOLLOW` descriptor. `tests/model.test.mjs`
  runs every undo script against temporary files.
- Marking a finding as reviewed stores a fingerprint (check id plus a hash
  of its status) in the state file, so the review lasts while the finding
  stays the same kind; a worse status is a new fingerprint. For evidence
  checks (open ports, startup files, file changes, secrets, infected files,
  malicious, compromised or vulnerable packages, preload, AUR status, plugin
  capabilities) the hash also covers what was found, so a review cannot hide
  something new. Passing findings cannot be reviewed, and the panel rejects
  a report that claims one is. State updates hold an
  exclusive `flock` on the state directory's own descriptor, so a background
  check and a dismissal cannot overwrite each other.
- App actions map an id and an install kind reported by the helper
  (`native`, `flatpak` or nothing) to one of two fixed argv arrays. The
  helper reports `flatpak` only when `/usr/bin/flatpak` is root-owned and the
  ClamUI app directory exists.
- Other tools' results (Bumblebee's `last-scan.json`) are read through a
  descriptor walk from home with `O_NOFOLLOW` on every component, capped at
  64 KiB, and accepted only if `ok` is `true` and `exposure_count` is a
  non-negative integer. Vigil never writes there.

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

The weekly refresh (and **Update sources** or **Full scan**) is the only network use Vigil starts
by itself, and only once the relevant tool is installed:

- `arch-audit --json --upgradable` and `osv-scanner --format json
  --no-resolve --recursive -- <folders>` are root-owned system binaries, run
  with the helper's usual absolute path, empty environment, deadline and
  output cap. osv-scanner sends package names and versions, not files; git
  checkouts are not sent (its default).
- The AUR lookup is one `curl -q -sS --fail --proto =https --proto-redir
  =https --max-time 30 --max-filesize 4194304 -- <url>` to a fixed host,
  with package names checked against a strict pattern and percent-encoded.
  `tests/test_marketplace_rules.py` fails if any other network call appears.
- The virus scan runs `/usr/bin/nice -n 19 /usr/bin/clamscan --recursive
  --no-summary --stdout --cross-fs=no --follow-dir-symlinks=0
  --follow-file-symlinks=0 --exclude-dir=... -- ~` as you, never as root.
  Its output is read line by line: lines for clean files are only counted
  (for the progress bar) and dropped, and only `FOUND` lines are kept,
  within a byte cap. File names in them are chosen by whoever named the
  file, so they are cleaned, capped and shown as plain text, and never reach
  a command or notification.
- Results are parsed with byte caps and strict patterns, and only names,
  severities, IDs and counts are kept. A failed refresh keeps the last good
  result and retries after a day, so an offline machine is not hammered.

Actions you start yourself (package installs, ClamUI, `omarchy-update`)
say where they connect before they run.

## Reading other software

- File changes are checked against pacman's own records: each package's
  `mtree` in `/var/lib/pacman/local` is decompressed with a 32 MiB output
  cap, within a five-second budget, and a changed `/etc` file whose SHA-256
  matches what a package shipped is not reported.
- The plugin capability scan reads other plugins' files as text, at most 300
  files per plugin, 512 KiB per file, 8 MiB and three seconds in total,
  without following symlinks. It never loads, imports or runs them.
- The one exception to "never runs it": a Full scan you start asks
  Bumblebee to rescan by running Bumblebee's own scanner exactly as
  Bumblebee's service does, `/usr/bin/python3 <bumblebee>/bin/scan_bumblebee.py
  --force`, as you, with Vigil's cleaned environment and a five-minute limit.
  It is code that already runs as you every few hours, so nothing gains
  privileges. Vigil runs it only if the plugin folder, its `bin` folder and
  the script are not links, belong to you (or root) and cannot be changed by
  anyone else.
- For the Last run list Vigil reads ClamUI's log index
  (`clamui/logs/log_index.json` in its data folder, Flatpak or not) with
  the no-follow reader and a 2 MiB cap, and keeps only the newest
  timestamp of each kind ("scan", "update"), matched against a strict date
  pattern. It never reads ClamUI's logs themselves.
- File-change alerts store SHA-256 fingerprints, never contents; symlinks
  are recorded by their target path and never followed.
- Secrets found in shell history are reported by file, line and kind. The
  matched text never leaves the helper.

## Repository hygiene

No agent instruction files, no binaries, no file over 512 KiB, no NUL bytes,
one ID (`keasbeexd.vigil`) everywhere, versions in the manifest and
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
