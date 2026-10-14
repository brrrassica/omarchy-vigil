# Security model

A security plugin that is itself careless would be worse than none. This page
explains how Vigil is built, mapped to the points the Omarchy plugin
marketplace review checks. `tests/test_marketplace_rules.py` enforces the
mechanical ones.

## Design rules

These hold for every pillar, now and in later phases:

1. **No root from the plugin.** Root steps are constant scripts from
   `Model.js`, or the helper's two constant pkexec commands (the ClamAV
   signatures and Bumblebee update, and the password scan). Each is shown
   in full on a confirmation in the panel, then run through `pkexec`, so
   Omarchy's own polkit dialog asks for your password each time. Tools that
   ask questions as they go run in a visible terminal: Omarchy's own
   commands, and `ssh-keygen` when you add a passphrase to an SSH key. No
   root helper, sudoers rule, polkit policy, service or timer, ever.
2. **Everything Vigil reads is untrusted**, including its own helper's output,
   other tools' result files and file names (a file name is chosen by whoever
   created the file). It is size-capped, validated and shown as plain text,
   and never put into a notification or a program's arguments. Two kinds of
   value reach a program only after a strict check, and only as data: a
   Wi-Fi network's ID, which must be a UUID before `nmcli` is given it, and
   the files a virus scan is handed (new downloads, and detections it
   double-checks), which go to ClamAV in a private list file
   (`--file-list`), one per line, never with a line break in a name.
3. **Virus scans run as you.** ClamAV scans (Vigil's scans and ClamUI)
   never run as root: malware scanners have had parser bugs, and running
   them unprivileged limits what a malicious file can do. What needs root
   runs only from a button you press: the password scan (accounts without
   a password) only in Run all, keeping only account names; Show listeners
   (`ss -tulpn`, read-only) on its own button; and the ClamAV signature
   update (freshclam, which downloads signatures and scans nothing) in Run
   list update and Run all.
4. **Hand off, don't absorb.** ClamUI keeps quarantine, Black Ops keeps
   telemetry blocking. Vigil reads their results and opens them; it does not
   run their code or write their files, with one exception you confirm:
   **Let Vigil run them** switches off a duplicate scheduled scan the way
   you would in that app (ClamUI's user timer and its one
   `scheduled_scans_enabled` setting, Omarchy's `omarchy-plugin-disable`
   for the Bumblebee plugin), leaves a marker per change, and its Undo
   reverses only what the markers name. The script checks again itself: it
   touches ClamUI only when every scheduled folder of every ClamUI install
   is inside your home folder, and the plugin only when Vigil's own
   Bumblebee is installed; it refuses a link anywhere on the way to its
   markers, and never writes through one. Perplexity's Bumblebee is a
   standalone program Vigil installs from Perplexity's own release and runs
   as you, read-only.
5. **Maintained sources, never executed.** Vigil keeps no threat lists. Data
   comes from the tools of the people who maintain it: every day,
   `checkupdates` (your Arch and Omarchy mirrors) and `flatpak remote-ls`
   (your Flatpak remotes) for waiting updates; every week, fwupd's refresh
   from LVFS, arch-audit, osv-scanner, Perplexity's Bumblebee catalogs and
   one fixed AUR lookup; ClamAV's own freshclam service keeps the virus
   signatures. All of it on those schedules (the `autoUpdate` setting) or
   when you press a run button. Nothing the background checks fetch is ever
   run; results are size-capped and validated like any other input. The one
   program Vigil downloads, Bumblebee, is installed only from a button you
   press (Install, Update Bumblebee, or the List update and Run all buttons when
   the installed one is older), never by a background check, at the
   version pinned in Vigil's code, after its checksum matches.
6. **Nothing automatic.** Every change to your system is confirmed. Marking
   a finding as reviewed, a virus detection as a false positive, or a
   leftover as kept, changes only Vigil's own notes and is undone with one
   click, so it does not ask. Nothing in your home folder is deleted to
   tidy it: a leftover goes to the trash, where you can restore it.
   Notifications carry counts only; IPC methods take no parameters.
7. **Removal leaves nothing running.** Vigil has no units, cron jobs or
   daemons of its own, and a scan or update under way stops within seconds
   of the plugin folder being removed. Services Vigil switched on for you
   (ClamAV's `clamav-freshclam`, the `ufw` firewall) belong to their
   packages and keep protecting you; the README says how to turn them off,
   and lists every file Vigil leaves behind.

## What runs where

| Part | Runs as | Does |
|---|---|---|
| `Panel.qml` + `Model.js` | you, inside `omarchy-shell` | Draws the lighthouse and panel, starts the helper, validates its output, launches confirmed actions. |
| `bin/vigil` | you, as a child process | Reads local settings and files and returns one JSON report; performs the helper actions (a closed list), and moves leftovers you choose to the trash. |
| Script actions | root through `pkexec` (Omarchy's password dialog), or you | Constant scripts from `Model.js`, shown in full on a confirmation first; what they print is shown in the panel. |
| Terminal actions | you, in a visible terminal | Omarchy's own interactive commands, and choosing an SSH passphrase. |
| App actions | you | Open ClamUI with a fixed argv: `/usr/bin/clamui`, or `/usr/bin/flatpak run io.github.linx_systems.ClamUI`. |

Nothing from the plugin folder ever runs as root. There is no sudoers rule,
no polkit policy, no service, no timer and no daemon.

One scan or update at a time: `refresh-feeds` takes an exclusive,
non-blocking `flock` on `~/.local/state/omarchy-vigil/busy/` (a directory
opened with the usual no-follow walk, so there is no lock file to plant a
link at) and exits at once if another run holds it. The kernel releases the
lock when the last holder ends, so a crash or a shell restart cannot leave
it stuck. The programs a run starts (clamscan, Bumblebee, the scanners)
inherit the descriptor, so a virus scan left running after the helper is
gone still blocks a second one. If the panel goes away mid-run, the helper
stops writing to it and finishes instead of dying halfway. Its current step
is kept in `progress.json`; `vigil running` (no arguments) reports it, and
the panel accepts it only while the lock is held and only with a step text
from the helper's fixed list.

**Stop** sends TERM to the panel's own run; the helper then signals the
program it is running (its own process group) and skips the remaining
steps, and `run()` starts nothing more. For a run the panel did not start,
`vigil stop` (no arguments) reads `run.json`: the helper's PID and the PID
of the program it is running, each with its start time from
`/proc/<pid>/stat`. It signals a PID only if that process still runs as
you with the recorded start time, so a reused PID is never hit, and the
program by its process group. TERM first, KILL after 15 seconds if the
lock is still held. A step running as root (a password prompt that was
accepted) cannot be signalled; the panel then says so.

Removing the plugin stops a run too, even when no panel is left to press
Stop: while it holds the lock, the helper looks every five seconds whether
its own file still exists (`plugin_removed`). Once it is gone, it stops the
program it is running, process group and all, and starts no further step.

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
- The confirmation card shows, below Run and Cancel, the exact commands
  Run starts: for each step the program with its options (for a root step
  `/usr/bin/pkexec /usr/bin/env HOME=<your home> /usr/bin/bash -c`), then
  the script exactly as it is passed, unabridged; for a terminal action, the
  command the terminal runs. The run cards show the helper's root steps the
  same way: the ClamAV signatures and Bumblebee update (each only when it
  applies) and, in Run all, the password scan. `Model.js` keeps copies of
  those two helper scripts, and a test checks they are identical to what the
  helper starts; another checks every card against the plan that runs.
- The List update button (and Run all) updates ClamAV's signatures only when you press it (the
  background run never asks), with one constant root script through pkexec: if
  ClamAV's update service runs, it is woken with `systemctl kill
  --signal=SIGUSR1` (it then checks at once; a second freshclam would fail
  on the service's log lock), and the script waits up to two minutes for the
  service's journal to report the result; otherwise it runs freshclam.
- Programs Vigil runs must be trusted files, never links: root-owned, not
  writable by anyone else, in a root-owned directory.
- **Install** (shown in red as "MISSING … INSTALL" when a helper is
  missing) is one constant root script: `pacman -S --needed --noconfirm`
  for ClamAV, ClamUI (skipped when you already have it from Flathub),
  arch-audit, osv-scanner and fwupd, then Bumblebee. Everything except
  Bumblebee comes from the Arch repositories, so `omarchy-update` keeps it
  current. Bumblebee is installed and updated by
  one constant root script (`BUMBLEBEE_SCRIPT` in `bin/vigil`, identical
  to `BUMBLEBEE_INSTALL` in `Model.js`; a test checks), used by Install,
  Update Bumblebee, List update and Run all. It takes no data from the report:
  it installs exactly `BUMBLEBEE_VERSION` (0.1.2), and the SHA-256 of
  each release archive (amd64 and arm64) is written in `bin/vigil`, so the
  reviewed commit decides which bytes run. Nothing is taken from the
  network to decide that: no release list, no `checksums.txt`. The archive
  is downloaded over HTTPS only (`curl -q --proto =https --proto-redir
  =https`, time-limited) and capped in bytes while it streams (`head -c`
  of the limit plus one, then a size check, under `pipefail`), into a
  fresh `mktemp -d`; its SHA-256 must equal the pinned one. Only the
  `bumblebee` member is extracted (`--no-same-owner
  --no-same-permissions`), and only a regular file, not a link, is
  installed as `/usr/local/bin/bumblebee`, owned by root, mode 0755. The
  installed program is never run as root: a byte comparison decides
  whether anything changed. Whether an update is due is checked as you
  (`bumblebee version`, compared with the pinned version), and only then
  does the list update add the Bumblebee step to its one password prompt.
  A newer Bumblebee arrives only with a Vigil update, which goes through
  the marketplace review again.
- Terminal actions are constant strings in `Model.js`. The report only names
  an action id; an id that is not in the table does nothing. Omarchy tools
  are addressed by absolute path, from one of the two trusted directories,
  found by the helper (a root-owned file, not writable by anyone else). A
  script that calls Omarchy's plugin commands gets them the same way, as
  variables set at its top (`omarchy_plugin_disable=/usr/share/omarchy/bin/...`,
  empty and skipped when not found). The one exception is the **Restart
  shell** button, a constant `omarchy-restart-shell` found through the fixed
  PATH `/usr/share/omarchy/bin:/usr/bin:/bin`, all root-owned.
  Each script prints what it will do and waits for Enter before running.
  `tests/model.test.mjs` runs `bash -n` on every script. Scripts never put
  private file names into a program's arguments, which every account can
  read in `/proc/<pid>/cmdline`: **Add a passphrase** opens each SSH key on
  descriptor 3, `grep` reads it from stdin, and `ssh-keygen` is given
  `/proc/self/fd/3` (a test runs the script and checks the arguments). The
  key's name it shows goes through `printf %q`, so control characters in a
  file name are printed as `$'\E...'` escapes, never sent to the terminal.
- **Learn more** opens a page with `xdg-open` (root-owned, in `/usr/bin`) as
  a two-element argv, no shell. The URL is a constant from the `DOCS` table
  in `Model.js`, chosen by id; any other id is dropped when the report is
  validated.
- The password scan runs `pkexec /usr/bin/awk -F: '$2 == "" { print $1 }'
  /etc/shadow` from the helper, a constant argv (`NO_PASSWORD_ARGV`), only
  when you press Run all, never in the background run. pkexec asks for your
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

The background checks (and the run buttons) are the only network use Vigil starts
by itself, and only once the relevant tool is installed:

- `checkupdates --nocolor` (pacman-contrib, which Omarchy ships) syncs a
  private copy of the package databases into
  `~/.local/state/omarchy-vigil/checkup-db` (`CHECKUPDATES_DB`; not the
  shared `/tmp`, where another account could plant one first) as you and
  lists waiting updates; only `name old -> new` lines matching a
  strict pattern are kept. It installs nothing.
- In the weekly check, `fwupdmgr refresh --no-unreported-check` (fwupd's
  polkit policy lets a logged-in user refresh firmware metadata without a
  password) and `fwupdmgr get-updates --json --no-unreported-check
  --no-metadata-check`, as you, with stdin closed so nothing can prompt.
  Only device names, versions and whether a release lists CVEs or a high
  urgency are kept. Installing firmware is Omarchy's
  `omarchy-update-firmware`, in a terminal, when you press the button.
- `arch-audit --json --upgradable` and `osv-scanner --format json
  --no-resolve --recursive -- <folders>` are root-owned system binaries, run
  with the helper's usual absolute path, empty environment, deadline and
  output cap. osv-scanner sends package names and versions, not files; git
  checkouts are not sent (its default).
- The AUR lookup is one `curl -q -sS --fail --proto =https --proto-redir
  =https --max-time 30 --max-filesize 4194304 -- <url>` to a fixed host,
  with package names checked against a strict pattern and percent-encoded.
- Bumblebee's catalogs are one `curl -q -sS --fail --proto =https
  --proto-redir =https --max-time 60 --max-filesize 33554432 -- <url>` to a
  fixed address, Perplexity's repository archive on `codeload.github.com`.
  The archive is never unpacked to disk. It is decompressed in memory with
  a hard cap of 96 MiB first (tar headers such as PAX are read whole before
  any per-member limit could apply), then only `threat_intel/*.json`
  members are read (at most 5,000 members, 8 MiB each, 64 MiB in total,
  20 seconds). Each entry is checked the way Bumblebee
  checks it (id, ecosystem, package and a list of versions; no control
  characters), since one bad entry would make Bumblebee refuse the whole
  list, and only those fields plus name, severity and source are kept, at
  most 50,000 entries. They are written as one JSON file with mode 0600 in
  catalog schema 0.1.0, which every Bumblebee release reads (Perplexity's
  lists moved to 0.2.0, which the released program does not read yet; 0.2.0
  only adds "any version" entries, which are left out). Bumblebee then reads that file as data
  (`--exposure-catalog`).
- Bumblebee's scan is `/usr/local/bin/bumblebee scan --profile baseline
  --exposure-catalog <file> --findings-only --output stdout --max-duration
  5m`, as you, with the empty environment, and only finding fields (catalog
  name, ecosystem, package, version, file, severity) are kept, cleaned and
  capped. It reads files only and makes no network calls of its own.
  `tests/test_marketplace_rules.py` fails if any other network call appears.
- The virus scan runs `/usr/bin/nice -n 19 /usr/bin/clamscan --recursive
  --no-summary --stdout --cross-fs=no --follow-dir-symlinks=0
  --follow-file-symlinks=0 --exclude-dir=... -- ~` as you, never as root.
  Its output is read line by line: lines for clean files are only counted
  (for the progress bar) and dropped, and only the first 500 `FOUND` lines
  are kept, so a flood of them cannot push the result past its cap. File
  names in them are chosen by whoever named the file, so they are cleaned,
  capped and shown as plain text, and never reach a command or
  notification. clamscan prints names as they are, so a name with a line
  break could print a fake `...: X FOUND` line for another file (your SSH
  key, say). Every detection is therefore confirmed by a second scan of
  exactly those files; only confirmed detections are kept. File paths never
  go into a program's arguments, since `/proc/<pid>/cmdline` is readable by
  every account on the machine: both the Downloads scan and the confirming
  scan hand clamscan a `--file-list` in Vigil's state folder (0600 inside
  0700), and the confirming list is deleted when that scan ends. File names with a line break or other control
  character are reported as a warning in their own right.
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
- To offer fingerprint login only where it works, the helper runs Omarchy's
  own detector, `omarchy-hw-fingerprint`, with no arguments, the empty
  environment and a five-second limit, and uses only its exit code. It is
  a root-owned file in `/usr/bin` or `/usr/share/omarchy/bin` (a test
  checks the lookup) and reads `/sys/bus/usb/devices` only. It runs only
  when sudo has neither a fingerprint nor a security key set up.
- The "Duplicate scan schedules" check reads, without following links: the
  `timers.target.wants` entries for `clamui-scheduled-scan.timer` and
  `qs-security-scan.timer` (lstat only), ClamUI's `settings.json` (1 MiB
  cap; only the schedule fields, and folders count as inside your home only
  as absolute paths or `~/` that normalise under it), and `shell.json` (2 MiB
  cap) for whether the Bumblebee plugin is switched on. The hand-over and
  its Undo are constant user-level scripts in `Model.js`, run without a
  password. Both ClamUI installs (Arch and Flatpak) share one timer, so the
  hand-over leaves all of ClamUI as it is when any settings file has a
  schedule that reaches outside your home folder, cannot be parsed, or is a
  link. ClamUI's settings are edited with `jq` into a fresh temporary file
  in the same folder, given the original's mode and renamed over it
  (`mv -T`), and only a regular file (not a link) is edited; a failed edit
  removes the temporary.
- The user-level scripts that keep notes in Vigil's state folder (the
  hand-over, Stop auto-joining and their Undos) walk from your home folder
  one component at a time, `~/.local`, `state`, `omarchy-vigil` and below,
  and refuse, without changing anything, a component that is a link or not
  a folder of yours; the helper refuses the same with its `O_NOFOLLOW` walk.
  Markers and the list of changed networks are written as fresh files
  (`mktemp`) renamed into place, so a link planted at their names is
  replaced, never written through, and Undo counts only regular files.
- **False positive** on a virus detection is keyed to one detection (an id
  from the real path and signature name, recorded at scan time only for
  plain absolute paths inside your home folder) and to that file's SHA-256,
  read with `O_NOFOLLOW` (regular files up to 2 GiB). On later checks an
  unchanged device, inode, size, mtime and ctime skip re-reading; anything
  else re-hashes, and a different hash, a missing file or a link in its
  place counts the detection again. The panel asks first. The helper verbs
  are `vigil ignore|unignore <16 hex digits>`.
- **Leftover app data** reads, never runs: pacman's `desc` files in
  `/var/lib/pacman/local` (names, provides and replaces only, 64 KiB cap
  each), the names in `/usr/bin`, `/usr/share`, `/usr/lib`, `/etc`, `/opt`
  and the like, desktop entries (`Exec`, `TryExec`, `StartupWMClass` and
  `Icon` of the main group, 64 KiB cap), the installed Flatpak app folders,
  `/proc/<pid>/comm`, and the same startup files the persistence check
  reads. All within four seconds; if that survey does not finish, the row
  says so and lists nothing, since an incomplete survey would list things
  that are in use. Folder walks never follow links, and a folder too big
  to walk within the limit is treated as in use.
- Each leftover is named to the panel by an id: 16 hex digits of the
  SHA-256 of its place and name. File names never reach a command line.
  The verbs are `vigil keep|unkeep <id>` (Vigil's notes in
  `kept-leftovers.json`, nothing else) and `vigil trash <id>...` (at most
  150 distinct ids, each checked against the pattern). The panel asks
  first, on a card that lists every item, and sends exactly the ids that
  card showed. The helper runs the whole check again and moves only ids it
  still lists and you have not kept, so something reinstalled or kept in
  the meantime stays put.
- Moving to the trash follows the freedesktop.org trash layout, as a file
  manager does. The source folder is opened with the usual no-follow walk
  from your home folder, and so are `~/.local/share/Trash/files` and
  `info`. The item must be yours; a link is moved as a link, never
  followed. The `.trashinfo` file is created first with `O_EXCL` (mode
  0600), reserving the name, with the original path percent-encoded byte
  by byte, so a line break in a name cannot add a line. Then one `rename`
  between the held folders, and `fsync` of all three. An item on another
  disk than the trash (a mount point, say) is refused rather than copied,
  and nothing that holds the trash itself is ever moved. Nothing is
  deleted.
- The daily Downloads scan lists files changed since the last one (an hour
  of overlap, never a gap) in your Downloads folder (`XDG_DOWNLOAD_DIR` only
  when it is a plain `$HOME/...` path), without following links, at most
  5,000 files and 10 seconds of walking, and hands the list to clamscan with
  `--file-list` from Vigil's private folder. Names with a line break are
  left to the weekly scan, which reports them.
- Open Wi-Fi: `nmcli` as you, read-only, for saved networks (UUIDs checked
  against a strict pattern). Stop auto-joining and its Undo are constant
  user-level scripts; Undo only touches the UUIDs Stop auto-joining
  recorded, each checked against the same pattern. The list is rebuilt in a
  fresh file and renamed into place on the way out, also when a step fails,
  so every network already changed stays recorded.
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
