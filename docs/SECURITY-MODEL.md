# Security model

A security plugin that is itself careless would be worse than none. This page
explains how Vigil is built, mapped to the points the Omarchy plugin
marketplace review checks. `tests/test_marketplace_rules.py` enforces the
mechanical ones.

## Design rules

These hold for every pillar, now and in later phases:

1. **No root from the plugin.** Root steps are constant scripts from
   `Model.js`, or the helper's two constant pkexec commands (the virus
   signatures update, and the password scan). Each is shown
   in full on a confirmation in the panel, then run through `pkexec`, so
   Omarchy's own polkit dialog asks for your password each time. Tools that
   ask questions as they go run in a visible terminal: Omarchy's own
   commands, and `ssh-keygen` when you add a passphrase to an SSH key. No
   root helper, sudoers rule, polkit policy, service or timer, ever. Some
   steps that run as you make a system service ask through its own rules
   (NetworkManager for Stop auto-joining and its Undo, Flatpak for apps
   installed for every account); those prompts are the
   service's, not pkexec, and their cards say a password dialog may appear.
2. **Everything Vigil reads is untrusted**, including its own helper's output,
   other tools' result files and file names (a file name is chosen by whoever
   created the file). It is size-capped, validated and shown as plain text,
   and never put into a notification or a program's arguments. Five kinds
   of value reach a program only after a strict check, and only as data: the
   ids the panel sends back to the helper (`vigil keep|trash|ignore <keyed
   id>`, `vigil dismiss <check id>`, `vigil fix <action id>`), each checked
   against its pattern or closed list on both sides; your AUR package names,
   which must match Arch's lowercase name pattern and are percent-encoded
   into the AUR lookup's URL; a
   Wi-Fi network's ID, which must be a UUID before `nmcli` is given it; the
   files a virus scan is handed (new downloads, and detections it
   double-checks), which go to ClamAV in a private list file
   (`--file-list`), one per line, never with a line break in a name; and the
   packages and plugins you tick and confirm for removal, by name. A package
   name must follow Arch's rules (letters, digits and `@._+-`, not starting
   with `-` or `.`) and a plugin id Omarchy's (letters, digits and `._-`,
   no `..`, never Vigil itself). Each is checked in the helper, again in
   `Model.js`, and again by the script that receives it, which as root also
   checks that pacman still lists each package as orphaned or foreign and
   removes nothing unless every one passes. They are separate arguments
   after a constant script, never part of it, and pacman gets them after
   `--`. Those removal command lines name the packages or plugins, and every
   account can read a running command line in `/proc/<pid>/cmdline`.
3. **Virus scans run as you.** ClamAV scans (Vigil's scans and ClamUI)
   never run as root: malware scanners have had parser bugs, and running
   them unprivileged limits what a malicious file can do. What needs root
   runs only from a button you press: the password scan (accounts without
   a password) only in Run all, keeping only account names; Show listeners
   (`ss -tulpn`, read-only) on its own button; and the virus signature
   update (freshclam, which downloads signatures and scans nothing), only
   in Run all and only when ClamAV's own update service has let them get
   over two days old. The daily and weekly checks (pressed or in the
   background) and a row's Scan now never ask for a password.
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
5. **Maintained sources, fresh, never executed.** Vigil keeps no threat
   lists, and each scan gets its list right before it runs: every day,
   `checkupdates` (your Arch and Omarchy mirrors) and `flatpak remote-ls`
   (your Flatpak remotes) for waiting updates, arch-audit (which downloads
   the Arch tracker as it scans), osv-scanner (which asks OSV.dev as it
   scans), the AUR lookup (one request per 100 packages, to a fixed
   address), and Perplexity's Bumblebee catalogs right
   before the Bumblebee scan; every week, fwupd's refresh from LVFS. ClamAV's
   own freshclam service keeps the virus signatures current, and Vigil
   checks them right before every virus scan. A failed Bumblebee list
   download never stops the Bumblebee scan: it uses the last good list and
   says how old it is. arch-audit and osv-scanner fetch as they scan, so for
   them a failed download is a failed step, tried again the next day. All of
   it on those schedules (the `autoUpdate` setting) or when you press a run
   button. Nothing the checks fetch is ever run, except that a Daily check or
   Run all you press installs the waiting updates for your own Flatpak apps,
   through Flatpak; results are size-capped and validated like any other
   input. The one program Vigil downloads,
   Bumblebee, is installed only from a button you press (Install, or
   Install Bumblebee on its row after a Vigil update raised the pinned
   version), never by a run, at the version pinned in Vigil's code, after
   its checksum matches.
6. **Nothing automatic.** Every change to your system is confirmed: removing
   packages or plugins, moving leftovers to the trash and marking virus
   detections as false positives each ask first, on a card that lists the
   items (the first 40, then how many more; a removal card's command line
   names every one). Marking a finding as reviewed, or an item of a list as
   kept, changes only Vigil's own notes and is undone with one click (Show
   again, or the item's lock), so it does not ask. Leftover app data is
   never deleted, only moved to the trash, where you can restore it. The
   Care cleanups that do delete (the thumbnail cache, caches in `~/.cache`
   unused for a week, and emptying the trash, alone or in Clean all) say so
   on their card. Removing a plugin is Omarchy's own `omarchy-plugin-remove`, which
   deletes a plugin it cloned from git (add it again to get it back),
   unlinks a development install and backs up any other folder; the card
   says so.
   Notifications carry counts, one fixed sentence (the virus signatures are
   over two days old: press Run all), or, after a weekly check or Run all
   you started, a fixed sentence saying it finished, was stopped or did not
   finish; never data from the report or a file. IPC methods take no
   parameters.
7. **Removal leaves nothing running.** Vigil has no units, cron jobs or
   daemons of its own, and a run under way stops within seconds of the
   plugin folder being removed (the single scans behind a row's Scan now or
   Look up now are bounded by their own deadlines instead). Services Vigil switched on for you
   (ClamAV's `clamav-freshclam`, the `ufw` firewall) belong to their
   packages and keep protecting you; the README says how to turn them off,
   and lists every file Vigil leaves behind.

## What runs where

| Part | Runs as | Does |
|---|---|---|
| `Panel.qml` + `Model.js` | you, inside `omarchy-shell` | Draws the lighthouse and panel, starts the helper, validates its output, launches confirmed actions. |
| `bin/vigil` | you, as a child process | Reads local settings and files and returns one JSON report; performs the helper actions (a closed list), moves leftovers you choose to the trash, runs the scans and lookups (and the updates for your own Flatpak apps when you press Daily check or Run all), and starts its two constant pkexec root steps in Run all. |
| Script actions | root through `pkexec` (Omarchy's password dialog), or you | Constant scripts from `Model.js`, shown in full on a confirmation first; what they print is shown in the panel. |
| Removing from a list | root through `pkexec` (packages), or you (plugins) | A constant script from `Model.js` with the names you ticked as its arguments, shown in full on the card first: `pacman -Rns`, or Omarchy's `omarchy-plugin-remove`. |
| Terminal actions | you, in a visible terminal | Omarchy's own interactive commands, and choosing an SSH passphrase. |
| App actions | you | Open ClamUI with a fixed argv: `/usr/bin/clamui`, or `/usr/bin/flatpak run io.github.linx_systems.ClamUI`. |

No file from the plugin folder is executed as root. The root scripts are text
from `Model.js`, which a program running as you could change like the rest
of the plugin folder, so each one is shown in full on its card before
pkexec runs it. There is no sudoers rule, no polkit policy, no service, no
timer and no daemon.

One run at a time: `refresh-feeds` takes an exclusive,
non-blocking `flock` on `~/.local/state/omarchy-vigil/busy/` (a directory
opened with the usual no-follow walk, so there is no lock file to plant a
link at) and exits at once if another run holds it. The kernel releases the
lock when the last holder ends, so a crash or a shell restart cannot leave
it stuck. The programs a run starts (clamscan, Bumblebee, the scanners)
inherit the descriptor, so a virus scan left running after the helper is
gone still blocks a second one. If the panel goes away mid-run, the helper
stops writing to it and finishes instead of dying halfway. Its current step
is kept in `progress.json`; `vigil running` (no arguments) reports it only
while the lock is held and only with a step text from its fixed list, and
the panel checks the numbers and length again. The Scan now and Look up now
buttons on the Arch security, OSV and AUR rows run their single scan through
`vigil fix`, outside the run lock; each is bounded by its own deadline.

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
  report that does not match is rejected whole (unknown Last run ids and
  unknown missing helpers are skipped instead). Keys are looked up with
  `hasOwnProperty` and collected into `Object.create(null)` maps. A Last
  run line's note ("with the list from Oct 14") must match one fixed
  pattern, and whether it shows in red is a separate boolean.
- The severity colours of list items (what a plugin's code can do, what
  ClamAV found) are the theme's red (Omarchy's urgent colour) and its
  yellow and green, which the helper reads from the theme's `colors.toml`
  as text (64 KiB cap; the panel reads no files itself): only a line of the
  form `yellow = "#rrggbb"` or `green = "#rrggbb"` (spacing and quotes
  optional) is used, and the
  report must carry `#rrggbb` or nothing; without them the panel uses the
  theme's accent or text colour. The colour is a separate field per part of the
  line, from a closed list (high, medium, low), and the panel shows the
  parts only when they read exactly as the item's plain line, so colour
  never adds or changes a word.
- Every `Text` sets `textFormat: Text.PlainText`. Strings passed to host
  components (tooltip, `PanelHero`) go through `Model.plain`, which removes
  `<`, `>`, `&`, control and bidi characters and caps the length.
  Notifications contain only a count, the constant sentence
  `SIGNATURES_NOTICE` from `Model.js` (at most once a day), or, after a
  weekly check or Run all you started, a fixed sentence naming that run and
  whether it finished, was stopped or did not finish. They are built from
  constants and a clamped number, never from the report or a file.
- Size limits: at most 160 checks; at most 300 items per row from the
  helper (the panel accepts 500): leftovers 150, detections 500 before that
  cap, plugins 100; result messages up to 2000 characters, shown whole
  (`MESSAGE_MAX` = `MAX_MESSAGE`, a test checks); an action's result at
  most 16 KiB; an action's printed output, the last 8 KiB, shown as 6000
  characters.
- The IPC target exposes `open`, `close`, `show`, `hide`, `toggle` and
  `refresh`, none with parameters, and is registered only by the copy of the
  widget on the first monitor.

## Commands

- The helper runs only absolute paths, in a new session, with an empty
  environment apart from a fixed `PATH`, `HOME`, `LANG` and `LC_ALL` (plus
  `CHECKUPDATES_DB` for checkupdates), a deadline, and
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
  reaches it, apart from which of the two trusted folders an Omarchy tool
  is in, a closed choice. Steps that would wait for input are not allowed (a test
  checks), and `ufw` runs with `--force` so it never prompts.
- The confirmation card shows, below Run and Cancel, the exact commands
  Run starts: for each step the program with its options (for a script
  action's root step `/usr/bin/pkexec /usr/bin/env HOME=<your home>
  /usr/bin/bash -c`; for the helper's root steps and package removal
  `/usr/bin/pkexec /usr/bin/bash -c`), then
  the script exactly as it is passed, unabridged; for a terminal action, the
  command the terminal runs. The run cards show the helper's root steps the
  same way; only Run all has any: the virus signatures update (only when
  they are over two days old, which the report states as `signaturesDue`)
  and the password scan. The panel lets the helper run the signatures
  update only when the Run all card you confirmed showed that exact command
  (`refresh-feeds --full --signatures`, the one combination the helper
  accepts); without the flag the helper never asks for that password, so a
  card drawn before the signatures grew old cannot lead to a prompt it did
  not show. `Model.js` keeps copies of
  those two helper scripts, and a test checks they are identical to what the
  helper starts; another checks every card against the plan that runs.
- Right before every virus scan, the helper checks how old the virus
  signatures are, from the dates of ClamAV's database files and
  `freshclam.dat` (which ClamAV's service touches on every check), Vigil's
  own record and ClamUI's log. ClamAV's own service keeps them current, so
  no run forces an update until they are over two days old; then only Run
  all updates them, first, while you are at the screen (every other run
  scans with what is there and records how old they were), with one
  constant root script through pkexec: if
  ClamAV's update service runs, it is woken with `systemctl kill
  --signal=SIGUSR1` (it then checks at once; a second freshclam would fail
  on the service's log lock), and the script waits up to two minutes for the
  service's journal to report the result; otherwise it runs freshclam.
- Programs the helper starts itself must be trusted files, never links:
  root-owned, not writable by anyone else, in a root-owned directory.
  Scripts name every tool by absolute path in `/usr/bin`, but do not check
  each one; pkexec's own target is always `/usr/bin/bash` or
  `/usr/bin/env`, never a link.
- **Install** (shown in red as "MISSING … INSTALL" when a helper is
  missing) is one constant root script: `pacman -S --needed --noconfirm`
  for ClamAV, ClamUI (skipped when you already have it from Flathub),
  arch-audit, osv-scanner and fwupd, then Bumblebee. Everything except
  Bumblebee comes from the Arch repositories, so `omarchy-update` keeps it
  current. Bumblebee is installed by one constant root script
  (`BUMBLEBEE_SCRIPT` in `bin/vigil`, identical to `BUMBLEBEE_INSTALL` in
  `Model.js`; a test checks), used only by Install and by Install Bumblebee
  on its row; no run installs or updates it (a test checks). It takes no
  data from the report:
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
  whether anything changed. Whether the installed one is older than the
  pinned version is checked as you (`bumblebee version`); only then does
  its row offer Install Bumblebee. A newer Bumblebee arrives only with a
  Vigil update, which goes through the marketplace review again.
- Terminal actions are constant strings in `Model.js`. The report only names
  an action id; an id that is not in the table does nothing. Omarchy tools
  are addressed by absolute path, from one of the two trusted directories,
  found by the helper (a root-owned file, not writable by anyone else). A
  script that calls Omarchy's plugin commands gets them the same way, as
  variables set at its top (`omarchy_plugin_disable=/usr/share/omarchy/bin/...`,
  empty and skipped when not found). The one exception is the **Restart
  shell** button, a constant `omarchy-restart-shell` found through the fixed
  PATH `/usr/share/omarchy/bin:/usr/bin:/bin` (root-owned folders on
  Omarchy, though the panel does not check that itself).
  Each script prints what it will do and waits for Enter before running.
  `tests/model.test.mjs` runs `bash -n` on every script. Scripts never put
  private file names into a program's arguments, which every account can
  read in `/proc/<pid>/cmdline`: **Add a passphrase** opens each SSH key on
  descriptor 3, `grep` reads it from stdin, and `ssh-keygen` is given
  `/proc/self/fd/3` (a test runs the script and checks the arguments). The
  key's name it shows goes through `printf %q`, so control characters in a
  file name are printed as `$'\E...'` escapes, never sent to the terminal.
- **Remove** on a list of packages runs `pkexec /usr/bin/bash -c <script>
  vigil-remove orphans|foreign <name>...`, where the script is the constant
  `REMOVE_PACKAGES_SCRIPT` in `Model.js` and the names are the packages the
  card listed. The card shows that command line, with the script's place
  marked, and the script in full; Run rebuilds the command from the same
  ids and starts it only if it is exactly what the card showed. As root the
  script checks each name against Arch's rules, then that `pacman -Qdtq`
  (orphans) or `pacman -Qmq` (foreign) still lists it, and exits without
  removing anything if one fails; only then does it run `pacman -Rns
  --noconfirm -- <names>`. If another package still needs one, pacman
  refuses the whole removal. There is no Remove all for foreign packages.
  **Remove** on plugins runs `/usr/bin/bash -c <script> vigil-remove-plugins
  <id>...` as you, which checks every id the way `omarchy-plugin-remove`
  does (and refuses Vigil's own) before it runs that tool, at its trusted
  path, once per id with `--yes`. A test runs both scripts with fake tools
  and checks that a bad or unlisted name removes nothing.
- **Learn more** opens a page with `xdg-open` (root-owned, in `/usr/bin`) as
  a two-element argv, no shell. The URL is a constant from the `DOCS` table
  in `Model.js`, chosen by id; any other id is dropped when the report is
  validated.
- The password scan runs `pkexec /usr/bin/bash -c "/usr/bin/awk -F: '$2 ==
  \"\" { print $1 }' /etc/shadow"` from the helper, a constant argv
  (`NO_PASSWORD_ARGV`; bash, not awk, is pkexec's target because awk is a
  link on Arch), only
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
- Undo actions are constant scripts too. The drop-in Undos each delete a
  fixed path only if the file's first line is exactly Vigil's marker, read
  with `head -n 1` and compared as a whole string, so a file someone
  rewrote is left alone; the helper offers them only for files whose first
  line it has itself read as the marker through an `O_NOFOLLOW` descriptor.
  The Avahi Undo moves Vigil's backup back into place, which drops edits
  made since (its card says so). The hand-over and Stop auto-joining Undos
  reverse only what their marker files in the state folder name, and the
  fingerprint and security-key Undos are Omarchy's own commands. `tests/model.test.mjs`
  runs every undo script against temporary files.
- Marking a finding as reviewed stores a fingerprint (check id plus a keyed
  hash of its status, see [Ids](#ids)) in the state file, so the review lasts while the finding
  stays the same kind; a worse status is a new fingerprint. For evidence
  checks (open ports, startup files, file changes, secrets, infected files,
  malicious, compromised or vulnerable packages, preload, AUR status, user
  accounts, shell history, old services) the hash also covers what was
  found, so a review cannot hide something new. The four rows reviewed item
  by item with Keep (leftovers, orphans, AUR and foreign packages, other
  plugins) cannot be reviewed as a row. Passing findings cannot be reviewed, and the panel rejects
  a report that claims one is. State updates hold an
  exclusive `flock` on the state directory's own descriptor, so a background
  check and a dismissal cannot overwrite each other.
- App actions map an id and an install kind reported by the helper
  (`native`, `flatpak` or nothing) to one of two fixed argv arrays. The
  helper reports `flatpak` only when `/usr/bin/flatpak` is root-owned and the
  ClamUI app directory exists.

## Ids

Every item id (an entry of a list you tick: a leftover, package, plugin or
virus detection) that Vigil gives the panel, puts on a command line (`vigil
keep <id>`, `vigil trash <id>`, `vigil ignore <id>`) or writes to its notes
is a keyed hash: the first 16 hex digits of an HMAC-SHA256, under a random
32-byte key made for this install, `~/.local/state/omarchy-vigil/id-key`
(mode 0600). The same goes for the fingerprints of reviewed and
already-seen findings. Vigil's own check ids (such as `open-ports`) stay
plain: they are the same on every machine.

- **What it protects.** A plain hash of a public name (a package, a
  plugin, a common folder name) can be reversed in seconds by hashing the
  whole list of names. A keyed one cannot be without the key. So the notes
  files (`kept.json`, `ignored-detections.json`, `state.json`), a backup or
  sync of them, a copy pasted into a bug report, and another account that
  reads Vigil's own command line (`/proc/<pid>/cmdline` is readable by every
  account), learn nothing about what you kept, marked or reviewed. (The
  command line that removes packages or plugins does name them; see design
  rule 2.)
- **What the notes hold.** `kept.json` holds ids and dates only.
  `ignored-detections.json` holds the id, the file's SHA-256 and its
  device, inode, size and times, which Vigil needs to notice a changed file,
  and no path or signature name. `state.json` holds check ids (Vigil's own,
  such as `open-ports`), keyed fingerprints and daily scores.
- **What it does not protect.** A program running as you can read the key,
  as Vigil does, and could also edit Vigil's notes, or Vigil itself. No
  scheme that keeps the key where Vigil (running as you) can read it can
  stop that, and Vigil keeps no root-owned store (design rule 1). What limits
  it: a kept item stays on its list with a lock, and the four lists that can
  be kept never count toward the score or notify. A reviewed finding stays
  on its tab marked reviewed, and a false positive stays on the virus list
  with a lock, so neither disappears; but both stop counting toward the
  score and notifications, so such a program could quiet a finding that
  way. The same program could also change the root scripts in `Model.js`,
  which is why every root step is shown in full on its card first.
- **The key itself.** It is read with `O_NOFOLLOW` and used only when it is
  a 32-byte regular file of yours. A new one is written whole to a private
  temporary file and linked into place (`linkat`, which never replaces), so
  a run never reads half a key and two runs agree on one; a link or a
  wrong-size file at its name is replaced, never followed. A look-only
  check (`--peek`, the copies on other monitors) never creates the key; until
  the first full check (or a Mark as reviewed) has, its ids last one run. Deleting the state folder
  makes a new key, so earlier keeps, false positives and reviews no longer
  match, just as their notes are gone.
- **Results are not ids.** What a scan found (`virus-scan.json`,
  `downloads-scan.json`, the other result files), the list of new downloads
  the daily scan was handed (`downloads-scan.list`), the account names the
  password scan found (`no-password.txt`), the file baseline and the list of
  Wi-Fi networks Stop auto-joining changed keep their names and paths: the panel shows them, and Undo needs them. They hold what anyone
  running as you can read from the system anyway, all mode 0600.
- **Carrying over.** Before keyed ids, ids were plain SHA-256 hashes, and
  the kept list also stored each item's name. After each full check Vigil
  carries old ids over to keyed ones for the items it just listed and drops
  the names. An old kept id whose item is no longer listed is dropped once
  every list it could belong to was read in full (otherwise it waits,
  nameless); an old false positive whose detection is gone is dropped. An
  old review fingerprint is replaced when its finding shows; until then it
  stays, so a review is never lost.

## Files

- Reads open the file once with `O_NONBLOCK` (a planted FIFO cannot hang
  the check), `fstat` that descriptor for a regular file, and read at most
  the cap + 1 bytes from it. Files in `/etc`, `/proc`, `/var` and Vigil's
  own state are opened with `O_NOFOLLOW`. A few reads follow symlinks on
  purpose, with the same type and size limits: the files scanned for
  persistence and the environment files (dotfile managers symlink them, and
  refusing would let a hidden line escape the scan), `shell.json` (for the
  lock timeout and whether the Bumblebee plugin is on), the theme's
  `colors.toml` (through Omarchy's `current/theme` link), other plugins'
  `manifest.json` (only their `name` is used), desktop entries in the
  leftover survey, and sysfs entries (sysfs is made of symlinks). Nothing
  read is executed, and nothing read is written back except by **Remove
  those lines**, which rewrites your shell history without the lines that
  hold a key.
- Writes (the state file, Vigil's other notes such as the kept list, the
  file baseline, the opt-out file, and the shell history that Remove those
  lines rewrites, only a regular file with one link) walk from your home
  directory
  one component at a time with `O_NOFOLLOW`, refusing any component that is
  a symlink or not owned by you, then create an exclusive random temporary
  at its final mode, `fsync`, `rename` over the target and `fsync` the
  directory. A symlink planted at the target is replaced, not written
  through; tests plant one and check the victim file is untouched. The
  permission fixes (`~/.ssh`, `~/.gnupg`, credential files) `fchmod` a
  descriptor opened the same way; moving to the trash is described below.
- Deletion (thumbnail cache, the trash, unused application caches) works
  relative to held directory descriptors and never follows a symlink.
  Leftover app data is never deleted, only moved to the trash (see below). The opt-out file is removed only if its bytes
  are exactly what Vigil wrote.

## Network

The background checks (and the run buttons) are the only network use Vigil starts
by itself, and only once the relevant tool is installed:

- `flatpak remote-ls --user|--system --updates --columns=application`, as
  you, lists waiting app updates; only app IDs matching a strict pattern
  are kept. When you press Daily check or Run all (never in the
  background), `flatpak update --user --noninteractive` installs the
  updates for your own Flatpak apps from their remotes, as you, without a
  password; the card says so. Apps installed for every account are updated
  only by their row's button.
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
  =https --max-time 30 --max-filesize 4194304 -- <url>` per 100 packages,
  to a fixed host, with package names checked against a strict pattern and
  percent-encoded.
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
  `tests/test_marketplace_rules.py` fails if the helper gains another direct
  curl or wget call, one without these limits, or a Python network import.
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
  severities, IDs and counts are kept. A failed step keeps the last good
  result and is tried again the next day, so an offline machine is not
  hammered. A failed Bumblebee list download leaves the last good list in
  place; the scan uses it and records which list it used, so its row and
  its Last run line say how old it was. Each list is fetched at most once
  per daily check, and only right before the scan that uses it.

Actions you start yourself (package installs, ClamUI, `omarchy-update`)
say where they connect before they run.

## Reading other software

- File changes are checked against pacman's own records: each package's
  `mtree` in `/var/lib/pacman/local` is decompressed with a 32 MiB output
  cap, within a five-second budget, and a changed `/etc` file whose SHA-256
  matches what a package shipped is not reported.
- The plugin capability scan reads other plugins' files as text, at most 100
  plugins and the first 300 code files of each, 512 KiB per file, 8 MiB and
  three seconds in total, without following symlinks (a development install
  linked from elsewhere is listed, not scanned). It never loads, imports or
  runs them.
- To offer fingerprint login only where it works, the helper runs Omarchy's
  own detector, `omarchy-hw-fingerprint`, with no arguments, the empty
  environment and a five-second limit, and uses only its exit code. It is
  a root-owned file in `/usr/bin` or `/usr/share/omarchy/bin` (a test
  checks the lookup) and reads `/sys/bus/usb/devices` only. It runs only
  when sudo has neither a fingerprint nor a security key set up.
- The "Duplicate scan schedules" check reads: the
  `timers.target.wants` entries for `clamui-scheduled-scan.timer` and
  `qs-security-scan.timer` (lstat only), ClamUI's `settings.json` (1 MiB
  cap; only the schedule fields, and folders count as inside your home only
  as absolute paths or `~/` that normalise under it), both without following
  links, and `shell.json` (2 MiB cap, following Omarchy's own link) for
  whether the Bumblebee plugin is switched on. The hand-over and
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
  place counts the detection again. The panel asks first, on one card that
  lists the ticked files (the first 40, then how many more); there is no
  "all". The helper verbs are `vigil ignore|unignore <id>...`, at most 300
  distinct keyed ids of 16 hex
  digits, and marking takes only detections still in the last scan whose
  file it could read. The note keeps the id and the file's hash, not its
  path or the signature name.
- **Orphaned and foreign packages** are listed as you, read-only, with
  `pacman -Qdti` and `pacman -Qmi` (name, version, description and size;
  4 MiB cap), keeping only names that follow Arch's rules. **Other plugins**
  are listed from `~/.config/omarchy/plugins` without following links
  (except each one's `manifest.json`, for its name). Each
  item is named to the panel by a keyed id (see [Ids](#ids)) of its kind and
  name; for a plugin also what its code can do, so a plugin you kept that
  gains a capability is counted again. It carries its name only for the
  remove command.
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
- Each leftover is named to the panel by a keyed id of its place and name
  (see [Ids](#ids)). File names never reach a command line.
  The verbs are `vigil keep|unkeep <id>...` (Vigil's notes in `kept.json`,
  nothing else, for every list; keeping takes only ids a list shows right
  now) and `vigil trash <id>...`, each
  taking at most 300 distinct ids (a whole list), each checked against the
  pattern on both sides. For trash the panel asks first, on a card that
  lists the ticked items (the first 40, then how many more), and sends
  exactly the ids that card showed (the card's action is
  that id list, and Run accepts it only if every id is still listed and not
  kept). The helper runs the whole check again and moves only ids it
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
- Vigil reads ClamUI's log index (`clamui/logs/log_index.json` in its data
  folder, Flatpak or not) with the no-follow reader and a 2 MiB cap, and
  keeps only the newest timestamp of each kind, matched against a strict
  date pattern: "scan" for the Last run list, "update" for how old the
  virus signatures are. It never reads ClamUI's logs themselves.
- File-change alerts store SHA-256 fingerprints, never contents; symlinks
  are recorded by their target path and never followed.
- Secrets found in shell history are reported by file, line and kind. The
  matched text never leaves the helper.

## Repository hygiene

No agent instruction files, no executables (ELF files), no file over 512 KiB
but the preview, no NUL bytes outside images,
one ID (`keasbeexd.vigil`) everywhere, versions in the manifest and
helper kept equal, MIT licence, and a Removing section in the README that
names every file Vigil can leave behind.

The repository itself is guarded too, since Omarchy installs and updates
plugins straight from the default branch:

- Every push to `master` and every pull request runs the tests
  (`.github/workflows/tests.yml`) with a token that has no permissions, no
  third-party actions (the code is fetched with plain git), only the
  `pull_request` event (never `pull_request_target`), and only pytest and
  its dependencies installed, pinned by SHA-256.
- `SECURITY.md` asks for vulnerabilities to be reported privately, through
  GitHub's private vulnerability reporting. `CODEOWNERS` names the owner
  for every file.
- The repository's settings (branch protection on `master`, secret scanning
  and push protection, private vulnerability reporting, Actions limits) are
  the owner's to keep; they are not in the code.

## Known limits

- Checks read configuration, not live kernel or firewall state that only
  root can see (for example `ufw status`). A check that cannot read
  something says "unknown"; it never assumes the safe answer.
- The startup-file scan is a heuristic. It finds common download-and-run and
  reverse-shell patterns, not obfuscated or novel ones.
- The weekly virus scan skips `.cache`, Steam, container and Flatpak data
  (`.local/share/containers`, `.local/share/flatpak`, `.var`), language
  toolchains (`.npm`, `.cargo`, `.rustup`, `go/pkg`, mise), every
  `node_modules` and `.git` folder, and other filesystems. The daily
  Downloads scan goes 8 folders deep, at most 5,000 files and 10 seconds.
- Vigil cannot prove a machine is not compromised. A compromised account can
  lie to any program running as that account, Vigil included.
