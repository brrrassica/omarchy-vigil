# Roadmap

Vigil is organised in five pillars and grows in phases. Each phase ships on
its own and keeps the rules in [SECURITY-MODEL.md](SECURITY-MODEL.md).

| Pillar | Question | Hands off to |
|---|---|---|
| Harden | Can someone get in? | Omarchy's own security commands |
| Detect | Is something bad already here? | ClamUI for virus scanning and quarantine |
| Supply | Can I trust what I installed? | Perplexity's Bumblebee for known-compromised components |
| Privacy | What am I leaking? | Black Ops for telemetry blocking |
| Care | Is the system tidy and recoverable? | pacman's own tools (paccache, pacman -Rns) and Omarchy's updater |

## Decisions

- **Root steps are constant scripts you see before they run.** Vigil will not
  install a root helper, sudoers rule or polkit policy. Since 0.16 the panel
  shows each script in plain words and as commands, then runs it through
  pkexec, so Omarchy's own password dialog asks and the panel stays open.
  Only Omarchy's interactive tools (and choosing an SSH passphrase) still
  use a terminal. (Until 0.15 every root step ran in a visible terminal;
  closing the panel to type in it got in the way.)
- **Hand off rather than rebuild.** Where a maintained tool already does the
  job well (ClamUI, Bumblebee, Black Ops, Omarchy's own commands), Vigil
  shows its status and opens it. It does not copy it.
- **Maintained sources only.** Vigil keeps no threat lists of its own. It
  checks against what the Arch security team, OSV.dev and the OpenSSF,
  ClamAV, Bumblebee and the AUR publish, refreshed once a week, or by the
  source's own updater (ClamAV's `freshclam` service).
- **No false alarms.** Vigil is for people who want to set it and forget it.
  Only confirmed problems lower the score; anything merely worth knowing is
  information. A check that cannot be made precise is shown as information or
  left out.
- **No scheduling outside the shell.** Background checks are timers inside
  the bar widget; Vigil installs no systemd units or cron jobs, so removing
  the plugin leaves nothing running.

## Phase 1 (0.1): foundation

- [x] Bar shield with score, tabbed panel, keyboard navigation.
- [x] Local, read-only checks; six no-root fixes; terminal actions for root.
- [x] Omarchy's security commands launched from the panel.
- [x] Scanners installed and run on demand.
- [x] Tests for checks, fixes, the report contract and marketplace rules.

## Phase 2 (0.2): pillars and hand-offs

- [x] Five pillars: Harden, Detect, Supply, Privacy, Care (one word each).
- [x] ClamUI: detected (Flatpak or system package), opened from the panel,
      installed from Flathub on request.
- [x] Bumblebee: its last result read (never written) and shown under
      Supply.
- [x] Inventory of other Omarchy plugins.
- [x] Avahi edit made fail-closed: refuses an unexpected file layout, keeps
      the original, rolls back if Avahi does not restart.
- [x] ID `keasbeexd.vigil`, matching the other keasbeexd plugins.

## Phase 3 (0.3): undo, reviewed warnings, history

- [x] Undo from the panel for each `/etc` change, as a terminal action that
      removes a file only while its first line is still Vigil's marker, and
      restores Avahi's original from the backup.
- [x] Mark a warning as reviewed: dimmed, not scored, no notification, and
      back as new if the finding changes. Never for failures, system-wide
      preload, Bumblebee's result or passwordless sudo. No free-text reason
      field: a text box would be one more input to secure for little gain.
- [x] Score history: one score per day for 30 days, as bars on the Overview
      with a hover readout and a one-line summary in words.
- [ ] `preview.png` and the marketplace submission (checklist below).

## Phase 4 (0.4): deeper supply chain and detection

- [x] **Exposed secrets**: keys and tokens in shell histories, and credential
      files readable by others (fixable without root). Reports file and
      line, never the secret. Project `.env` files are left out on purpose:
      they are normal in development and would drown the real findings.
- [x] ~~Known malicious AUR packages from a hand-kept list, and malware
      process names.~~ Replaced in 0.5 by maintained sources.
- [x] arch-audit results in the panel (severity per package, fix available
      or not), refreshed only when you press Check now.
- [x] ClamUI quarantine count, from the number of files in its quarantine
      folder (no dependency on ClamUI's database format).
- [x] File-change alerts for accounts, PAM, SSH and `authorized_keys`,
      system and user services, autostart and startup files, with Accept.
      `/etc/sudoers.d` is root-only, so it cannot be watched without root.
- [x] Read-only capability audit of other Omarchy plugins.

## Phase 4.5 (0.5): maintained sources, no false alarms

- [x] Removed the hand-kept list (`data/known-bad.json`) and the malware
      process-name check, which had no maintained source.
- [x] Known-malicious npm, Bun and other packages from OSV.dev (OpenSSF
      Malicious Packages) through osv-scanner, over AUR build folders and
      global npm, Bun, mise and pnpm installs. Catches the 2026 Atomic Arch
      AUR attack (`bun install js-digest`) and the Bun-based npm worms. Only
      `MAL-` entries count.
- [x] arch-audit limited to problems an update fixes (`--upgradable`), shown
      as a warning rather than a failure.
- [x] AUR package status from the AUR itself: packages that left the AUR,
      moved to the official repositories, or have no maintainer.
      Information only. There is no maintained feed of malicious AUR packages.
- [x] Weekly refresh of all three (`autoUpdate`, on by default), with a
      retry after a day on failure; ClamAV signatures through ClamAV's own
      `clamav-freshclam` service, turned on when Vigil installs ClamAV or
      ClamUI; rkhunter data updated before each run.
- [x] False-alarm pass: file changes that match what a package shipped
      (pacman's mtree records) and system users added by packages are not
      reported; `/etc/hosts` is no longer watched; only changes to who can log
      in or what runs at start are warnings. Secret detection uses provider
      formats only. Bumblebee staleness, plugin capabilities and AUR status
      are information. Disk encryption, unfixable without a reinstall, is a
      warning that can be marked as reviewed.

## 0.30.0 (this release): leftovers, and a clearer Overview and Care tab

- [x] **Leftover app data** on the Care tab: settings and data in
      `~/.config`, `~/.local/share`, `~/.local/state` and the dot-folders
      in `~` that nothing on the computer uses any more (no package, what
      packages provide, program, desktop entry, Flatpak, Omarchy config,
      running program or startup file answers to the name, and nothing in
      it changed for 30 days); Flatpak data in `~/.var/app` of apps no
      longer installed; links in `~/.local/bin` to programs that are gone;
      launchers in `~/.local/share/applications` that start nothing.
      Information only: it never lowers the score or notifies.
- [x] One line per item, to tick and then **Trash** (asks first) or
      **Keep** (Vigil's notes only; the item's lock undoes it). The trash is the
      freedesktop.org trash every file manager reads, so Restore puts an
      item back; nothing is deleted, and leftovers are never part of Clean
      all. Before it moves anything the helper checks again that nothing
      uses the item and that you did not keep it.
- [x] Overview redesign: the Pillars list is gone. Each tab carries its
      most important count right under it (to fix, to improve, notes, all
      good; the tooltip has every count), Overview the total of the four
      security pillars, and Care sits past a divider with "to tidy". The run
      buttons sit under **Run now**, each with when that check next runs by
      itself under it, in place of three countdown lines. The title line
      says when Vigil last checked instead of repeating the score.
- [x] Care is shown as separate from security everywhere: a line on the
      Overview, one on the Care tab, and one on the daily and Run all
      cards say it never counts toward the score and no run cleans
      anything.
- [x] Every tab groups its rows under headings that say which check brings
      them in (Always current, with when those rows are read; Daily check,
      Weekly check), when it has more than one. The Care tab splits **In Clean all** from
      **Not in Clean all**: Orphaned packages and Leftover app data sit at
      the bottom, under a heading and a line that say Clean all never
      touches them.
- [x] Key hints show the keys of the tab you are on (C for Clean all on
      Care). The Detect tab's intro no longer promises rootkit checks Vigil
      stopped running; it names what it does check.
- [x] One naming convention. Runs are the only things called a check:
      the Daily check and the Weekly check. Steps say what they do: a scan
      reads this computer (Virus scan of ~, Bumblebee scan, Arch security
      scan, OSV malware scan, Password scan), a lookup asks a tool or a
      service (System update lookup, Flatpak update lookup, AUR status
      lookup, Firmware lookup), and a list is downloaded (Bumblebee list,
      Virus signatures). Rows name what is examined, with the tool in brackets: System
      updates, Flatpak updates, Firmware updates, Infected files (ClamAV),
      Virus signatures (ClamAV), Known vulnerabilities (arch-audit),
      Known-malicious packages (OSV), Known-compromised packages (Bumblebee),
      Duplicate scan schedules. Check ids stay the same, so reviews, kept
      leftovers and false positives carry over. Reading your settings and
      files is not a run: those rows are headed **Always current**, with a
      line saying when they are read.
- [x] **Every scan gets its list right before it runs.** There is no
      separate list update any more (its button, countdown, `U` key and
      tab heading are gone). The daily check runs the Arch security scan
      (arch-audit downloads the tracker as it scans), the OSV malware scan
      (osv-scanner asks OSV.dev as it scans), the AUR status lookup, the
      Bumblebee list followed by the Bumblebee scan, and Virus signatures
      followed by the virus scan of new downloads; the weekly check checks
      the signatures again right before the virus scan of `~`. These
      lookups move from weekly to daily: a few MB a day more.
- [x] Virus signatures are ClamAV's job: its own update service keeps them
      current, and Vigil checks them before every virus scan. The daily and
      weekly checks never ask for a password. Over two days old (the
      service fell behind), Vigil sends one notification a day pointing to
      Run all, which updates them first, behind your password and with the
      command on its card. Run all's password scan and that update are the
      only password prompts in any run. The Virus signatures row lost its
      own Update now button: Run all is the one way to force an update.
- [x] Every scan says which list or signatures it used ("with the list
      from Oct 14"). The line turns the theme's red only when that list was
      over 48 hours old when the scan ran (not 24, and judged at scan time,
      so a week-old scan with a fresh list stays as it is).
- [x] A failed list download no longer stops a scan: it uses the last good
      list, and its row and its Last run line say "with the list from Oct 1".
      The Last run list groups every scan and lookup under the run that
      does it, and has no lines for the lists themselves.
- [x] No run installs or updates Bumblebee. Only Install, or Install
      Bumblebee on its row once a Vigil update has raised the pinned
      version, puts the reviewed version in place.
- [x] Panel review: the Overview tab has no caption (its tooltip is the
      score); the panel is 60 units wider and the tabs use slightly less
      padding, so six tabs and their captions fit at larger fonts; the tabs
      use the same unfilled button style as the rest of the panel. The virus
      scan row sits under **Daily and weekly checks** and names both scans
      with their run. The Downloads scan records its signatures even when
      there was nothing new to scan. Bumblebee no longer names its list,
      since it downloads the newest right before every scan; only a scan
      that fell back to the last good list says which.
- [x] Leftovers are ticked, not handled one button at a time: below the
      list, **Trash** and **Keep** act on every item not kept (Trash all,
      Keep all) or, once you tick some, on just those (Trash selected,
      Keep selected). Each item reads as two lines (where and how big,
      then why and since when) beside a small tick box. Any confirmation
      card now scrolls the panel to the top, where it opens, wherever the
      button was.
- [x] System logs under 500 MB count as tidy: no cleanup offered, and not
      part of Clean all.
- [x] **Every list works the same way.** Orphaned packages, AUR and other
      foreign packages, other Omarchy plugins and infected files are listed
      like leftovers: one item per line on two lines, a small box to tick,
      and buttons under the list that say how many they act on. Orphans:
      Remove all or Remove selected (`pacman -Rns`, behind your password,
      replacing the terminal review through `omarchy-update-orphan-pkgs`),
      Keep. Foreign packages: Remove selected only, Keep. Plugins: Remove
      selected only, through Omarchy's own `omarchy-plugin-remove`, as you,
      Keep. Infected files: False positive selected, on one card. Every
      card lists each item and shows the exact command; package names and
      plugin ids are the arguments of a constant script that checks them
      again (as root, for packages, also that pacman still lists each) and
      removes nothing if one fails.
- [x] A kept item, or a false positive, shows a lock in place of its box and
      moves to the bottom of its list; clicking the lock counts it again. A
      plugin you kept is counted again if its code gains a capability. Kept
      items are now one list, `kept.json`, for every row (an earlier
      build's `kept-leftovers.json` is read and folded in). Those rows lose
      Mark as reviewed, since Keep reviews them item by item.
- [x] Severity colours, from the theme: each plugin capability in red
      (root, downloads and runs code, compiled binaries), yellow (network,
      shell commands, a linked install that was not scanned) or green
      (none found); each infected file's signature in red (known malware)
      or yellow (a heuristic guess). The lock alone marks a kept item or a
      false positive, without words.
- [x] **Keyed ids.** Every id Vigil hands the panel, puts on a command line
      or writes to its notes (kept items, false positives, reviewed and seen
      findings) is an HMAC-SHA256 under a random key made for this install
      (`id-key`, mode 0600), not a plain SHA-256 that could be reversed by
      hashing every package or plugin name. `kept.json` holds only ids and
      dates, and false positives only the id and the file's hash and times
      (no path, no signature name). Notes from before are carried over once,
      after a full check, and their names dropped. This hides what you trust
      from copies of the notes and from other accounts; it cannot hide it
      from a program running as you, which can read the key, and the docs say
      so.
- [x] Nothing is cut short: check results, trash and keep messages are
      shown whole (up to 2000 characters, the same limit on both sides),
      and summaries and how-to texts get the panel's own limits. On the
      Overview's Last run list, the list a scan used ("with signatures from
      Oct 14") sits on its own line under when it ran, so no line wraps.
- [ ] Later: show launchers that point to a program by name rather than
      by path, once there is a reliable way to know the PATH your session
      uses.

## 0.29.0: the design rules, checked against the code

- [x] Every confirmation card shows the exact commands Run starts, below
      the Run and Cancel buttons: each root step in full (the pkexec argv,
      then the script as it is passed), the scripts that run as you, and
      the command a terminal runs. The run cards show the helper's root
      steps the same way: the ClamAV signatures and Bumblebee update, and
      in Run all the password check. A test checks they are the very
      scripts the helper starts.
- [x] Let Vigil run them leaves ClamUI alone when any ClamUI schedule,
      Arch or Flatpak (they share one timer), covers folders outside your
      home folder or cannot be checked.
- [x] The hand-over, Stop auto-joining and their Undos refuse a link, or
      a folder that is not yours, anywhere from `~/.local` to their own
      folder; markers and the list of changed networks are fresh files
      renamed into place, so a link planted at their names is replaced,
      never written through. Stop auto-joining keeps its list even when a
      step fails, so Undo still knows every network it changed.
- [x] Omarchy's plugin commands are named by absolute path, from the same
      trusted lookup as Omarchy's other commands.
- [x] Add a passphrase prints key names with `printf %q`, so a name
      cannot send control codes to the terminal.
- [x] Removing the plugin stops a scan or update that is running within
      seconds: the helper looks for its own file every five seconds.
- [x] The design rules, the README and the helper's own description say
      what the code does: the daily and weekly network checks are listed,
      every button that installs Bumblebee is named, and the FireWire
      setting is in the list of files Vigil writes.

## 0.28.3: SSH key names stay out of process lists

- [x] Add a passphrase hands each SSH key to grep and ssh-keygen by
      descriptor (stdin, `/proc/self/fd/3`) instead of by path, so the
      key file names are not in `/proc/<pid>/cmdline` while ssh-keygen
      waits for the passphrase.

## 0.28.2: readable hints on every theme

- [x] Secondary text (the key hints, times, descriptions) uses the theme's
      text colour darkened, as mouse-ctrl does, instead of the theme's
      muted colour, which some themes set close to the background.

## 0.28.1: file names stay out of process lists

- [x] The scan that double-checks a virus detection hands clamscan its
      file paths in a private list file, like the Downloads scan, instead
      of as arguments other accounts could read in `/proc/<pid>/cmdline`.

## 0.28: ready for the marketplace

- [x] Bumblebee is pinned: Vigil installs exactly 0.1.2, checked against
      the SHA-256 written in its own code, with the download capped in
      bytes while it streams. The release check and the automatic update
      to newer releases are gone (a checksum from the same release only
      binds those bytes to themselves); a newer Bumblebee comes with a
      Vigil update. Replaces 0.22.
- [x] README, manifest and security model describe every network contact
      (checkupdates, Flatpak, fwupd, Perplexity on GitHub) and no longer
      claim Vigil sends nothing anywhere.

## 0.25 to 0.27: one name per thing, one button per schedule

- [x] Every scan and update has one name, used in the schedule lines, the
      Last run list, the progress line and the tabs, all in schedule order.
- [x] Run daily check, Run weekly check, Run update check and Run all
      replace Full scan and Update sources. Run all does not scan
      ~/Downloads twice. Each button restarts its own countdown.
- [x] The scroll bar has its own lane, in the theme's colours.

## 0.24: daily and weekly

- [x] A daily check: what is new in Downloads (virus scan), waiting
      system, Omarchy and Flatpak updates, and Bumblebee over your
      packages. Weekly stays for the lists, the whole home folder and
      firmware. The Overview shows the next time of each.
- [x] App updates (Flatpak): checked daily, installed by Update sources
      (your own apps, no password).
- [x] Open Wi-Fi that joins by itself, with Stop auto-joining and Undo.
- [x] ClamUI from the Arch repositories, so Omarchy's updater keeps it
      current.
- [x] A detected file that is gone (deleted, quarantined) stops counting.

## 0.23: a lighthouse

- [x] The bar icon is a lighthouse instead of a shield (so many plugins use
      one); its beams show while a scan or update runs.

## 0.22: Bumblebee stays current (replaced in 0.28)

- [x] Bumblebee follows Perplexity's releases: the newest one that has been
      out for a week, checked against Perplexity's published SHA-256. The
      row offers Update Bumblebee, and Update sources installs it behind
      the same password prompt as the virus signatures.

## 0.21: resource and security pass

- [x] Nothing loops or repeats hours of work: every background error counts
      as tried, the automatic run starts at most every six hours, a virus
      scan that runs out of time waits a week; checks and runs at lowered
      priority; a progress bar weighted by how long each step takes.
- [x] From an independent review: Bumblebee pinned by a SHA-256 in Vigil
      (not the release's own checksums) and never installed through a link;
      the catalog archive unpacked with a hard memory cap; the hand-over
      script re-checks what it turns off; virus detections confirmed by a
      second scan of each file, names with line breaks flagged, detections
      capped at 500; checkupdates' databases in Vigil's private folder.

## 0.20: updates and firmware

- [x] System updates says when a newer Omarchy is out (checkupdates, in
      Update sources and the Full scan) and offers Omarchy's updater.
- [x] Firmware updates: the Full scan asks fwupd (LVFS); a firmware
      security fix is a warning, with Omarchy's `omarchy-update-firmware`.
      fwupd joins the red Install button.
- [x] 0.20.1: after an update, the panel no longer fails with "could not
      read": the shell keeps the old panel loaded until it restarts, so the
      panel compares versions and offers **Restart shell**. Names it does
      not know yet (a new source or helper) are skipped, and any other
      rejection says which part failed.

## 0.19: false positives

- [x] **False positive** next to each virus detection: asks first, then
      stops counting that exact file (by SHA-256) until it changes.

## 0.18: one schedule

- [x] "Scans scheduled twice" (Detect): finds other apps that repeat
      Vigil's weekly work (a ClamUI scheduled scan of folders inside your
      home folder, the older Bumblebee plugin) and offers **Let Vigil run
      them**, which turns those off the way you would in each app, with an
      Undo that turns back on exactly what it changed. Broader ClamUI scans
      and the Security Scan plugin (AUR-Malware) are listed and left on.

## 0.17: Bumblebee from Perplexity, one run at a time

- [x] Bumblebee comes straight from Perplexity: **Install** fetches a pinned
      release and installs it only if it matches the release's published
      SHA-256. The weekly update downloads Perplexity's `threat_intel`
      catalogs; each Full scan runs Bumblebee against them. The third-party
      Omarchy wrapper plugin is no longer needed. Black Ops stays out.
- [x] When a helper is missing, a red **MISSING … INSTALL** button takes the
      place of **Update sources** and installs all of them at once.
- [x] Full scan runs Bumblebee before the long virus scan, and the Last run
      list updates as each step finishes.
- [x] Bumblebee scans work with Perplexity's current lists: they moved to a
      newer format the released program does not read, so Vigil converts
      them, checking each entry.
- [x] One scan or update at a time, even across monitors and shell
      restarts (a lock the kernel drops when the run ends, held by clamscan
      too). A panel that did not start the run shows "Already running" with
      its progress.
- [x] Installs, fixes and Clean all show a progress bar while they run;
      the install says which of its four steps it is on.
- [x] 0.17.2: USB and Thunderbolt authorization dropped. Omarchy shipped
      approval for new devices briefly (edge and dev) and removed it again,
      commands included, so the buttons pointed at commands that no longer
      exist.
- [x] 0.17.3: fingerprint login. On a computer where Omarchy's own detector
      finds a fingerprint reader, the "Security key or fingerprint" row
      offers **Set up fingerprint** (Omarchy's setup, in a terminal, since you
      touch the sensor). Once a fingerprint or security key is set up, the row
      offers Omarchy's removal command as its Undo.
- [x] 0.17.4: **Stop** under the progress bar ends a Full scan or update,
      including one left running after a shell restart. Finished steps are
      kept; the rest waits a day before the weekly run tries again.

## 0.16: no terminal pop-ups

- [x] Fixes, Undo, Clean all and installs run from the panel: the
      confirmation explains them, then Omarchy's password dialog asks
      (pkexec), and a result card shows what happened. Packages come from
      pacman directly. Only tools that ask questions as they go keep a
      terminal.
- [x] Exposed secrets: **Remove those lines** deletes the leaked-key lines
      from your shell history directly (whole entries in fish).
- [x] Update sources also updates ClamAV's virus signatures (asks for your
      password); the Overview shows when ClamAV last checked.
- [x] Fixed: the Full scan password check never ran on Arch (`awk` is a
      link, which Vigil never runs as root); it now runs through bash.
- [x] The countdowns stay visible while a scan runs.
- [x] 0.16.2: countdowns show the time (local timezone) and are exact to the
      minute; button results stay on a card until closed. Fixed: Update
      sources could not update signatures while ClamAV's service ran (it now
      wakes the service), and Full scan skipped Bumblebee on Arch, where
      python3 is a link (now resolved to the trusted file; a Bumblebee that
      cannot run is reported, not skipped).
- [x] 0.16.1: the Last run list counts work done outside Vigil: ClamAV's own
      signature service and ClamUI's updates and scans (from ClamUI's log
      index), marked "by ClamUI" where it was ClamUI.

## 0.15: Full scan with progress, and a schedule you can see

- [x] Full scan opens no terminal: the password check uses Omarchy's own
      password dialog (pkexec), first, while you are at the screen. A progress
      bar shows each step and, during the virus scan, files done of the total.
- [x] Two weekly timers with countdowns on the Overview: the next automatic
      update and the next automatic full scan (everything but the password
      check). Each button resets its own.
- [x] The virus scan always covers the home folder (Downloads included), and
      its row's Scan now runs in the background with progress.
- [x] **Last run** on the Overview: when each scan last ran and each source
      last updated, with the time.
- [x] Every terminal explains itself the same way: what it does, what
      changes for you, then a "Technical:" line, and whether it will ask for
      your password.

## 0.14: a simpler Overview, a real Full scan

- [x] Overview: the score, **Full scan** and **Update sources**, one line
      with the last update and a countdown to the next automatic one, then
      the pillars with how many findings each has to fix, to improve and for
      information. The source list, the 30-day chart and "Fix these first"
      are gone.
- [x] **Full scan** (`R` or `S`) runs everything: sources, a virus scan of
      the whole home folder, a Bumblebee rescan, the password check, every
      setting; a notification says when it is done.
- [x] Rows with nothing to do are dimmed in the pillar tabs.
- [x] Every colour comes from the Omarchy theme (urgent, accent, muted,
      text), the bar shield included; the scroll bar is themed and has its
      own gutter, so it no longer covers text.

## 0.13: Lynis retired

- [x] Vigil does the checks Lynis was kept for: other root accounts and
      shared IDs (from `/etc/passwd`), accounts without a password (Full
      scan's one sudo step, a single `awk` over `/etc/shadow`), hidden shell
      history, and old network services (telnet, rsh, rlogin, FTP, TFTP,
      NIS, xinetd) as systemd units, with **Switch them off**. Lynis's
      versions looked for Debian package names and never matched on Arch.
- [x] One helper fewer: nothing to install for a Full scan.

## 0.12: Full scan, and only what helps a newcomer

- [x] Two buttons instead of one: **Full scan** (`S`) checks everything,
      including the checks that need a password, with one sudo prompt in a
      terminal; **Update sources** (`U`) only refreshes the lists Vigil
      checks against, with no password and no scan.
- [x] Lynis cut down to three test groups and eight tests that matter on a
      personal computer (other root accounts, accounts without a password or
      sharing an ID, hidden shell history, old insecure network servers),
      each in plain words with how to fix it. The overlap logic with Vigil's
      own checks is gone: nothing Lynis shows overlaps them.
- [x] New: **Restart after updates**, when a newer kernel is installed than
      the one running.
- [x] No longer suggested, because a newcomer gains too little or risks too
      much: Rootkit Hunter (last released 2018, many false alarms on Arch),
      setting up Secure Boot, and turning off rarely used network protocols
      (still shown, with Undo, where an earlier Vigil turned them off).

## 0.11: every finding explains itself

- [x] Every finding: **Why it matters** in one or two sentences, **How to
      fix**, and a button: Fix, or Learn more / Show (a guide or a read-only
      command), and Undo once Vigil changed something.
- [x] **Mark as reviewed** on every finding that is not passing, kept
      through later checks and Lynis runs; evidence findings come back only
      when something new is found.
- [x] Lynis findings are rows in the pillars (named from Lynis's own test
      list), with Learn more and Mark as reviewed.
- [x] New: rarely used network protocols and FireWire (with Undo), which
      also answer Lynis NETW-3200 and STRG-1846; Add a passphrase for SSH
      keys; screen lock reset to Omarchy's 5-minute default.
- [x] Clean all fixed: the trash is emptied without a desktop session, the
      package cache also drops removed packages and shows what can be freed,
      and unused application caches are cleared.

## 0.10: Clean all, Lynis in the panel

- [x] **Clean all** on the Care tab (and `C`): one confirmation listing every
      cleanup on offer with its size; the no-root ones run at once, the root
      ones share one terminal. Orphaned packages stay a separate step.
- [x] Lynis results in the panel instead of a wall of text: hardening index,
      warnings and suggestions, Lynis's own fix where it gives one, and where
      to read more. Information only.
- [x] Lynis findings that a Vigil check covers are left out and named, matched
      by Lynis test ID (verified against Lynis's `db/tests.db`) and, for
      kernel settings, per setting.

## 0.9: easier to read

- [x] The Overview leads with a large bold score and a bold one-line verdict,
      with the check time in small dim text underneath.
- [x] Sections (Updates, Last 30 days, Pillars, Fix these first) use
      Omarchy's own small-caps section label.
- [x] Each tab opens with its question in bold, then what it covers in dim
      text. Pillar names and finding titles are bold; problem counts are
      coloured; "Reviewed on" and status messages are in italics.
- [x] An open finding labels its explanation and details ("Why it matters",
      "Details").

## 0.8: first real-machine test

Tested on Omarchy: the widget loads, every check ran with no false alarms,
and osv-scanner is in Arch's `extra` repository.

- [x] Fixed: the widget did not load (`ShellIpc` is internal to Omarchy;
      now `IpcHandler`), with a test that every QML type is one plugins can use.
- [x] Update messages separate what was refreshed ("the Arch vulnerability
      database") from what was found on this machine, so a refresh never
      reads as a finding. Source names on the Overview name the database or
      scan.
- [x] Warnings cost 2 points per weight instead of 4; failures unchanged. A
      typical Omarchy machine with only privacy improvements left no longer
      scores in the 50s.

## 0.7: source dates on the Overview

- [x] The Overview lists when the last full update ran and whether every
      source updated, and each set-up source with its last successful update;
      failed or week-old sources are shown in red with the date they last
      worked.

## 0.6: one schedule, one button

- [x] Weekly virus scan of `~/Downloads` with ClamAV, as the user, in the
      same weekly cycle as the sources; infected files hand off to ClamUI.
- [x] **Update and check everything** button (and `U`): refreshes every
      available source and runs the virus scan now, then re-checks every
      pillar. Reports back; the weekly run stays quiet.
- [x] "When Vigil runs what" table in the README.

## Phase 5: privacy and recovery

- Black Ops status through its `rows.d` contract when installed.
- Browser hardening checks for Chromium and Firefox profiles.
- Snapshot and backup status (`omarchy-snapshot`, recent backups, whether
  they are encrypted), and a short "what to do if Vigil finds something"
  guide in the panel.

## Ideas to weigh

- A "travel mode" bundle: firewall strict, Bluetooth and LocalSend off, MAC
  randomised, short screen lock.
- AppArmor and Secure Boot (`sbctl`) as guided Omarchy-style setups.
- Firejail or bubblewrap profiles for risky apps.

Deliberately out of scope: VPN, outbound firewalls, password managers.
Dedicated plugins do these well; Vigil may show their status.

## Marketplace submission checklist

- [x] `preview.png` at the root, under 512 KiB, a real screenshot.
- [ ] `omarchy plugin validate .` passes on an Omarchy machine.
- [ ] Panel exercised on a real Omarchy install: each tab, each helper
      action, Open ClamUI, Stop, Let Vigil run them and its Undo, and at
      least the firewall, sysctl and Avahi actions.
- [ ] Marketplace baseline scanner run locally against the final commit.
      Expect the `privilege`, `package-manager` and `service-management`
      capabilities (sudo, `omarchy-pkg-add` and `systemctl` in the terminal
      scripts); these mean manual review, not a block.
- [ ] All fixes on one final commit; submit the `[Plugin]: Vigil` issue with
      that full SHA, category System, tags `bar`, `system`, `security`.
