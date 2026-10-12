# Roadmap

Vigil is organised in five pillars and grows in phases. Each phase ships on
its own and keeps the rules in [SECURITY-MODEL.md](SECURITY-MODEL.md).

| Pillar | Question | Hands off to |
|---|---|---|
| Harden | Can someone get in? | Omarchy's own security commands |
| Detect | Is something bad already here? | ClamUI for virus scanning and quarantine |
| Supply | Can I trust what I installed? | Bumblebee for known-compromised components |
| Privacy | What am I leaking? | Black Ops for telemetry blocking |
| Care | Is the system tidy and recoverable? | Omarchy's orphan and update commands |

## Decisions

- **Root changes run in a visible terminal, permanently.** Vigil will not
  install a root helper, sudoers rule or polkit policy. Every privileged step
  is a constant script you see before it runs, or an Omarchy command.
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

## 0.14 (this release): a simpler Overview, a real Full scan

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

- [ ] `preview.png` at the root, under 512 KiB, a real screenshot.
- [ ] `omarchy plugin validate .` passes on an Omarchy machine.
- [ ] Panel exercised on a real Omarchy install: each tab, each helper
      action, Open ClamUI, and at least the firewall, sysctl, Avahi and USB
      terminal actions.
- [ ] Marketplace baseline scanner run locally against the final commit.
      Expect the `privilege`, `package-manager` and `service-management`
      capabilities (sudo, `omarchy-pkg-add` and `systemctl` in the terminal
      scripts); these mean manual review, not a block.
- [ ] All fixes on one final commit; submit the `[Plugin]: Vigil` issue with
      that full SHA, category System, tags `bar`, `system`, `security`.
