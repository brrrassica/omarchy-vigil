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

## Phase 4 (0.4, this release): deeper supply chain and detection

- [x] **Exposed secrets**: keys and tokens in shell histories, and credential
      files readable by others (fixable without root). Reports file and
      line, never the secret. Project `.env` files are left out on purpose:
      they are normal in development and would drown the real findings.
- [x] Known malicious AUR packages, from a reviewed list shipped in
      `data/known-bad.json` with a public source per entry; version- and
      install-date-aware. Plus known malware process names.
- [x] arch-audit results in the panel (severity per package, fix available
      or not), refreshed only when you press Check now.
- [x] ClamUI quarantine count, from the number of files in its quarantine
      folder (no dependency on ClamUI's database format).
- [x] File-change alerts for accounts, PAM, SSH and `authorized_keys`,
      system and user services, autostart and startup files, with Accept.
      `/etc/sudoers.d` is root-only, so it cannot be watched without root.
- [x] Read-only capability audit of other Omarchy plugins.

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
