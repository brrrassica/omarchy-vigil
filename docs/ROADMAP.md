# Roadmap

Vigil grows in phases. Each phase ships on its own and keeps the marketplace
rules in [SECURITY-MODEL.md](SECURITY-MODEL.md).

## Phase 1: foundation (0.1, this release)

- [x] Bar shield with score, five-tab panel, keyboard navigation.
- [x] 37 local, read-only checks across Harden, Scan, Privacy and Clean.
- [x] Fixes: six no-root helper actions; terminal actions for root changes,
      each a constant script that explains itself and waits for Enter.
- [x] Omarchy's own security commands (USB, Thunderbolt, FIDO2,
      passwordless sudo, docker group, updates) launched from the panel.
- [x] ClamAV, rkhunter, Lynis and arch-audit installed and run on demand.
- [x] Background re-check with one notification for new findings.
- [x] Tests for every check and fix, for the report contract, and for the
      marketplace review rules.

## Phase 2: one-click hardening and undo

- A root helper with fixed verbs, installed once into
  `/usr/local/libexec/omarchy-vigil/` from a visible terminal, root-owned,
  and called through `pkexec` so every change shows Omarchy's password
  dialog. No sudoers rule. Verbs replace the terminal scripts for the
  `/etc` drop-ins, and each has an undo verb.
- Undo for every change from the panel (today undo is a documented `rm`).
- Dismiss a finding as reviewed, with the reason kept; heuristic findings
  only, never the ones that are direct evidence (as Security Scan does).
- Score history chart from the history Vigil already records.
- `preview.png` and the marketplace submission (see below).

## Phase 3: scanning that reports back

- Scanner results parsed back into the panel instead of only shown in the
  terminal: ClamAV detections, rkhunter warnings, the Lynis hardening index
  and suggestions, arch-audit's vulnerable packages with severity.
- Scheduled scans (opt-in), written by the root helper to
  `/var/lib/omarchy-vigil/` so the unprivileged panel can read them.
- Known-bad AUR package list and npm/PyPI compromise catalog, in the spirit
  of AUR-Malware and Bumblebee, shipped as reviewed data in the repository
  rather than fetched at run time.
- Optional Bumblebee integration when its binary is installed.
- File integrity baseline for a few high-value paths (`/etc/pam.d`,
  `/etc/sudoers.d`, shell startup files) with change alerts.

## Phase 4: privacy depth

- Telemetry host blocking, Bluetooth pairing and Chromium policy, either
  ported from Black Ops (MIT) with attribution or shown through Black Ops'
  `rows.d` status contract when it is installed. Decide with its author.
- Browser hardening checks (third-party cookies, DNS-over-HTTPS) for
  Chromium and Firefox profiles.
- Per-app network activity summary, deferring to OpenSnitch-based plugins
  for blocking.

## Phase 5: beyond the machine

- Password manager and 2FA presence (Compliantish's fifth check).
- Backup status (is there a recent backup, is it encrypted).
- Audit of other installed Omarchy plugins (network, process and file
  capabilities), as Omavet and Plugin Guard do.
- Exportable report (plain text) for a help request or a work laptop audit.

## Ideas to weigh

- Firejail or bubblewrap profiles for risky apps (PDF readers, downloads).
- AppArmor: Arch supports it with a kernel parameter; worth a guided setup.
- Secure Boot with `sbctl`, guided, for people who want it.
- A "travel mode" bundle: firewall strict, Bluetooth and LocalSend off, MAC
  randomised, screen lock short.

## Marketplace submission checklist

- [ ] `preview.png` at the root, under 512 KiB, a real screenshot.
- [ ] `omarchy plugin validate .` passes on an Omarchy machine.
- [ ] Panel exercised on a real Omarchy install: each tab, each helper
      action, and at least the firewall, sysctl and USB terminal actions.
- [ ] Marketplace baseline scanner run locally against the final commit.
      Expect the `privilege`, `package-manager` and `service-management`
      capabilities (sudo, `omarchy-pkg-add` and `systemctl` appear in the
      terminal scripts); these mean manual review, not a block.
- [ ] All fixes on one final commit; submit the `[Plugin]: Vigil` issue with
      that full SHA, category System, tags `bar`, `system`, `security`.
