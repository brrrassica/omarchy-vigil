# The landscape: security plugins for Omarchy

Before building Vigil we checked whether someone had already built it. This
is what we found in October 2026, from the marketplace catalog
([plugins.omarchy.org](https://plugins.omarchy.org), about 5,400 plugins) and
a web search, and what Vigil does about each one.

**Short answer:** several plugins call themselves a security hub or posture
monitor, but none combine hardening with fixes, malware scanning, privacy and
cleanup in one panel written for beginners. Most either only report, or need
their own root daemon or a native build. Vigil fills that gap and defers to
the specialised plugins where they go deeper.

## The plugins you named

| Plugin | What it does | How Vigil relates |
|---|---|---|
| [Black Ops](https://github.com/brightwalker25/omarchy-black-ops) (`brightwalker25.black-ops`) | One switch for ~24 privacy protections in Omarchy and common apps: telemetry hosts in `/etc/hosts`, DNS fallback, MAC address and hostname, Chromium policy, connectivity check, Avahi, Bluetooth pairing, opt-out variables, a watchdog that re-checks every 10 minutes, and a root helper with fixed verbs. Very thorough, well tested. | Vigil covers the overlapping basics (DNS fallback, MAC, connectivity, Avahi, opt-out variables) so a newcomer gets them from one place, detects Black Ops, and leaves telemetry blocking to it. Phase 4 considers either porting more of its protections (MIT) or reading its status through its `rows.d` contract. |
| [Bumblebee](https://github.com/duketopceo/omarchy-bumblebee) (`io.github.duketopceo.bumblebee`) | Supply-chain radar: wraps Perplexity's `bumblebee` binary to match lockfiles, packages, extensions and MCP configs against a catalog of known-compromised versions. | Phase 3: an optional "Supply chain" scanner row when `bumblebee` is installed, reusing its catalog approach. Vigil will not download binaries itself. |
| [Security Scan](https://github.com/Percius04/security-scan) (`io.github.elynch303.security-scan`) | Badge for scheduled AUR-Malware and bumblebee scans, a persistence heuristic for autostart/units/crontab, dismissals and history. | Vigil's Startup files check generalises its persistence heuristic (more locations, more patterns) and needs no install step or timer. AUR-Malware integration is deferred: it is a third-party script cloned from a fork, which the marketplace treats as unpinned remote code. |
| [SysCare](https://github.com/cytracon/omarchy-syscare) (`io.github.cytracon.syscare`) | Bar front-end for the SysCare GTK app: CPU, memory, disk, updates, and a safe user-cache clean. | Vigil's Clean tab covers the security-relevant part (thumbnails, trash, package cache, orphans, logs) without needing a separate app. System monitoring stays out of scope. |

## ClamUI

[ClamUI](https://github.com/linx-systems/clamui) (MIT, Flathub
`io.github.linx_systems.ClamUI`) is an actively maintained GTK4 front end for
ClamAV: scan profiles, scheduled scans, removable-drive scans, quarantine with
SHA-256 checks on restore, and an advisory audit. Rather than rebuild it, Vigil
detects it under Detect, opens it, and offers to install it from Flathub.

## Plugins that already aim to be "the security plugin"

| Plugin | Approach | Gap Vigil fills |
|---|---|---|
| [OmaSecurity](https://github.com/ucmz851/omasecurity) (`ucmz851.omasecurity`, unverified) | Posture audit (sysctl, sudoers, firewall, ports, SSH, key permissions, lock) plus a scan of other plugins' code. Fixes are copyable shell commands. | No scanners, no privacy or cleanup, and fixes are commands to paste. Vigil runs fixes for you after confirmation. |
| [Security Posture](https://github.com/omarkamal/omarchy-security-posture) (`io.github.omarkamal.security-posture`, unverified) | Careful, read-only, evidence-based monitor: updates, arch-audit, AUR changes, units, sockets, Docker, SSH, encryption, Secure Boot. Deliberately never changes anything. | Read-only by design. Vigil adds guided fixes, scanners, privacy and cleanup. |
| [Security Hub](https://github.com/btey/omarchy-security-hub-plugin) (`security-hub`, verified, manual setup) | Front-end for `omarchy-securityd`, a Rust daemon with a root helper: threat alerts, USBGuard, security keys, firewall with per-app rules, vaults, sandbox launcher, hardening audit. | Powerful but heavy: a daemon, root services and a downloaded or source-built backend. Vigil needs nothing beyond Omarchy and Python. |
| [Security Sentinel](https://github.com/ozdil/omarchy-security-sentinel) (`ozdil.security-sentinel`, verified) | Rust engine you build with cargo: socket radar, BadUSB guard, CVE radar, auth watch, canary files, DoT toggle, MAC randomiser, EXIF scrubber. | Requires a Rust toolchain and a local build. Vigil uses Omarchy's own USB and Thunderbolt authorization instead of its own. |
| [Compliantish](https://github.com/kenhara/omarchy-compliantish) (`kenhara.compliantish`, verified) | Five Vanta/Drata-style workstation checks: disk encryption, screen lock, antivirus, password manager, auto-updates. | Narrow by design. Vigil covers all five except the password manager (roadmap). |

## Specialised plugins Vigil does not replace

These do one thing deeply. Vigil checks the setting and points you to them
rather than rebuilding them:

- **Firewall rules**: [omarchy-firewall](https://github.com/illegalstudio/omarchy-firewall) (verified), [Omawall](https://github.com/sahzudin/omawall) (verified), [ufw](https://github.com/srozen/omarchy-ufw).
- **Outbound firewall / per-app connections**: [Omasnatch](https://github.com/weedwhitesandwine/omasnatch) (OpenSnitch), [Citadel](https://github.com/NeatOuk/citadel), [Snitch](https://github.com/ccdwyer/omarchy-snitch).
- **USB**: [Omaguard](https://github.com/fcsonline/omaguard) and [USBGuard](https://github.com/Skymebr/omarchy-usbguard). Omarchy now ships `omarchy-setup-security-usb-authorization`, which Vigil uses.
- **Vulnerabilities**: [Cyber Sentry](https://github.com/SiWestworth/omarchy-cyber-sentry) (CISA KEV), [depaudit](https://github.com/thomasvez/omarchy-depaudit) (project dependencies), [CVE Watcher](https://github.com/Bottelet/omarchy-cve-watcher).
- **Plugin auditing**: [Omavet](https://github.com/vonsensey/omavet) and [Plugin Guard](https://github.com/kmpeeduwee/omarchy-plugin-guard) scan your other plugins' code.
- **ClamAV on-access**: [ClamAV Monitor](https://github.com/szentesg/omarchy-clamav-monitor).
- **Login with hardware keys**: [FIDO2 Key Suite](https://github.com/Erijl/omarchy-fido2-key-suite). Omarchy ships `omarchy-setup-security-fido2`, which Vigil uses.

## Outside the marketplace

- [omarchy-hardening](https://github.com/dannymcc/omarchy-hardening) is an
  interactive script (not a plugin) that turns off LLMNR, enables UFW, limits
  SSH to Tailscale and tightens the login lockout. Its author's advice holds
  for Vigil too: read what a change does before you apply it, which is why
  every Vigil fix shows its commands first.
- General Linux tools Vigil drives rather than reimplements: ClamAV,
  arch-audit and osv-scanner, all in the Arch repositories. Rootkit Hunter
  was dropped in 0.12 (last release 2018, many false alarms on Arch) and
  Lynis in 0.13: the few of its checks that help a newcomer are simple
  enough for Vigil to do itself, better suited to Arch.

## What Omarchy already ships

Recent Omarchy has its own security commands, which Vigil surfaces rather
than duplicates: `omarchy-setup-security-usb-authorization`,
`-thunderbolt-authorization`, `-fido2`, `-fingerprint`, `-sshd`,
`-ssh-agent`, `omarchy-sudo-passwordless` and
`omarchy-remove-security-sudoless-docker`. Omarchy also configures ufw
(deny incoming, LocalSend allowed) and a 10-attempt login lockout at install.
