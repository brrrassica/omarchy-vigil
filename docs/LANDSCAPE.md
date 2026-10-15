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
| [Black Ops](https://github.com/brightwalker25/omarchy-black-ops) (`brightwalker25.black-ops`) | One switch for ~24 privacy protections in Omarchy and common apps: telemetry hosts in `/etc/hosts`, DNS fallback, MAC address and hostname, Chromium policy, connectivity check, Avahi, Bluetooth pairing, opt-out variables, a watchdog that re-checks every 10 minutes, optional listen and watch modes, and a root helper with fixed verbs. Very thorough, well tested. | Since 0.31 Vigil no longer detects it or leaves telemetry to it. It carries the settings over as buttons you press once (telemetry hosts, Chromium policy, agent and developer-tool opt-out variables, the weather location, plus the DNS, MAC, connectivity and Avahi rows it already had), with Undo and no watchdog, listener or service. Left out because they need something running or edit another program's files: the Bluetooth pairing guard, web app profiles, the Agents panel rows, Neovim and Proton VPN settings, the LAN route, listen and watch modes. Vigil recognises what Black Ops set by reading the files, so the two can coexist; use one. |
| [omarchy-security-scan](https://github.com/brightwalker25/omarchy-security-scan) (`brightwalker25.security-scan`) | Six scans on systemd timers (arch-audit, AIDE, picklescan for AI models, gitleaks, rkhunter, Lynis), a risk register and a weekly HTML report; installed by a root installer. | Vigil took the ideas that fit its rules and wrote them again: gitleaks weekly (a repository cannot switch its own findings off), rkhunter in Run all only (with the pacman check that explains the usual false alarms), and a pickle reader of its own for AI model files, with no PyPI dependency. It runs no timers and installs no root units; AIDE, Lynis, the risk register and the HTML report were left out (see the roadmap). |
| [Bumblebee](https://github.com/duketopceo/omarchy-bumblebee) (`io.github.duketopceo.bumblebee`) | Supply-chain radar: wraps Perplexity's `bumblebee` binary to match lockfiles, packages, extensions and MCP configs against a catalog of known-compromised versions. | Vigil now runs Perplexity's [Bumblebee](https://github.com/perplexityai/bumblebee) directly: it installs Bumblebee 0.1.2, the version it was reviewed with, only if it matches the SHA-256 written in Vigil's code, and downloads Perplexity's newest list right before each daily scan, so this wrapper is no longer needed. |
| [Security Scan](https://github.com/Percius04/security-scan) (`io.github.elynch303.security-scan`) | Badge for scheduled AUR-Malware and bumblebee scans, a persistence heuristic for autostart/units/crontab, dismissals and history. | Vigil's Startup files check generalises its persistence heuristic (more locations, more patterns) and needs no install step or timer. AUR-Malware integration is deferred: it is a third-party script cloned from a fork, which the marketplace treats as unpinned remote code. |
| [SysCare](https://github.com/cytracon/omarchy-syscare) (`io.github.cytracon.syscare`) | Bar front-end for the SysCare GTK app: CPU, memory, disk, updates, and a safe user-cache clean. | Vigil's Care tab covers the security-relevant part (thumbnails, trash, unused application caches, package cache, logs, and, ticked item by item, orphaned packages to remove or keep and data left behind by removed apps to trash or keep) without needing a separate app. System monitoring stays out of scope. |

## ClamUI

[ClamUI](https://github.com/linx-systems/clamui) (MIT, in Arch's extra repository as `clamui`,
and on Flathub as `io.github.linx_systems.ClamUI`) is an actively maintained GTK4 front end for
ClamAV: scan profiles, scheduled scans, removable-drive scans, quarantine with
SHA-256 checks on restore, and an advisory audit. Rather than rebuild it, Vigil
detects it under Detect, opens it, and installs it from the Arch repositories, so Omarchy's
updater keeps it current.

## Plugins that already aim to be "the security plugin"

| Plugin | Approach | Gap Vigil fills |
|---|---|---|
| [OmaSecurity](https://github.com/ucmz851/omasecurity) (`ucmz851.omasecurity`, unverified) | Posture audit (sysctl, sudoers, firewall, ports, SSH, key permissions, lock) plus a scan of other plugins' code. Fixes are copyable shell commands. | No scanners, no privacy or cleanup, and fixes are commands to paste. Vigil runs fixes for you after confirmation. |
| [Security Posture](https://github.com/omarkamal/omarchy-security-posture) (`io.github.omarkamal.security-posture`, unverified) | Careful, read-only, evidence-based monitor: updates, arch-audit, AUR changes, units, sockets, Docker, SSH, encryption, Secure Boot. Deliberately never changes anything. | Read-only by design. Vigil adds guided fixes, scanners, privacy and cleanup. |
| [Security Hub](https://github.com/btey/omarchy-security-hub-plugin) (`security-hub`, verified, manual setup) | Front-end for `omarchy-securityd`, a Rust daemon with a root helper: threat alerts, USBGuard, security keys, firewall with per-app rules, vaults, sandbox launcher, hardening audit. | Powerful but heavy: a daemon, root services and a downloaded or source-built backend. Vigil needs nothing beyond Omarchy and Python. |
| [Security Sentinel](https://github.com/ozdil/omarchy-security-sentinel) (`ozdil.security-sentinel`, verified) | Rust engine you build with cargo: socket radar, BadUSB guard, CVE radar, auth watch, canary files, DoT toggle, MAC randomiser, EXIF scrubber. | Requires a Rust toolchain and a local build. Vigil does not guard USB ports: Omarchy tried approval for new USB and Thunderbolt devices and removed it again. |
| [Compliantish](https://github.com/kenhara/omarchy-compliantish) (`kenhara.compliantish`, verified) | Five Vanta/Drata-style workstation checks: disk encryption, screen lock, antivirus, password manager, auto-updates. | Narrow by design. Vigil covers all five except the password manager, which is deliberately out of scope. |

## Specialised plugins Vigil does not replace

These do one thing deeply. Vigil checks the setting and points you to them
rather than rebuilding them:

- **Firewall rules**: [omarchy-firewall](https://github.com/illegalstudio/omarchy-firewall) (verified), [Omawall](https://github.com/sahzudin/omawall) (verified), [ufw](https://github.com/srozen/omarchy-ufw).
- **Outbound firewall / per-app connections**: [Omasnatch](https://github.com/weedwhitesandwine/omasnatch) (OpenSnitch), [Citadel](https://github.com/NeatOuk/citadel), [Snitch](https://github.com/ccdwyer/omarchy-snitch).
- **USB**: [Omaguard](https://github.com/fcsonline/omaguard) and [USBGuard](https://github.com/Skymebr/omarchy-usbguard). Omarchy shipped approval for new USB and Thunderbolt devices briefly (edge and dev, #11874) and then removed it, uninstalling the USBGuard it had set up. Vigil leaves USB alone: a wrong USB policy can lock a beginner out of their own keyboard.
- **Vulnerabilities**: [Cyber Sentry](https://github.com/SiWestworth/omarchy-cyber-sentry) (CISA KEV), [depaudit](https://github.com/thomasvez/omarchy-depaudit) (project dependencies), [CVE Watcher](https://github.com/Bottelet/omarchy-cve-watcher).
- **Plugin auditing**: [Omavet](https://github.com/vonsensey/omavet) and [Plugin Guard](https://github.com/kmpeeduwee/omarchy-plugin-guard) scan your other plugins' code more deeply; Vigil lists what each plugin's code can do, colored by how much it deserves a look.
- **ClamAV on-access**: [ClamAV Monitor](https://github.com/szentesg/omarchy-clamav-monitor).
- **Login with hardware keys**: [FIDO2 Key Suite](https://github.com/Erijl/omarchy-fido2-key-suite). Omarchy ships `omarchy-setup-security-fido2`, which Vigil uses.

## Outside the marketplace

- [omarchy-hardening](https://github.com/dannymcc/omarchy-hardening) is an
  interactive script (not a plugin) that turns off LLMNR, enables UFW, limits
  SSH to Tailscale and tightens the login lockout. Its author's advice holds
  for Vigil too: read what a change does before you apply it, which is why
  every Vigil fix shows its commands first.
- General Linux tools Vigil drives rather than reimplements: ClamAV,
  arch-audit, osv-scanner and gitleaks, all in the Arch repositories. Rootkit
  Hunter was dropped in 0.12 and came back in 0.31, for Run all only, with
  warnings about package-owned programs explained away by pacman's own
  records. Lynis was dropped in 0.13: the few of its checks that help a newcomer are simple
  enough for Vigil to do itself, better suited to Arch.

## What Omarchy already ships

Recent Omarchy has its own security commands, which Vigil surfaces rather
than duplicates: `omarchy-setup-security-fido2`, `-fingerprint`, `-sshd`,
`-ssh-agent`, `omarchy-sudo-passwordless` and
`omarchy-remove-security-sudoless-docker`. Omarchy also configures ufw
(deny incoming, LocalSend allowed) and a 10-attempt login lockout at install.
