# Vigil

A security suite for [Omarchy](https://omarchy.org): one shield in the bar,
one panel, five pillars.

| Pillar | The question it answers |
|---|---|
| **Harden** | Can someone get in? Firewall, SSH, kernel protections, disk encryption, screen lock, sudo, USB and Thunderbolt authorization, updates, open ports. |
| **Detect** | Is something bad already here? Malware hiding places, virus scanning through [ClamUI](https://github.com/linx-systems/clamui), rootkit checks. |
| **Supply chain** | Can I trust what I installed? Known-compromised packages through [Bumblebee](https://github.com/duketopceo/omarchy-bumblebee), known vulnerabilities, AUR packages, your other Omarchy plugins. |
| **Privacy** | What does this machine tell the networks it joins? DNS fallback, hardware address, connectivity pings, announcements, telemetry opt-outs. |
| **Care** | Is the system tidy? Thumbnails, trash, caches, old packages and logs. |

Every finding says, in plain language, what Vigil found and why it matters.
Most come with a fix. Nothing changes until you press **Run** on a
confirmation that says exactly what will happen, and anything that needs
root runs in a terminal you can watch.

Vigil is written for people who are new to Linux security. If you are not,
the [security model](docs/SECURITY-MODEL.md) explains how it is built.

> **Status: 0.3.** The [roadmap](docs/ROADMAP.md) lists what comes next, and
> [docs/LANDSCAPE.md](docs/LANDSCAPE.md) compares Vigil with the other
> security plugins for Omarchy.

## Install

```sh
omarchy plugin add https://github.com/keasbeexd/omarchy-vigil --enable
```

The shield appears on the right of the bar. Nothing else is needed: Vigil
uses Python and commands Omarchy already ships. ClamUI, the scanners and
Bumblebee are optional; Vigil offers to install ClamUI and the scanners when
you ask.

## Using it

| | |
|---|---|
| Left-click the shield | Open or close the panel |
| Middle-click the shield | Check again now |
| `←` `→` or `1`–`6` | Switch tabs |
| `↑` `↓`, `Enter` | Move through findings, open one |
| `F` | Fix the selected finding (asks first) |
| `D` | Mark the selected warning as reviewed, or show it again |
| `R` | Check again |
| `Esc` | Cancel a confirmation, or close |

The shield is dim until the first check finishes, about eight seconds after
login. It turns red when something needs fixing and a softer red when only
improvements are left. The **Overview** tab shows a score out of 100, a bar
for each of the last 30 days, how each pillar is doing, and the findings to
fix first.

### Reviewed warnings

Some warnings are deliberate on your machine: a port you opened on purpose,
a startup line you wrote yourself. Open the finding and choose **Mark as
reviewed**. It stays in its tab, dimmed, and no longer lowers the score or
triggers notifications. If the finding changes (another port opens, another
line appears), it comes back as new. **Show again** undoes it.

Only warnings can be marked as reviewed. Failures can't, and neither can
three checks that are direct evidence or a live risk: system-wide preload,
Bumblebee's known-compromised result, and passwordless sudo.

### Undo

Every change Vigil makes in `/etc` can be undone from the finding it fixed:
open it and choose **Undo Vigil's change**. The undo runs in a terminal like
the fix did, and it deletes the file only if its first line is still Vigil's
marker; a file someone has edited since is left alone. For Avahi, undo puts
back the original file Vigil saved before its first change.

From a keybinding or script:

```sh
omarchy-shell keasbeexd.vigil toggle
omarchy-shell keasbeexd.vigil refresh
```

### Settings

Set these on Vigil's entry in `~/.config/omarchy/shell.json`, or in the bar
settings:

| Key | Default | Meaning |
|---|---|---|
| `refreshMinutes` | `30` | How often to check in the background (5 to 1440). |
| `notifyOnNew` | `true` | One desktop notification when a check that was fine starts failing. It only says how many. |

## What Vigil checks

Each check has a weight. Failures and warnings on weighted checks lower the
score; checks with weight 0 are information and never lower it.

### Harden

| Check | Finding when | Fix |
|---|---|---|
| Firewall | ufw is not installed, switched off, or lets incoming connections in | Turns ufw on (terminal, sudo) |
| Kernel self-protection | Any of nine kernel switches is off (`kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, unprivileged BPF, the `fs.protected_*` set, `suid_dumpable`) | Writes `/etc/sysctl.d/90-omarchy-vigil.conf` (terminal, sudo) |
| Network stack | ICMP redirects, source routing, reverse-path filtering, SYN cookies or broadcast pings are set loosely | Same file as above |
| LLMNR | systemd-resolved answers LLMNR, which attackers on shared Wi-Fi abuse | `/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf` (terminal, sudo) |
| SSH server | sshd runs and allows passwords or root login | `/etc/ssh/sshd_config.d/00-omarchy-vigil.conf`, only if you have an authorized key, validated with `sshd -t` (terminal, sudo) |
| SSH keys | `~/.ssh` or a private key is readable by others, or a key has no passphrase | Makes them private (no root); a passphrase you add yourself with `ssh-keygen -p` |
| GnuPG folder | `~/.gnupg` is readable by others | Makes it private (no root) |
| Automatic screen lock | Stay Awake is on, the lock is off, or it takes over 15 minutes | Turns Stay Awake off; the timeout is `idle.lock` in `shell.json` |
| Disk encryption | The system disk is not on LUKS | Cannot be added after install; information only |
| Secure Boot | Off (information only) | |
| Wrong-password lockout | `pam_faillock` is missing or never locks | |
| Passwordless sudo | Omarchy's passwordless sudo is on | `omarchy-sudo-passwordless --disable` (terminal) |
| Docker group | You are in the docker group, which equals root | `omarchy-remove-security-sudoless-docker` (terminal) |
| USB authorization | New USB devices are trusted automatically (information) | `omarchy-setup-security-usb-authorization` (terminal) |
| Thunderbolt authorization | Thunderbolt accessories are trusted automatically (information) | `omarchy-setup-security-thunderbolt-authorization` (terminal) |
| Security key or fingerprint | sudo takes only a password (information) | `omarchy-setup-security-fido2` (terminal) |
| System updates | No full update in 14 days (warning) or 30 days (failure) | `omarchy-update` (terminal) |
| Open network ports | Programs listen on the network with no firewall in front | |
| Lynis | Installs Lynis and runs `lynis audit system --quick` for a hardening index and suggestions | |

### Detect

| Check | What it does |
|---|---|
| Startup files | Reads shell startup files, autostart entries, user services and timers, uwsm and environment.d files, Hyprland config and your crontab, and flags lines that download and run code, decode hidden code, open reverse shells, or set `LD_PRELOAD`. These are leads to read, not proof. |
| System-wide preload | Fails if `/etc/ld.so.preload` loads anything; rootkits use it to hide. |
| ClamUI | Vigil hands virus scanning to [ClamUI](https://github.com/linx-systems/clamui): file and folder scans, scheduled scans, USB drive scans and quarantine. When it is installed, **Open ClamUI** starts it; otherwise Vigil offers to install it from Flathub. |
| ClamAV virus engine | Whether ClamAV is installed and its signatures are under a week old; updates them with `freshclam`; quick scan of `~/Downloads` in a terminal. |
| Rootkit Hunter | Installs rkhunter, records a baseline, and runs `rkhunter --check`. |

### Supply chain

| Check | What it does |
|---|---|
| Known-compromised packages | Shows the last result of the [Bumblebee](https://github.com/duketopceo/omarchy-bumblebee) plugin, which checks packages, lockfiles, editor extensions and MCP configs against a catalog of known compromises. Vigil only reads Bumblebee's result file; install Bumblebee yourself to use it. |
| Known vulnerabilities | Installs arch-audit and lists installed packages with published vulnerabilities that already have a fix. |
| AUR and other foreign packages | Lists packages that did not come from the official repositories, so you can remove what you no longer recognise. |
| Other Omarchy plugins | Lists your third-party plugins. They run unsandboxed with your account's access, so keep only the ones you use. |

### Privacy

| Check | Finding when | Fix |
|---|---|---|
| DNS fallback servers | systemd-resolved falls back to Google, Cloudflare or Quad9 | `/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf` (terminal, sudo) |
| Connectivity check | NetworkManager pings a server every few minutes (information) | `/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf` (terminal, sudo) |
| Hardware address on Wi-Fi | Networks see your real MAC address | `/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf` (terminal, sudo) |
| Network announcements | Avahi announces this machine's name | Sets `disable-publishing=yes` in `/etc/avahi/avahi-daemon.conf` (terminal, sudo). Refuses unless the setting appears exactly once under `[publish]`, keeps the first original as `avahi-daemon.conf.vigil-backup`, and restores the previous file if Avahi does not restart. |
| Telemetry opt-out variables | `DO_NOT_TRACK` and similar are not set (information) | Writes `~/.config/uwsm/env.d/90-omarchy-vigil-opt-out` (no root) |
| Black Ops | Shows whether [Black Ops](https://github.com/brightwalker25/omarchy-black-ops) is installed; it blocks app telemetry, which Vigil leaves to it | |

### Care

Thumbnail cache and trash (cleared without root), application caches (size
only), package cache (`paccache -rk2`), orphaned packages
(`omarchy-update-orphan-pkgs`, which asks before removing anything) and the
system journal (`journalctl --vacuum-time=2weeks`).

## How actions run

The panel always says which kind an action is:

1. **No fix**: Vigil explains and leaves it to you.
2. **Helper actions** run `bin/vigil fix <action>` as you, never as root:
   making `~/.ssh` and `~/.gnupg` private, the opt-out file, the thumbnail
   cache and the trash. Each is a fixed action name; nothing from a file or
   from the report reaches it.
3. **Terminal actions** open a floating Omarchy terminal running one of the
   constant scripts in [`Model.js`](Model.js). The terminal first prints what
   it will do and waits for Enter; `sudo` then asks for your password.
   Ctrl+C cancels. Wherever Omarchy has its own command for the job (USB and
   Thunderbolt authorization, FIDO2, passwordless sudo, the docker group,
   updates, orphans, package installs), Vigil runs that command rather than
   doing it itself.
4. **Open an app**: **Open ClamUI** starts ClamUI directly, with a fixed
   command and no shell. It changes nothing, so it does not ask first.
5. **Mark as reviewed** and **Show again** only change Vigil's own state
   file, so they do not ask first either.

Vigil never runs anything from its own folder as root, never adds a sudoers
rule, polkit policy, service or timer, and never changes a setting on its
own.

## Privacy

Vigil makes no network connections. The checks read local files and ask
`systemctl`, `pacman`, `journalctl` and `crontab` about local state. Some
actions you start yourself use the network, and their confirmation says so:
installing ClamUI (Arch mirrors, dl.flathub.org, ClamAV's servers), installing
a scanner (Arch mirrors), updating ClamAV's signatures (ClamAV's servers),
`arch-audit` (security.archlinux.org) and `omarchy-update`.

## Files Vigil writes

| Path | Written by | When |
|---|---|---|
| `~/.local/state/omarchy-vigil/state.json` | the helper, mode 0600 | every check: which findings you have already seen, which you marked as reviewed, and one score per day for 30 days |
| `~/.config/uwsm/env.d/90-omarchy-vigil-opt-out` | the helper | only when you set the opt-out variables |
| `/etc/sysctl.d/90-omarchy-vigil.conf` | terminal action | only when you apply the kernel settings |
| `/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf` | terminal action | only when you turn LLMNR off |
| `/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf` | terminal action | only when you remove the DNS fallback |
| `/etc/ssh/sshd_config.d/00-omarchy-vigil.conf` | terminal action | only when you harden SSH |
| `/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf` | terminal action | only when you turn the connectivity check off |
| `/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf` | terminal action | only when you change the hardware address setting |
| `/etc/avahi/avahi-daemon.conf` (first original kept at `avahi-daemon.conf.vigil-backup`) | terminal action | only when you stop Avahi announcements |

Every file in `/etc` that Vigil creates starts with the line
`# Written by Vigil (keasbeexd.vigil)`. Vigil reads, but never writes,
Bumblebee's result file (`~/.local/state/omarchy/bumblebee/last-scan.json`).
ClamUI, the scanners and the Omarchy commands Vigil launches keep their own
files; see their documentation.

## Removing

```sh
omarchy plugin remove keasbeexd.vigil
```

This removes the plugin folder. Vigil runs no services, timers or daemons, so
nothing keeps running. These stay behind until you remove them:

- `~/.local/state/omarchy-vigil/` (seen findings and score history). Remove
  it with `rm ~/.local/state/omarchy-vigil/state.json` and
  `rmdir ~/.local/state/omarchy-vigil`.
- The opt-out file, if you set it. Remove it from the Privacy tab before
  uninstalling, or delete `~/.config/uwsm/env.d/90-omarchy-vigil-opt-out`.
- Settings you applied in `/etc`. They are your system settings now and keep
  protecting you after Vigil is gone. To undo one, delete its file from the
  table above with `sudo rm <file>`, then reboot (or restart the service
  named in the table). For Avahi, restore the original with
  `sudo mv /etc/avahi/avahi-daemon.conf.vigil-backup /etc/avahi/avahi-daemon.conf`.
  Easier: use **Undo** on each finding before you remove Vigil.
- Apps and scanners you installed through Vigil. Remove ClamUI with
  `flatpak uninstall --user io.github.linx_systems.ClamUI`, and `clamav`,
  `rkhunter`, `lynis` or `arch-audit` with `omarchy pkg drop <name>`.

## Requirements

- Omarchy with the Quattro shell.
- `/usr/bin/python3` (Omarchy ships it). Standard library only.

## Development

```sh
python3 -m pytest tests -q          # helper checks, fixes, and marketplace rules
node --test tests/*.test.mjs        # Model.js validation and terminal scripts
omarchy plugin validate .
```

The QML cannot be checked outside Omarchy: it imports `qs.Commons` and
`qs.Ui`, which come from the running shell.

## Credits

Vigil is new code, but it stands on the work of the projects it brings
together, all MIT licensed:
[Black Ops](https://github.com/brightwalker25/omarchy-black-ops) (privacy
protections and its research on Omarchy's defaults),
[Security Scan](https://github.com/Percius04/security-scan) (scheduled
scanners and the startup-file heuristics),
[Bumblebee](https://github.com/duketopceo/omarchy-bumblebee) (supply-chain
catalogs), [ClamUI](https://github.com/linx-systems/clamui) (virus scanning
and quarantine), and [SysCare](https://github.com/cytracon/omarchy-syscare)
(cleaning). The terminal-only approach to root comes from the reasoning in
[omarchy-firewall](https://github.com/illegalstudio/omarchy-firewall).

## License

MIT. See [LICENSE](LICENSE).
