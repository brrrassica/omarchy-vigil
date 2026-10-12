# Vigil

A security suite for [Omarchy](https://omarchy.org): one shield in the bar,
one panel, five pillars.

| Pillar | The question it answers |
|---|---|
| **Harden** | Can someone get in? Firewall, SSH, kernel protections, disk encryption, screen lock, sudo, security keys, updates, open ports. |
| **Detect** | Is something bad already here? Malware hiding places, virus scanning through [ClamUI](https://github.com/linx-systems/clamui), rootkit checks. |
| **Supply** | Can I trust what I installed? Known-compromised packages through Perplexity's [Bumblebee](https://github.com/perplexityai/bumblebee), known vulnerabilities, AUR packages, your other Omarchy plugins. |
| **Privacy** | What does this machine tell the networks it joins? DNS fallback, hardware address, connectivity pings, announcements, telemetry opt-outs. |
| **Care** | Is the system tidy? Thumbnails, trash, caches, old packages and logs. |

Vigil keeps no threat lists of its own. Everything it checks against comes
from the people who maintain it (the Arch security team, OSV.dev and the
OpenSSF, ClamAV, Bumblebee, the AUR itself), and Vigil refreshes it once a
week by itself. It is tuned for no false alarms: only confirmed problems
lower the score, and anything that is merely worth knowing is shown as
information.

Every finding says, in plain language, what Vigil found and why it matters.
Most come with a fix. Nothing changes until you press **Run** on a
confirmation in the panel that says exactly what will happen; anything that
needs root then asks for your password in Omarchy's own password dialog, and
the panel shows the result.

Vigil is written for people who are new to Linux security. If you are not,
the [security model](docs/SECURITY-MODEL.md) explains how it is built.

> **Status: 0.20.2.** The [roadmap](docs/ROADMAP.md) lists what comes next, and
> [docs/LANDSCAPE.md](docs/LANDSCAPE.md) compares Vigil with the other
> security plugins for Omarchy.

## Install

```sh
omarchy plugin add https://github.com/keasbeexd/omarchy-vigil --enable
```

After updating Vigil, restart the shell so the new panel loads (the panel
offers a **Restart shell** button when it notices the update); until then
the old panel keeps running against the new helper.

The shield appears on the right of the bar. Nothing else is needed: Vigil
uses Python and commands Omarchy already ships. ClamUI, ClamAV, the
scanners and Bumblebee are optional. When any are missing, the Overview shows
a red **MISSING … INSTALL** button in place of **Update sources**; it lists
what it will install, asks once more, and then asks for your password.

## Using it

| | |
|---|---|
| Left-click the shield | Open or close the panel |
| Middle-click the shield | Re-read your settings now (quick, no scans) |
| `←` `→` or `1`–`6` | Switch tabs |
| `↑` `↓`, `Enter` | Move through findings, open one |
| `F` | Fix the selected finding (asks first) |
| `D` | Mark the selected finding as reviewed, or show it again |
| `R` or `S` | Full scan (asks first) |
| `U` | Update sources |
| `C` | On the Care tab: Clean all |
| `Esc` | Cancel a confirmation, or close |

The shield is dim until the first check finishes, about eight seconds after
login. It takes your theme's urgent colour when something needs fixing and
its accent colour when only improvements are left; every colour in Vigil
comes from your Omarchy theme. The **Overview** tab shows your score out of
100, the **Full scan** and **Update sources** buttons, and each pillar with
how many findings it has to fix, to improve, and for information. In the
pillar tabs, rows with nothing to do (passing, not applicable, or marked as
reviewed) are dimmed.

### When Vigil runs what

| What | When |
|---|---|
| Every check in every pillar (reading local settings) | every 30 minutes, and whenever you open the panel; offline, under a second |
| **Update sources**: known vulnerabilities, malicious packages, AUR status | once a week, and when you press **Update sources** or **Full scan** |
| ClamAV virus signatures, on demand | when you press **Update sources** (asks for your password) |
| **Full scan**, background part: a Bumblebee scan, then a virus scan of your home folder | once a week, and when you press **Full scan** |
| Password check (accounts without a password) | only when you press **Full scan**, since it needs your password |
| ClamAV virus signatures | continuously, by ClamAV's own update service |
| Cleaning (Care) | only when you ask; Vigil only measures sizes by itself |

The Overview has two buttons:

- **Full scan** (`R` or `S`) runs every check and scan Vigil has, in this
  order: the password check (Omarchy's own password dialog asks for your
  password), the lists of known holes, malicious packages and AUR status, a virus scan of your whole home
  folder (skipping caches, game libraries, `node_modules` and `.git`
  folders, at low priority) last, then
  every setting again. Bumblebee (if installed) runs before the virus scan,
  and each line of the Last run list updates as its step finishes, so you
  do not wait for the virus scan to see the rest. The panel shows a progress bar with the current step
  (and, during the virus scan, how many files are done), and a notification
  says when it is finished. Every tab then shows the results, and you fix
  what you choose from there.
- **Update sources** (or `U`) downloads the latest of everything Vigil checks
  against: ClamAV's virus signatures first (Omarchy asks for your password,
  since they live in a system folder), then the lists of known security
  holes, malicious packages and AUR status. No scan runs. The automatic
  weekly update never asks for a password: it skips the signatures, which
  ClamAV's own service keeps current several times a day.

While a Full scan or update runs, **Stop** under the progress bar ends it:
the step it is on stops, what already finished is kept, and the rest is
tried again the next day (or when you press the button again). Stop also
ends a run left going after the shell restarted.

Only one scan or update runs at a time. Pressing a button while one runs
(on another monitor, or one still going after the shell restarted) starts
nothing new: the panel shows "Already running" with that run's progress
instead. Fixes, Clean all and installs show their own progress bar while
they run, so you can close the panel and come back to it.

Under the buttons, two lines count down to the next automatic update and the
next automatic full scan (everything but the password check), with the time
in your computer's timezone when it is today or tomorrow: each runs a week
after the last one, to the minute, or at Vigil's next background check if it
is already due. Each button resets its own countdown. Results of the buttons
stay on a card in the panel until you close it. Turning off `autoUpdate` leaves both to the
buttons.

Below the pillars, **Last run** lists when each scan last ran (the settings
checks, the virus scan, Bumblebee, the password check) and when each source
last updated (virus signatures, known vulnerabilities, malicious packages,
AUR status), with the time. Anything that failed or is out of date is red.
Work done outside Vigil counts too: the virus signatures line includes
ClamAV's own update service and updates made in ClamUI, the virus scan line
includes scans you ran in ClamUI (marked "by ClamUI"). The vulnerability, malicious-package and
AUR lines can only show Vigil's own updates, since those tools keep no record
when run by hand.

### Every finding

Open any finding and it says, in this order: **Why it matters** (a sentence
or two), **How to fix**, and **Details**. Below that are its buttons:

- **Fix** (named for what it does) when Vigil can do it, or **Learn more** /
  **Show …** when it can't: a guide in your browser (the Arch Wiki, a
  plugin's page) or a read-only command whose output the panel shows.
- **Undo Vigil's change** once Vigil has changed something for it.
- **Mark as reviewed** on anything that is not passing, when you don't want
  that fix: a port you opened on purpose, an unencrypted desktop that never
  leaves home. It stays in its tab, dimmed, no longer lowers the score or
  notifies, and stays reviewed through every later check and scan. **Show
  again** undoes it.

For findings that report evidence rather than a setting (open ports, startup
files, file changes, exposed secrets, infected files, known-malicious or
known-compromised packages, vulnerable packages, system-wide preload,
abandoned AUR packages, plugin capabilities), a review covers what was found
at the time. If something new turns up, the finding comes back.

### Undo

Every change Vigil makes in `/etc` can be undone from the finding it fixed
(cleanups and added passphrases are the exceptions; there is nothing to put
back):
open it and choose **Undo Vigil's change**. The undo asks for your password
like the fix did, and it deletes the file only if its first line is still Vigil's
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
| `autoUpdate` | `true` | The weekly work: update the sources (see [Where the data comes from](#where-the-data-comes-from)), and the background part of a Full scan (a Bumblebee scan and a virus scan of your home folder). Off means only when you press **Update sources** or **Full scan**. |

## What Vigil checks

Each check has a weight from 0 to 3. A failure costs 10 points per weight
point and a warning 2, so a confirmed problem moves the score a lot and an
improvement only a little; checks with weight 0 are information and never
lower it. A warning you mark as reviewed stops counting.

### Harden

| Check | Finding when | Fix |
|---|---|---|
| Firewall | ufw is not installed, switched off, or lets incoming connections in | Turns ufw on (asks for your password) |
| Kernel self-protection | Any of nine kernel switches is off (`kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, unprivileged BPF, the `fs.protected_*` set, `suid_dumpable`) | Writes `/etc/sysctl.d/90-omarchy-vigil.conf` (asks for your password) |
| Network stack | ICMP redirects, source routing, reverse-path filtering, SYN cookies or broadcast pings are set loosely | Same file as above |
| LLMNR | systemd-resolved answers LLMNR, which attackers on shared Wi-Fi abuse | `/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf` (asks for your password) |
| SSH server | sshd runs and allows passwords or root login | `/etc/ssh/sshd_config.d/00-omarchy-vigil.conf`, only if you have an authorized key, validated with `sshd -t` (asks for your password) |
| SSH keys | `~/.ssh` or a private key is readable by others, or a key has no passphrase | Makes them private (no root); **Add a passphrase** runs `ssh-keygen -p` for each key without one (in a terminal, since you type the passphrase; no root) |
| GnuPG folder | `~/.gnupg` is readable by others | Makes it private (no root) |
| Automatic screen lock | Stay Awake is on, the lock is off, or it takes over 15 minutes | Turns Stay Awake off; sets `idle.lock` to 300 seconds, Omarchy's default, with Omarchy's own `omarchy-shell-config` helper (no root) |
| Disk encryption | The system disk is not on LUKS | Cannot be added after install; Arch Wiki guide |
| Restart after updates | A newer kernel is installed than the one running | **Restart now** (after a confirmation) |
| Secure Boot | Shown for information only; Vigil does not suggest setting it up, since a mistake can stop the computer starting | |
| Wrong-password lockout | `pam_faillock` is missing or never locks | Arch Wiki guide |
| FireWire | The machine has a FireWire port and its driver can load (information; shown only on machines with the port) | `/etc/modprobe.d/90-omarchy-vigil-firewire.conf` (asks for your password) |
| Passwordless sudo | Omarchy's passwordless sudo is on | `omarchy-sudo-passwordless --disable` (terminal) |
| Docker group | You are in the docker group, which equals root | `omarchy-remove-security-sudoless-docker` (terminal) |
| Security key or fingerprint | sudo takes only a password (information). On a computer with a fingerprint reader (found by Omarchy's own `omarchy-hw-fingerprint`, which only reads `/sys`), it offers fingerprint instead | `omarchy-setup-security-fingerprint` or `omarchy-setup-security-fido2` (terminal); once set up, **Stop using…** runs Omarchy's `omarchy-remove-security-fingerprint` or `-fido2` |
| System updates | A newer Omarchy is out (warning; found by `checkupdates`, the same check Omarchy's own update indicator uses, in each Update sources and Full scan), or no full update in 14 days (warning) or 30 days (failure). Also says how many updates are waiting | `omarchy-update` (terminal) |
| Firmware updates | The Full scan asks fwupd, which gets firmware from LVFS where hardware makers publish it. A waiting update that fixes a known security hole (a CVE, or marked high or critical) is a warning; other firmware updates are information | `omarchy-update-firmware` (terminal) |
| Open network ports | Programs listen on the network with no firewall in front | **Show listeners** runs `ss -tulpn` as root and shows the result in the panel (read-only) |
| Exposed secrets | API keys and tokens in the formats their providers publish (AWS, GitHub, GitLab, Slack, Stripe, Anthropic, OpenAI, Google, private keys) in your shell histories, or credential files such as `~/.aws/credentials`, `~/.netrc` and `~/.git-credentials` readable by other accounts. Shows the file and line, never the secret. | Makes credential files private (no root); revoke leaked keys with their provider |

### Detect

| Check | What it does |
|---|---|
| Startup files | Reads shell startup files, autostart entries, user services and timers, uwsm and environment.d files, Hyprland config and your crontab, and flags lines that download and run code, decode hidden code, or open reverse shells. These are leads to read, not proof. |
| System-wide preload | Fails if `/etc/ld.so.preload` loads anything; rootkits use it to hide. |
| Changes to important files | Records a fingerprint of accounts, PAM, SSH settings, `~/.ssh/authorized_keys`, system and user services, autostart entries and your startup files, and lists anything changed, added or removed since. Changes that match exactly what a package update shipped (from pacman's own records) are not reported, nor are system users that packages add. Changes to who can log in or what runs at start are warnings; changes to your own shell files are information. **Accept these changes** records the current state as the new normal. |
| Virus scan | ClamAV scans your home folder once a week and in every Full scan, as you, with signatures ClamAV keeps current. Infected files are listed with **Open ClamUI** to quarantine them. If ClamAV is wrong about a file you know is safe (a game's DLL, say), press **False positive** next to it: Vigil records that exact file's SHA-256 and stops counting it, and reports it again if the file ever changes. **Not a false positive** counts it again. Only ClamAV's published signatures count; its guess-based "potentially unwanted" rules stay off. |
| Scans scheduled twice | Finds other apps that repeat what Vigil already runs every week: a scheduled scan in ClamUI whose folders are all inside your home folder, and the older Bumblebee plugin (once Vigil runs Bumblebee itself). **Let Vigil run them** turns those off the way you would in each app: ClamUI's timer and its own Scheduled scans setting, and `omarchy plugin disable` for the plugin. Undo turns back on exactly what it turned off. A ClamUI schedule that also covers folders outside your home folder, and the Security Scan plugin (it runs AUR-Malware, which Vigil does not), are listed but left on. Nothing is offered when Vigil's own weekly run is off. |
| ClamUI | Vigil hands virus scanning to [ClamUI](https://github.com/linx-systems/clamui): file and folder scans, scheduled scans, USB drive scans and quarantine. When it is installed, **Open ClamUI** starts it; otherwise Vigil offers to install it from Flathub. |
| ClamAV virus engine | Whether ClamAV is installed and its signatures keep themselves up to date. Vigil turns on ClamAV's own update service (`clamav-freshclam`) when it installs ClamAV or ClamUI, and offers to if it is off. |

### Supply

| Check | What it does |
|---|---|
| Known-compromised packages | Runs Perplexity's [Bumblebee](https://github.com/perplexityai/bumblebee) in each Full scan. It checks your packages, lockfiles, editor and browser extensions and MCP configs against the compromised releases Perplexity tracks, and reads files only. **Install** downloads Perplexity's pinned release, installs it only if it matches the SHA-256 in the release's own `checksums.txt`, and puts it in `/usr/local/bin/bumblebee` (owned by root). |
| Known-malicious npm and Bun packages | Runs [osv-scanner](https://github.com/google/osv-scanner) over your AUR build folders (`~/.cache/yay`, `~/.cache/paru`) and global npm, Bun, mise and pnpm installs, against [OSV.dev](https://osv.dev), which includes the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) reports. This is how the 2026 Atomic Arch AUR attack (which pulled malware in with `bun install`) and the npm worms that run on Bun are caught. Only confirmed malware (`MAL-` entries) counts; ordinary vulnerabilities in development dependencies are left out. |
| Known vulnerabilities | Installs arch-audit, which uses the Arch security team's tracker, and lists only the problems an update fixes. |
| AUR package status | Asks the AUR about your AUR packages: which have left the AUR, which are now in the official repositories, and which have no maintainer (most 2026 AUR attacks took over such orphans). Information only, since packages leave the AUR for ordinary reasons too. |
| AUR and other foreign packages | Lists packages that did not come from the official repositories, so you can remove what you no longer recognise. |
| Other Omarchy plugins | Lists your third-party plugins and what each one's code can do: network access, root through sudo or pkexec, shell commands, downloading and running code, compiled binaries. Vigil reads the files as text and never loads or runs them. |

### Privacy

| Check | Finding when | Fix |
|---|---|---|
| DNS fallback servers | systemd-resolved falls back to Google, Cloudflare or Quad9 | `/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf` (asks for your password) |
| Connectivity check | NetworkManager pings a server every few minutes (information) | `/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf` (asks for your password) |
| Hardware address on Wi-Fi | Networks see your real MAC address | `/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf` (asks for your password) |
| Network announcements | Avahi announces this machine's name | Sets `disable-publishing=yes` in `/etc/avahi/avahi-daemon.conf` (asks for your password). Refuses unless the setting appears exactly once under `[publish]`, keeps the first original as `avahi-daemon.conf.vigil-backup`, and restores the previous file if Avahi does not restart. |
| Telemetry opt-out variables | `DO_NOT_TRACK` and similar are not set (information) | Writes `~/.config/uwsm/env.d/90-omarchy-vigil-opt-out` (no root) |
| Black Ops | Shows whether [Black Ops](https://github.com/brightwalker25/omarchy-black-ops) is installed; it blocks app telemetry, which Vigil leaves to it | |

### Care

Thumbnail cache and trash (cleared without root, the trash directly in its
standard folders), application caches (files in `~/.cache` that no app has
read or written for a week; caches in use are left alone), package cache
(`paccache -rk2`, keeping Omarchy's two versions per package for rollback,
and `paccache -ruk0` for packages you have removed; the row shows what a dry
run says can be freed), orphaned packages (`omarchy-update-orphan-pkgs`,
which asks before removing anything) and the system journal
(`journalctl --vacuum-time=2weeks`).

**Clean all** (or `C` on the Care tab) does every cleanup on offer in one go,
after one confirmation that lists each item and its size: thumbnails, the
trash and unused caches right away, then the package cache and the journal,
for which Omarchy asks for your password once. Orphaned packages are left out on purpose: removing packages
can take away something you use, so that stays a separate, reviewed step.

### Accounts, history and old services

Checks a newcomer benefits from that need no extra tools:

| Check | Finding when | Fix |
|---|---|---|
| User accounts | Another account has root's powers, accounts share one ID (both from `/etc/passwd`), or an account has no password (from the last Full scan, which reads `/etc/shadow` with sudo and keeps only the account names) | How to fix and the Arch Wiki guide; Vigil does not change accounts itself, since a mistake can lock you out |
| Shell history | A history file (`~/.bash_history`, `~/.zsh_history`, `~/.histfile`, fish) is a link or not a normal file, a way attackers hide what they typed | Guide (MITRE ATT&CK); mark as reviewed if you did it yourself |
| Old network services | A telnet, rsh, rlogin, FTP, TFTP, NIS or xinetd service is switched on | **Switch them off**: `systemctl disable --now` on each one that is on (asks for your password) |

Earlier versions ran Lynis for these. Vigil now does them itself: Lynis
looks for Debian package names that never match on Arch, and most of its
hundreds of other tests are written for servers.

## How actions run

The panel always says which kind an action is:

1. **No fix**: Vigil explains and leaves it to you.
2. **Helper actions** run `bin/vigil fix <action>` as you, never as root:
   making `~/.ssh` and `~/.gnupg` private, the opt-out file, the thumbnail
   cache and the trash. Each is a fixed action name; nothing from a file or
   from the report reaches it.
3. **Script actions** run one of the constant scripts in
   [`Model.js`](Model.js) without a terminal. The panel first shows what it
   will do, in plain words and then the exact commands, and waits for
   **Run**. Scripts that need root run through `pkexec`, so Omarchy's own
   password dialog asks; cancelling it changes nothing. The panel then shows
   what the script printed. Only tools that ask you questions as they go
   still open a terminal: Omarchy's updater, its FIDO2 key
   and fingerprint setup, passwordless sudo, the docker group, the orphan review, and
   choosing an SSH passphrase. Packages Vigil installs come straight from
   the Arch repositories with `pacman --needed --noconfirm`.
4. **Open an app or a guide**: **Open ClamUI** starts ClamUI directly, and
   **Learn more** opens a page with `xdg-open`, each with a fixed command and
   no shell. Pages come only from a fixed list in `Model.js` (Arch Wiki,
   MITRE ATT&CK, Perplexity's Bumblebee, Black Ops); nothing in the report becomes a URL.
   They change nothing, so they do not ask first.
5. **Mark as reviewed** and **Show again** only change Vigil's own state
   file, so they do not ask first either.

Vigil never runs anything from its own folder as root, never adds a sudoers
rule, polkit policy, service or timer, and never changes a setting on its
own.

## What it costs your computer

Vigil runs no service, timer or daemon of its own. While you are logged in:

- **A check every 30 minutes** (the `refreshMinutes` setting), from one
  monitor's copy only, at lowered priority. It reads files only, and every
  folder walk has a time and size limit (a few seconds), so even a huge home
  folder cannot make it slow. Other monitors check only when you open their
  panel.
- **The weekly run** (sources once a week, the background part of a Full
  scan once a week) at low priority; the virus scan itself runs at the
  lowest (`nice -n 19`). It starts at most once every six hours, whatever
  happens to it, so a run that keeps failing can never restart in a loop.
- **One run at a time**, across monitors and shell restarts.
- **Every step has a deadline**: the virus scan 3 hours, the other steps
  between 15 seconds and 10 minutes, and the panel stops anything that runs
  past its own backstop. A step that fails is retried the next day; a virus
  scan that runs out of time waits a week instead of repeating hours of
  work every day.
- **Nothing polls** except while a scan started elsewhere is running, when
  the panel asks every 4 seconds for its progress (a file read).

## Where the data comes from

Vigil keeps no threat lists of its own.

| What | Maintained by | How it stays current |
|---|---|---|
| Virus signatures | ClamAV (Cisco Talos) | ClamAV's own `clamav-freshclam` service, several times a day |
| Known vulnerabilities in Arch packages | Arch Linux security team | arch-audit, once a week (and **Update sources**) |
| Known-malicious npm, Bun and other packages | OSV.dev and the OpenSSF Malicious Packages project | osv-scanner, once a week (and **Update sources**) |
| AUR package status | the AUR | AUR lookup, once a week (and **Update sources**) |
| Known-compromised packages, extensions and MCP configs | Perplexity (Bumblebee's `threat_intel` catalogs) | downloaded from Perplexity's repository once a week (and **Update sources**); Bumblebee scans in each Full scan |

There is no maintained feed of malicious AUR packages; Arch's own list for
the 2026 attacks was a one-off document. Vigil covers the AUR through what
the malware pulls in (OSV), through ClamAV signatures, and through the AUR's
own package status.

## Privacy

Vigil's checks read local files and ask `systemctl`, `pacman`, `journalctl`
and `crontab` about local state. With `autoUpdate` on (the default), once a
week Vigil also:

- runs `arch-audit`, which downloads the Arch security tracker from
  security.archlinux.org;
- runs `osv-scanner`, which sends the names and versions of the packages in
  your AUR build folders and global npm and Bun installs to OSV.dev (run by
  Google), never file contents;
- asks aur.archlinux.org about your installed AUR packages by name, as yay
  and paru do on every update.

Each happens only once the tool is installed, and turning `autoUpdate` off
limits it to when you press **Update sources** or **Full scan**. Actions you start yourself also use
the network and say so first: installing ClamUI (Arch mirrors, dl.flathub.org,
ClamAV's servers), installing a tool (Arch mirrors), ClamAV's signature
service (ClamAV's servers), and `omarchy-update`.

## Files Vigil writes

| Path | Written by | When |
|---|---|---|
| `~/.local/state/omarchy-vigil/state.json` | the helper, mode 0600 | every check: which findings you have already seen, which you marked as reviewed, and one score per day for 30 days |
| `~/.local/state/omarchy-vigil/baseline.json` | the helper, mode 0600 | first check, and when you accept file changes: fingerprints (not contents) of the watched files |
| `~/.local/state/omarchy-vigil/arch-audit.json` | the helper, mode 0600 | weekly and on Update sources: package names and severities an update fixes |
| `~/.local/state/omarchy-vigil/osv.json` | the helper, mode 0600 | weekly and on Update sources: known-malicious packages found, if any, and which folders were checked |
| `~/.local/state/omarchy-vigil/aur.json` | the helper, mode 0600 | weekly and on Update sources: names of AUR packages that left the AUR or have no maintainer |
| `~/.local/state/omarchy-vigil/virus-scan.json` | the helper, mode 0600 | weekly, in each Full scan and on Scan now: names of infected files found in your home folder, if any, and how many files were scanned |
| `~/.local/state/omarchy-vigil/no-password.txt` | the helper, mode 0600 | each Full scan: names of accounts with an empty password, usually none |
| `~/.local/state/omarchy-vigil/full-scan.json` | the helper, mode 0600 | after each Full scan, automatic or not: its date and time, for the countdown |
| `~/.local/state/omarchy-vigil/bumblebee-catalog.json` | the helper, mode 0600 | weekly and on Update sources: Perplexity's list of compromised packages, for Bumblebee |
| `~/.local/state/omarchy-vigil/bumblebee.json` | the helper, mode 0600 | each Full scan: the compromised packages Bumblebee found, if any |
| `~/.local/state/omarchy-vigil/progress.json` | the helper, mode 0600 | during a scan or update: its current step, so a panel that did not start it can show it |
| `~/.local/state/omarchy-vigil/run.json` | the helper, mode 0600 | during a scan or update: the process IDs and start times of the run and the program it is running, so **Stop** can end it |
| `~/.local/state/omarchy-vigil/handed-over/` | the Let Vigil run them action, mode 0700 | one empty marker per schedule it turned off, so Undo turns back on exactly those |
| `~/.config/clamui/settings.json` (or ClamUI's Flatpak copy) | the Let Vigil run them action, and its Undo | only `scheduled_scans_enabled`, with everything else in the file kept |
| `~/.local/state/omarchy-vigil/pending-updates.json` | the helper, mode 0600 | each Update sources and Full scan: how many updates are waiting, and the Omarchy version if one is |
| `~/.local/state/omarchy-vigil/firmware.json` | the helper, mode 0600 | each Full scan: device names and firmware versions with an update waiting |
| `~/.local/state/omarchy-vigil/ignored-detections.json` | the helper, mode 0600 | when you mark a virus detection as a false positive: the file's path, the signature name and the file's SHA-256 |
| `~/.local/state/omarchy-vigil/busy/` | the helper, mode 0700, empty | once: the folder Vigil locks so only one scan or update runs at a time |
| `~/.local/state/omarchy-vigil/last-run.json` | the helper, mode 0600 | after each weekly or button update: its date, time and whether every source updated |
| `/usr/local/bin/bumblebee` | the Install button, as root | only when you install Bumblebee: Perplexity's program, checked against its published checksum |
| `~/.config/uwsm/env.d/90-omarchy-vigil-opt-out` | the helper | only when you set the opt-out variables |
| `/etc/sysctl.d/90-omarchy-vigil.conf` | a script action, as root | only when you apply the kernel settings |
| `/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf` | a script action, as root | only when you turn LLMNR off |
| `/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf` | a script action, as root | only when you remove the DNS fallback |
| `/etc/ssh/sshd_config.d/00-omarchy-vigil.conf` | a script action, as root | only when you harden SSH |
| `/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf` | a script action, as root | only when you turn the connectivity check off |
| `/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf` | a script action, as root | only when you change the hardware address setting |
| `/etc/avahi/avahi-daemon.conf` (first original kept at `avahi-daemon.conf.vigil-backup`) | a script action, as root | only when you stop Avahi announcements |

Every file in `/etc` that Vigil creates starts with the line
`# Written by Vigil (keasbeexd.vigil)`. ClamUI, the scanners and the Omarchy commands Vigil launches keep their own
files; see their documentation.

## Removing

```sh
omarchy plugin remove keasbeexd.vigil
```

This removes the plugin folder. Vigil runs no services, timers or daemons, so
nothing keeps running. These stay behind until you remove them:

- `~/.local/state/omarchy-vigil/` (seen findings, score history, the file
  baseline and the cached results of the weekly checks). Remove it with
  `rm -rf ~/.local/state/omarchy-vigil`. If you used **Let Vigil run them**
  and want ClamUI's schedule back, press its Undo first.
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
  `arch-audit` or `osv-scanner` with `omarchy pkg drop <name>` (and `lynis`
  or `rkhunter`, if an earlier Vigil installed them). Remove Bumblebee with
  `sudo rm /usr/local/bin/bumblebee`.
  ClamAV's update service stops with `sudo systemctl disable --now clamav-freshclam.service`.

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
[omarchy-bumblebee](https://github.com/duketopceo/omarchy-bumblebee) (the
idea of bringing Perplexity's Bumblebee to Omarchy), [ClamUI](https://github.com/linx-systems/clamui) (virus scanning
and quarantine), and [SysCare](https://github.com/cytracon/omarchy-syscare)
(cleaning). The terminal-only approach to root comes from the reasoning in
[omarchy-firewall](https://github.com/illegalstudio/omarchy-firewall).

Known-compromised packages are found by Perplexity's
[Bumblebee](https://github.com/perplexityai/bumblebee) (Apache 2.0) and its
`threat_intel` catalogs. Vigil does not ship either: **Install** downloads
the program from Perplexity's releases, and the catalogs come from
Perplexity's repository.

## License

MIT. See [LICENSE](LICENSE).
