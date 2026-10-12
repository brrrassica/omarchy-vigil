// Pure logic for the Vigil panel: validating the helper's report, the closed
// tables of actions, and display helpers. No QML types are used here, so the
// file is loaded unchanged by the tests in tests/model.test.mjs.
//
// Everything that comes back from bin/vigil is treated as untrusted input:
// it is size-checked by the caller, parsed here, and every field is checked
// for type, range and length before the panel shows it. A report that does
// not match the shape is rejected whole rather than trimmed into shape.

var MAX_REPORT_CHARS = 512 * 1024
var MAX_CHECKS = 80
var MAX_STR = 400
var MAX_DETAIL = 4000

var CATEGORIES = ["harden", "detect", "supply", "privacy", "care"]
var STATUSES = ["fail", "warn", "unknown", "info", "pass", "na"]
var FIX_KINDS = ["terminal", "helper", "app", "none"]
var TRUSTED_TOOL_DIRS = ["/usr/bin", "/usr/share/omarchy/bin"]
var LAUNCHER = "omarchy-launch-floating-terminal-with-presentation"

// ---------------------------------------------------------------------------
// Text

// For strings that reach host-owned components (WidgetButton tooltip,
// PanelHero, PanelSectionHeader, notifications) whose Text format the plugin
// cannot pin: drop markup characters, control and bidi characters, and cap.
function plain(value, max) {
  var s = String(value === undefined || value === null ? "" : value)
  s = s.replace(/[<>&]/g, "")
  s = s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, " ")
  var limit = max || MAX_STR
  if (s.length > limit) s = s.substring(0, limit - 1) + "…"
  return s
}

function isString(v, max) {
  return typeof v === "string" && v.length <= max
}

function inList(v, list) {
  return list.indexOf(v) !== -1
}

// ---------------------------------------------------------------------------
// Actions
//
// Helper actions run `bin/vigil fix <id>` as the logged-in user; they never
// need root. Terminal actions open a visible Omarchy terminal running one of
// the constant scripts below, so every privileged step is shown, asks for the
// password through sudo, and can be cancelled with Ctrl+C before it starts.
// No value from the report, a file or the network is ever put into a script:
// the report only names an action id, and an unknown id does nothing.

var HELPER_ACTIONS = ["ssh-perms", "gnupg-perms", "optout-on", "optout-off", "clean-thumbnails", "empty-trash",
                      "credential-perms", "integrity-accept", "arch-audit-refresh", "osv-refresh", "aur-refresh",
                      "virus-scan-now"]

// What the confirmation card says before a helper action runs.
var HELPER_INFO = {
  "ssh-perms": { title: "Make ~/.ssh private",
                 what: ["Sets ~/.ssh to 700 and your private keys to 600, so only you can read them."] },
  "gnupg-perms": { title: "Make ~/.gnupg private", what: ["Sets ~/.gnupg to 700."] },
  "optout-on": { title: "Set telemetry opt-out variables",
                 what: ["Writes ~/.config/uwsm/env.d/90-omarchy-vigil-opt-out with DO_NOT_TRACK=1 and similar.",
                        "Applies from your next login. Remove it here at any time."] },
  "optout-off": { title: "Remove the opt-out variables",
                  what: ["Deletes ~/.config/uwsm/env.d/90-omarchy-vigil-opt-out if Vigil wrote it and it is unchanged."] },
  "clean-thumbnails": { title: "Clear the thumbnail cache",
                        what: ["Deletes everything in ~/.cache/thumbnails. Previews are recreated when needed."] },
  "empty-trash": { title: "Empty the trash",
                   what: ["Permanently deletes the files in the trash. This cannot be undone."] },
  "credential-perms": { title: "Make credential files private",
                        what: ["Sets files such as ~/.aws/credentials, ~/.netrc and ~/.git-credentials to 600,",
                               "so only you can read them. Their contents are not read or changed."] },
  "integrity-accept": { title: "Accept the file changes",
                        what: ["Records the watched files as they are now as the new normal.",
                               "Only do this once you recognise every change in the list."] },
  "arch-audit-refresh": { title: "Check for known vulnerabilities now",
                          what: ["Runs arch-audit, which downloads the Arch security tracker from security.archlinux.org.",
                                 "Vigil also does this once a week by itself."] },
  "osv-refresh": { title: "Check for known-malicious packages now",
                   what: ["Runs osv-scanner on your AUR build folders and global npm and Bun installs.",
                          "It sends package names and versions (never your files) to OSV.dev, run by Google.",
                          "Vigil also does this once a week by itself."] },
  "virus-scan-now": { title: "Scan Downloads for viruses now",
                      what: ["Runs ClamAV on ~/Downloads as you, in the background. Nothing is deleted.",
                             "Large folders can take a few minutes. Vigil also does this once a week."] },
  "aur-refresh": { title: "Check your AUR packages now",
                   what: ["Asks aur.archlinux.org about the AUR packages you have installed, the same lookup",
                          "yay and paru make on every update. Vigil also does this once a week by itself."] }
}

function isHelperAction(id) {
  return typeof id === "string" && inList(id, HELPER_ACTIONS)
}

function helperInfo(id) {
  if (typeof id !== "string" || !Object.prototype.hasOwnProperty.call(HELPER_INFO, id)) return null
  return HELPER_INFO[id]
}

// Title and lines for the confirmation card of any runnable action.
function confirmation(kind, id) {
  var a = kind === "helper" ? helperInfo(id) : (kind === "terminal" ? terminalAction(id) : null)
  if (!a) return null
  var lines = a.what.slice(0)
  if (kind === "terminal") lines.push("Opens a terminal. sudo asks for your password there.")
  return { title: a.title, lines: lines }
}

var VIGIL_MARK = "# Written by Vigil (keasbeexd.vigil). Delete this file to undo."

var SYSCTL_LINES = [
  VIGIL_MARK,
  "kernel.kptr_restrict=2",
  "kernel.dmesg_restrict=1",
  "kernel.yama.ptrace_scope=1",
  "kernel.unprivileged_bpf_disabled=1",
  "fs.protected_symlinks=1",
  "fs.protected_hardlinks=1",
  "fs.protected_fifos=2",
  "fs.protected_regular=2",
  "fs.suid_dumpable=0",
  "net.ipv4.conf.all.accept_redirects=0",
  "net.ipv4.conf.default.accept_redirects=0",
  "net.ipv6.conf.all.accept_redirects=0",
  "net.ipv6.conf.default.accept_redirects=0",
  "net.ipv4.conf.all.send_redirects=0",
  "net.ipv4.conf.default.send_redirects=0",
  "net.ipv4.conf.all.accept_source_route=0",
  "net.ipv4.tcp_syncookies=1",
  "net.ipv4.conf.all.rp_filter=2",
  "net.ipv4.icmp_echo_ignore_broadcasts=1"
]

// printf '%s\n' 'line' 'line' ... | sudo tee <file> >/dev/null
function dropIn(path, lines) {
  var quoted = []
  for (var i = 0; i < lines.length; i++) quoted.push("'" + lines[i] + "'")
  return "printf '%s\\n' " + quoted.join(" ") + " | sudo /usr/bin/tee " + path + " >/dev/null"
}

// Undo for a drop-in Vigil wrote: removes it only while its first line is
// still exactly VIGIL_MARK, so a file someone has since edited is left alone.
function undoDropIn(name, path, afterText, after) {
  return {
    title: "Undo the Vigil change to " + name,
    what: ["Deletes " + path + " if its first line is still the Vigil marker.",
           "A file edited since Vigil wrote it is left alone.", afterText],
    run: "f=" + path + "; "
         + "[ -e \"$f\" ] || { echo 'Nothing to undo.'; exit 0; }; "
         + "[ \"$(/usr/bin/head -n 1 -- \"$f\")\" = '" + VIGIL_MARK + "' ] "
         + "|| { echo 'The file was changed since Vigil wrote it, so it was left alone.'; exit 1; }; "
         + "sudo /usr/bin/rm -f -- \"$f\" && " + after
  }
}

// Each entry: title, what (lines shown before anything runs), and either a
// constant `run` script or an Omarchy `tool` (resolved to a root-owned path
// in /usr/bin or /usr/share/omarchy/bin by the helper) with constant `args`.
var TERMINAL_ACTIONS = {
  "firewall-on": {
    title: "Turn the firewall on",
    what: ["Runs: sudo ufw enable", "Starts ufw now and at every boot with the rules Omarchy set up."],
    run: "sudo /usr/bin/ufw enable && sudo /usr/bin/systemctl enable --now ufw.service"
  },
  "firewall-deny-in": {
    title: "Deny incoming connections by default",
    what: ["Runs: sudo ufw default deny incoming", "Rules you added for specific ports stay in place."],
    run: "sudo /usr/bin/ufw default deny incoming && sudo /usr/bin/ufw reload"
  },
  "install-ufw": {
    title: "Install and turn on the ufw firewall",
    what: ["Installs ufw with omarchy pkg add, denies incoming connections and starts it."],
    tool: "omarchy-pkg-add", args: " ufw && sudo /usr/bin/ufw default deny incoming && sudo /usr/bin/ufw enable && sudo /usr/bin/systemctl enable --now ufw.service"
  },
  "sysctl-harden": {
    title: "Apply recommended kernel and network settings",
    what: ["Writes /etc/sysctl.d/90-omarchy-vigil.conf and loads it.",
           "Undo: sudo rm /etc/sysctl.d/90-omarchy-vigil.conf, then reboot."],
    run: dropIn("/etc/sysctl.d/90-omarchy-vigil.conf", SYSCTL_LINES) + " && sudo /usr/bin/sysctl --system >/dev/null && echo 'Settings applied.'"
  },
  "llmnr-off": {
    title: "Turn LLMNR off",
    what: ["Writes /etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf and restarts systemd-resolved.",
           "Undo: delete that file and restart systemd-resolved."],
    run: "sudo /usr/bin/install -d -m 0755 /etc/systemd/resolved.conf.d && "
         + dropIn("/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf", [VIGIL_MARK, "[Resolve]", "LLMNR=no"])
         + " && sudo /usr/bin/systemctl restart systemd-resolved.service"
  },
  "dns-fallback-off": {
    title: "Remove the public DNS fallback",
    what: ["Writes /etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf with an empty FallbackDNS=.",
           "If your DNS servers fail, lookups fail instead of going to Google, Cloudflare or Quad9."],
    run: "sudo /usr/bin/install -d -m 0755 /etc/systemd/resolved.conf.d && "
         + dropIn("/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf", [VIGIL_MARK, "[Resolve]", "FallbackDNS="])
         + " && sudo /usr/bin/systemctl restart systemd-resolved.service"
  },
  "sshd-harden": {
    title: "SSH: keys only, no root login",
    what: ["Writes /etc/ssh/sshd_config.d/00-omarchy-vigil.conf, checks it with sshd -t and reloads sshd.",
           "Stops if ~/.ssh/authorized_keys is empty, so you cannot lock yourself out."],
    run: "test -s \"$HOME/.ssh/authorized_keys\" || { echo 'No keys in ~/.ssh/authorized_keys. Add one first.'; exit 1; }; "
         + dropIn("/etc/ssh/sshd_config.d/00-omarchy-vigil.conf",
                  [VIGIL_MARK, "PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no"])
         + " && if sudo /usr/bin/sshd -t; then sudo /usr/bin/systemctl reload sshd.service; "
         + "else sudo /usr/bin/rm -f /etc/ssh/sshd_config.d/00-omarchy-vigil.conf; echo 'sshd rejected the change, so it was removed.'; exit 1; fi"
  },
  "connectivity-off": {
    title: "Turn the connectivity check off",
    what: ["Writes /etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf and reloads NetworkManager.",
           "The network menu can no longer tell a captive portal from no internet."],
    run: dropIn("/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf", [VIGIL_MARK, "[connectivity]", "enabled=false"])
         + " && sudo /usr/bin/systemctl reload NetworkManager.service"
  },
  "mac-randomize": {
    title: "Use a separate hardware address per network",
    what: ["Writes /etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf and reloads NetworkManager.",
           "Each network sees its own stable address. Takes effect when you next connect."],
    run: "if /usr/bin/grep -rqs '^wifi.backend=iwd' /etc/NetworkManager; then echo 'NetworkManager uses iwd here. Add AddressRandomization=network under [General] in /etc/iwd/main.conf instead.'; exit 1; fi; "
         + dropIn("/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf",
                  [VIGIL_MARK, "[device]", "wifi.scan-rand-mac-address=yes", "[connection]",
                   "wifi.cloned-mac-address=stable", "ethernet.cloned-mac-address=stable"])
         + " && sudo /usr/bin/systemctl reload NetworkManager.service"
  },
  "avahi-quiet": {
    title: "Stop announcing this machine on the network",
    what: ["Edits one line of /etc/avahi/avahi-daemon.conf: disable-publishing=yes, then restarts Avahi.",
           "Stops without changing anything unless that line appears exactly once, under [publish].",
           "The first original is kept as avahi-daemon.conf.vigil-backup; a failed restart rolls back.",
           "Printer discovery keeps working."],
    run: "f=/etc/avahi/avahi-daemon.conf; "
         + "[ \"$(/usr/bin/awk '/^\\[/{s=$0} /^#?disable-publishing=/{n++; if (s != \"[publish]\") bad=1} "
         + "END{print (n == 1 && !bad) ? \"ok\" : \"no\"}' \"$f\")\" = ok ] "
         + "|| { echo 'avahi-daemon.conf does not have the expected layout, so nothing was changed.'; exit 1; }; "
         + "t=$(sudo /usr/bin/mktemp /etc/avahi/.avahi-daemon.conf.XXXXXXXX) && sudo /usr/bin/cp -a \"$f\" \"$t\" && "
         + "sudo /usr/bin/cp -a --update=none \"$f\" \"$f.vigil-backup\" && "
         + "sudo /usr/bin/sed -i -E 's/^#?disable-publishing=.*/disable-publishing=yes/' \"$f\" && "
         + "if /usr/bin/grep -qx 'disable-publishing=yes' \"$f\" && sudo /usr/bin/systemctl restart avahi-daemon.service; "
         + "then sudo /usr/bin/rm -f \"$t\"; echo 'Avahi no longer announces this machine.'; "
         + "else sudo /usr/bin/mv -f \"$t\" \"$f\"; sudo /usr/bin/systemctl restart avahi-daemon.service; "
         + "echo 'The change did not apply cleanly, so the previous file was restored.'; exit 1; fi"
  },
  "sudo-passwordless-off": {
    title: "Turn passwordless sudo off",
    what: ["Runs the Omarchy command omarchy-sudo-passwordless --disable"],
    tool: "omarchy-sudo-passwordless", args: " --disable"
  },
  "docker-group-off": {
    title: "Leave the docker group",
    what: ["Runs the Omarchy command omarchy-remove-security-sudoless-docker", "Docker then needs sudo."],
    tool: "omarchy-remove-security-sudoless-docker", args: ""
  },
  "usb-auth": {
    title: "Set up USB authorization",
    what: ["Runs the Omarchy setup omarchy-setup-security-usb-authorization",
           "It installs USBGuard, trusts the devices plugged in now, and asks you about new ones."],
    tool: "omarchy-setup-security-usb-authorization", args: ""
  },
  "thunderbolt-auth": {
    title: "Set up Thunderbolt authorization",
    what: ["Runs the Omarchy setup omarchy-setup-security-thunderbolt-authorization"],
    tool: "omarchy-setup-security-thunderbolt-authorization", args: ""
  },
  "fido2": {
    title: "Set up a FIDO2 security key",
    what: ["Runs the Omarchy setup omarchy-setup-security-fido2", "Have your security key plugged in."],
    tool: "omarchy-setup-security-fido2", args: ""
  },
  "update": {
    title: "Update the system",
    what: ["Runs the Omarchy updater omarchy-update"],
    tool: "omarchy-update", args: ""
  },
  "allow-idle": {
    title: "Turn Stay Awake off",
    what: ["Runs: omarchy-toggle-idle allow-idle", "The screen locks again when you are idle."],
    tool: "omarchy-toggle-idle", args: " allow-idle"
  },
  "install-clamav": {
    title: "Install ClamAV",
    what: ["Installs clamav with omarchy pkg add, then downloads the virus database with freshclam."],
    tool: "omarchy-pkg-add", args: " clamav && sudo /usr/bin/freshclam && sudo /usr/bin/systemctl enable --now clamav-freshclam.service"
  },
  "freshclam-service": {
    title: "Keep virus signatures updated automatically",
    what: ["Turns on the ClamAV update service (clamav-freshclam), which downloads new signatures",
           "from the ClamAV servers several times a day, and fetches them once now."],
    run: "sudo /usr/bin/systemctl enable --now clamav-freshclam.service"
  },
  "install-osv-scanner": {
    title: "Install osv-scanner",
    what: ["Installs osv-scanner, the Google tool for checking packages against OSV.dev, with omarchy pkg add.",
           "Vigil then checks your npm and Bun packages for known malware once a week."],
    tool: "omarchy-pkg-add", args: " osv-scanner"
  },
  "freshclam": {
    title: "Update the ClamAV database",
    what: ["Runs: sudo freshclam (downloads signatures from the ClamAV servers)"],
    run: "sudo /usr/bin/freshclam"
  },
  "install-clamui": {
    title: "Install ClamUI",
    what: ["Installs flatpak and clamav with omarchy pkg add, adds the Flathub remote for your account,",
           "installs ClamUI from Flathub (io.github.linx_systems.ClamUI), downloads virus signatures,",
           "and turns on the ClamAV service that keeps them updated.",
           "Contacts the Arch mirrors, dl.flathub.org and the ClamAV servers."],
    tool: "omarchy-pkg-add", args: " flatpak clamav && "
      + "/usr/bin/flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo && "
      + "/usr/bin/flatpak install --user flathub io.github.linx_systems.ClamUI && sudo /usr/bin/freshclam && "
      + "sudo /usr/bin/systemctl enable --now clamav-freshclam.service"
  },
  "scan-downloads": {
    title: "Scan ~/Downloads for viruses",
    what: ["Runs: clamscan --recursive --infected ~/Downloads", "Only infected files are listed. Nothing is deleted."],
    run: "/usr/bin/clamscan --recursive --infected -- \"$HOME/Downloads\""
  },
  "install-rkhunter": {
    title: "Install Rootkit Hunter",
    what: ["Installs rkhunter with omarchy pkg add and records what this system looks like now (--propupd)."],
    tool: "omarchy-pkg-add", args: " rkhunter && sudo /usr/bin/rkhunter --propupd"
  },
  "run-rkhunter": {
    title: "Check for rootkits",
    what: ["Updates the rkhunter data files from its maintainers, then runs",
           "sudo rkhunter --check --skip-keypress --report-warnings-only",
           "Warnings need reading: after updates, changed system files are expected."],
    run: "sudo /usr/bin/rkhunter --update; sudo /usr/bin/rkhunter --check --skip-keypress --report-warnings-only"
  },
  "install-lynis": {
    title: "Install Lynis",
    what: ["Installs lynis with omarchy pkg add."],
    tool: "omarchy-pkg-add", args: " lynis"
  },
  "run-lynis": {
    title: "Run a Lynis audit",
    what: ["Runs: sudo lynis audit system --quick", "Ends with a hardening index and a list of suggestions."],
    run: "sudo /usr/bin/lynis audit system --quick"
  },
  "install-arch-audit": {
    title: "Install arch-audit",
    what: ["Installs arch-audit with omarchy pkg add."],
    tool: "omarchy-pkg-add", args: " arch-audit"
  },
  "run-arch-audit": {
    title: "List packages with known vulnerabilities",
    what: ["Runs: arch-audit --upgradable (contacts security.archlinux.org)",
           "Shows vulnerable packages that already have a fixed version: update to get it."],
    run: "/usr/bin/arch-audit --upgradable && echo 'Done. Nothing listed means nothing to fix.'"
  },
  "clean-pacman-cache": {
    title: "Trim the package cache",
    what: ["Runs: sudo paccache -rk2", "Keeps the two newest versions of each package for rollback."],
    run: "sudo /usr/bin/paccache -rk2"
  },
  "clean-orphans": {
    title: "Review orphaned packages",
    what: ["Runs the Omarchy command omarchy-update-orphan-pkgs", "It lists them and asks before removing anything."],
    tool: "omarchy-update-orphan-pkgs", args: ""
  },
  "clean-journal": {
    title: "Trim system logs",
    what: ["Runs: sudo journalctl --vacuum-time=2weeks", "Keeps the last two weeks of logs."],
    run: "sudo /usr/bin/journalctl --vacuum-time=2weeks"
  },
  "undo-sysctl": undoDropIn("kernel and network settings", "/etc/sysctl.d/90-omarchy-vigil.conf",
    "Reloads the remaining settings. The previous values come back after a reboot.",
    "sudo /usr/bin/sysctl --system >/dev/null; echo 'Removed. The previous kernel values come back after a reboot.'"),
  "undo-llmnr": undoDropIn("LLMNR", "/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf",
    "Then restarts systemd-resolved.",
    "sudo /usr/bin/systemctl restart systemd-resolved.service"),
  "undo-dns-fallback": undoDropIn("the DNS fallback", "/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf",
    "Then restarts systemd-resolved.",
    "sudo /usr/bin/systemctl restart systemd-resolved.service"),
  "undo-sshd": undoDropIn("SSH", "/etc/ssh/sshd_config.d/00-omarchy-vigil.conf",
    "Then reloads sshd if it is running. Passwords and root login go back to your other settings.",
    "if /usr/bin/systemctl is-active --quiet sshd.service; then sudo /usr/bin/systemctl reload sshd.service; fi"),
  "undo-connectivity": undoDropIn("the connectivity check", "/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf",
    "Then reloads NetworkManager.",
    "sudo /usr/bin/systemctl reload NetworkManager.service"),
  "undo-mac": undoDropIn("the hardware address", "/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf",
    "Then reloads NetworkManager. Takes effect when you next connect.",
    "sudo /usr/bin/systemctl reload NetworkManager.service"),
  "undo-avahi": {
    title: "Undo: restore the original Avahi settings",
    what: ["Puts back /etc/avahi/avahi-daemon.conf.vigil-backup, the file as it was before Vigil first changed it,",
           "and restarts Avahi. Edits made to the file since then are lost."],
    run: "b=/etc/avahi/avahi-daemon.conf.vigil-backup; "
         + "[ -f \"$b\" ] || { echo 'There is no backup to restore.'; exit 0; }; "
         + "sudo /usr/bin/mv -f -- \"$b\" /etc/avahi/avahi-daemon.conf && sudo /usr/bin/systemctl restart avahi-daemon.service"
  }
}

// App actions open another program you installed, with a fixed argv and no
// shell. The helper reports how the app is installed; anything else is "".
var APP_ACTIONS = {
  "open-clamui": {
    app: "clamui",
    argv: {
      "native": ["/usr/bin/clamui"],
      "flatpak": ["/usr/bin/flatpak", "run", "io.github.linx_systems.ClamUI"]
    }
  }
}

function appCommand(id, apps) {
  if (typeof id !== "string" || !Object.prototype.hasOwnProperty.call(APP_ACTIONS, id)) return []
  var a = APP_ACTIONS[id]
  if (!apps || typeof apps !== "object" || !Object.prototype.hasOwnProperty.call(apps, a.app)) return []
  var kind = apps[a.app]
  if (!Object.prototype.hasOwnProperty.call(a.argv, kind)) return []
  return a.argv[kind].slice(0)
}

function terminalAction(id) {
  if (typeof id !== "string" || !Object.prototype.hasOwnProperty.call(TERMINAL_ACTIONS, id)) return null
  return TERMINAL_ACTIONS[id] || null
}

function toolDir(tools, name) {
  if (!tools || typeof tools !== "object") return ""
  var dir = Object.prototype.hasOwnProperty.call(tools, name) ? tools[name] : ""
  return inList(dir, TRUSTED_TOOL_DIRS) ? dir : ""
}

// The full script for a terminal action, or "" when it cannot run here.
function terminalScript(id, tools) {
  var a = terminalAction(id)
  if (!a) return ""
  var body = ""
  if (a.tool) {
    var dir = toolDir(tools, a.tool)
    if (dir === "") return ""
    body = dir + "/" + a.tool + a.args
  } else {
    body = a.run
  }
  var intro = ["Vigil: " + a.title, ""].concat(a.what).concat([""])
  var shown = []
  for (var i = 0; i < intro.length; i++) shown.push("'" + intro[i] + "'")
  return "printf '%s\\n' " + shown.join(" ")
    + "; read -r -p 'Press Enter to continue, or Ctrl+C to cancel. ' _ && ( set -e; " + body + " )"
}

function launcherPath(tools) {
  var dir = toolDir(tools, LAUNCHER)
  return dir === "" ? "" : dir + "/" + LAUNCHER
}

function canRun(fixObj, tools, apps) {
  if (!fixObj) return false
  if (fixObj.kind === "app") return appCommand(fixObj.action, apps).length > 0
  if (fixObj.kind === "helper") return isHelperAction(fixObj.action)
  if (fixObj.kind === "terminal") return launcherPath(tools) !== "" && terminalScript(fixObj.action, tools) !== ""
  return false
}

// ---------------------------------------------------------------------------
// Report validation

function validFix(f) {
  if (!f || typeof f !== "object") return null
  if (!inList(f.kind, FIX_KINDS)) return null
  if (!isString(f.action, 32) || !/^[a-z0-9-]*$/.test(f.action)) return null
  if (!isString(f.label, 60)) return null
  if (f.kind === "helper" && !inList(f.action, HELPER_ACTIONS)) return { kind: "none", action: "", label: "" }
  if (f.kind === "terminal" && !terminalAction(f.action)) return { kind: "none", action: "", label: "" }
  if (f.kind === "app" && !Object.prototype.hasOwnProperty.call(APP_ACTIONS, f.action)) return { kind: "none", action: "", label: "" }
  return { kind: f.kind, action: f.action, label: plain(f.label, 60) }
}

function validCheck(c) {
  if (!c || typeof c !== "object") return null
  if (!isString(c.id, 40) || !/^[a-z0-9-]+$/.test(c.id)) return null
  if (!inList(c.category, CATEGORIES) || !inList(c.status, STATUSES)) return null
  if (!isString(c.title, MAX_STR) || !isString(c.summary, MAX_STR)) return null
  if (!isString(c.why, MAX_STR * 2) || !isString(c.detail, MAX_DETAIL)) return null
  if (typeof c.weight !== "number" || !isFinite(c.weight) || c.weight < 0 || c.weight > 3 || Math.floor(c.weight) !== c.weight) return null
  var f = validFix(c.fix)
  if (!f) return null
  var undo = { action: "", label: "" }
  if (c.undo !== undefined) {
    if (!c.undo || typeof c.undo !== "object" || !isString(c.undo.action, 32) || !isString(c.undo.label, 60)) return null
    if (c.undo.action !== "") {
      if (c.undo.action.indexOf("undo-") !== 0 || !terminalAction(c.undo.action)) return null
      undo = { action: c.undo.action, label: plain(c.undo.label, 60) }
    }
  }
  var dismissible = c.dismissible === true
  var dismissed = c.dismissed === true
  if ((c.dismissible !== undefined && typeof c.dismissible !== "boolean")
      || (c.dismissed !== undefined && typeof c.dismissed !== "boolean")) return null
  if (dismissed && (!dismissible || c.status !== "warn")) return null
  var dismissedAt = ""
  if (c.dismissedAt !== undefined && c.dismissedAt !== "") {
    if (!isString(c.dismissedAt, 10) || !/^\d{4}-\d{2}-\d{2}$/.test(c.dismissedAt)) return null
    dismissedAt = c.dismissedAt
  }
  return {
    id: c.id, category: c.category, status: c.status, weight: c.weight,
    title: plain(c.title, 80), summary: plain(c.summary, MAX_STR), why: plain(c.why, MAX_STR * 2),
    detail: plain(c.detail, MAX_DETAIL), fix: f, undo: undo,
    dismissible: dismissible, dismissed: dismissed, dismissedAt: dismissedAt
  }
}

var SOURCE_IDS = ["signatures", "virus-scan", "arch-audit", "osv", "aur", "bumblebee"]
var SOURCE_STATES = ["ok", "stale", "never", "failed"]
var DATE_RE = /^\d{4}-\d{2}-\d{2}$/

function parseSources(list) {
  if (list === undefined) return []
  if (!Array.isArray(list) || list.length > SOURCE_IDS.length) return null
  var out = []
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    if (!e || typeof e !== "object" || !inList(e.id, SOURCE_IDS) || !inList(e.state, SOURCE_STATES)) return null
    if (!isString(e.label, 40) || !isString(e.date, 10) || !isString(e.tried, 10)) return null
    if ((e.date !== "" && !DATE_RE.test(e.date)) || (e.tried !== "" && !DATE_RE.test(e.tried))) return null
    out.push({ id: e.id, label: plain(e.label, 40), date: e.date, state: e.state, tried: e.tried })
  }
  return out
}

function parseLastRun(r) {
  if (r === undefined) return { at: "", ok: false }
  if (!r || typeof r !== "object" || !isString(r.at, 16) || typeof r.ok !== "boolean") return null
  if (r.at !== "" && !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(r.at)) return null
  return { at: r.at, ok: r.ok }
}

// "today", "yesterday", or "Oct 3", relative to `now` (a Date).
function relativeDay(date, now) {
  var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(date))
  if (!m) return ""
  var day = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  var today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  var diff = Math.round((today - day) / 86400000)
  if (diff === 0) return "today"
  if (diff === 1) return "yesterday"
  return shortDate(String(date).substring(0, 10))
}

function sourceLine(src, now) {
  // Scans "ran"; databases and signatures are "updated".
  var scan = src.id === "virus-scan" || src.id === "bumblebee"
  if (src.state === "never") return scan ? "not run yet" : "not updated yet"
  if (src.state === "failed")
    return (scan ? "last run failed" : "last update failed") + (src.date !== "" ? "; last good " + relativeDay(src.date, now) : "")
  var when = relativeDay(src.date, now)
  return src.state === "stale" ? "out of date (" + when + ")" : (scan ? "ran " : "updated ") + when
}

function lastRunLine(run, now) {
  if (!run || run.at === "") return "No full update yet. It runs within a day, or press the button."
  var time = run.at.substring(11, 16)
  return "Last full update " + relativeDay(run.at, now) + " at " + time
    + (run.ok ? ". Every source refreshed." : ". Some sources did not refresh; Vigil tries again tomorrow.")
}

function parseHistory(h) {
  if (h === undefined) return []
  if (!Array.isArray(h) || h.length > 60) return null
  var out = []
  for (var i = 0; i < h.length; i++) {
    var e = h[i]
    if (!e || typeof e !== "object" || !isString(e.date, 10) || !/^\d{4}-\d{2}-\d{2}$/.test(e.date)) return null
    if (typeof e.score !== "number" || !isFinite(e.score) || e.score < 0 || e.score > 100 || Math.floor(e.score) !== e.score) return null
    out.push({ date: e.date, score: e.score })
  }
  return out
}

function parseReport(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_REPORT_CHARS) return null
  var d
  try { d = JSON.parse(text) } catch (e) { return null }
  if (!d || typeof d !== "object" || d.schema !== 1) return null
  if (!Array.isArray(d.checks) || d.checks.length > MAX_CHECKS) return null
  if (typeof d.score !== "number" || !isFinite(d.score) || d.score < 0 || d.score > 100) return null
  if (!inList(d.level, ["ok", "warn", "fail"])) return null
  if (!isString(d.generatedAt, 40) || !isString(d.version, 20)) return null
  var checks = []
  var seen = Object.create(null)
  for (var i = 0; i < d.checks.length; i++) {
    var c = validCheck(d.checks[i])
    if (!c || seen[c.id]) return null
    seen[c.id] = true
    checks.push(c)
  }
  var tools = Object.create(null)
  if (d.tools && typeof d.tools === "object") {
    for (var name in d.tools) {
      if (!Object.prototype.hasOwnProperty.call(d.tools, name)) continue
      if (!/^omarchy-[a-z0-9-]{1,60}$/.test(name)) return null
      var dir = d.tools[name]
      if (dir !== "" && !inList(dir, TRUSTED_TOOL_DIRS)) return null
      tools[name] = dir
    }
  }
  var apps = Object.create(null)
  apps.clamui = ""
  if (d.apps !== undefined) {
    if (!d.apps || typeof d.apps !== "object" || Array.isArray(d.apps)) return null
    if (d.apps.clamui !== undefined) {
      if (!inList(d.apps.clamui, ["", "native", "flatpak"])) return null
      apps.clamui = d.apps.clamui
    }
  }
  var fresh = []
  if (Array.isArray(d["new"])) {
    if (d["new"].length > 40) return null
    for (var j = 0; j < d["new"].length; j++) {
      var id = d["new"][j]
      if (!isString(id, 40) || !seen[id]) return null
      fresh.push(id)
    }
  }
  var history = parseHistory(d.history)
  if (!history) return null
  if (d.feedsDue !== undefined && typeof d.feedsDue !== "boolean") return null
  var feedsUpdated = ""
  if (d.feedsUpdated !== undefined && d.feedsUpdated !== "") {
    if (!isString(d.feedsUpdated, 10) || !/^\d{4}-\d{2}-\d{2}$/.test(d.feedsUpdated)) return null
    feedsUpdated = d.feedsUpdated
  }
  var sources = parseSources(d.sources)
  var lastRun = parseLastRun(d.lastRun)
  if (!sources || !lastRun) return null
  return {
    sources: sources,
    lastRun: lastRun,
    feedsDue: d.feedsDue === true,
    feedsUpdated: feedsUpdated,
    history: history,
    version: plain(d.version, 20), generatedAt: plain(d.generatedAt, 40),
    score: Math.round(d.score), level: d.level, checks: checks, tools: tools, apps: apps, fresh: fresh
  }
}

function parseFixResult(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > 4096) return null
  var d
  try { d = JSON.parse(text) } catch (e) { return null }
  if (!d || typeof d !== "object" || typeof d.ok !== "boolean" || !isString(d.message, 400)) return null
  return { ok: d.ok, message: plain(d.message, 240) }
}

// ---------------------------------------------------------------------------
// Display

function checksFor(report, category) {
  if (!report) return []
  var out = []
  for (var i = 0; i < report.checks.length; i++)
    if (report.checks[i].category === category) out.push(report.checks[i])
  // Reviewed warnings sort after the information rows, just above "pass".
  function rank(c) { return c.dismissed ? STATUSES.indexOf("info") + 0.5 : STATUSES.indexOf(c.status) }
  out.sort(function(a, b) {
    var d = rank(a) - rank(b)
    return d !== 0 ? d : b.weight - a.weight
  })
  return out
}

// Scored problems first, worst first: what the Overview tab lists.
function topFindings(report, max) {
  if (!report) return []
  var out = []
  for (var i = 0; i < report.checks.length; i++) {
    var c = report.checks[i]
    if ((c.status === "fail" || c.status === "warn") && c.weight > 0 && !c.dismissed) out.push(c)
  }
  out.sort(function(a, b) {
    if (a.status !== b.status) return a.status === "fail" ? -1 : 1
    return b.weight - a.weight
  })
  return out.slice(0, max || 6)
}

function countBy(report, category, status) {
  if (!report) return 0
  var n = 0
  for (var i = 0; i < report.checks.length; i++) {
    var c = report.checks[i]
    if ((category === "" || c.category === category) && c.status === status && !c.dismissed) n++
  }
  return n
}

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

function shortDate(date) {
  var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(date))
  if (!m) return ""
  var month = Number(m[2])
  return month >= 1 && month <= 12 ? MONTHS[month - 1] + " " + Number(m[3]) : ""
}

// One line that states the history in words, for when the bars are not seen.
function historySummary(history) {
  if (!history || history.length === 0) return ""
  var lo = 100, hi = 0
  for (var i = 0; i < history.length; i++) { lo = Math.min(lo, history[i].score); hi = Math.max(hi, history[i].score) }
  var first = history[0], last = history[history.length - 1]
  if (history.length === 1) return "Today " + last.score + ". The chart fills in day by day."
  return shortDate(first.date) + " " + first.score + " \u2192 " + shortDate(last.date) + " " + last.score
    + " \u00b7 low " + lo + ", high " + hi
}

function statusGlyph(status) {
  switch (status) {
  case "fail": return "✕"
  case "warn": return "!"
  case "pass": return "✓"
  case "info": return "•"
  case "unknown": return "?"
  default: return "–"
  }
}

function levelText(report) {
  if (!report) return "Not checked yet"
  if (report.level === "fail") return "Needs attention"
  if (report.level === "warn") return "A few things to improve"
  return "Looking good"
}

function categoryLabel(category) {
  return { overview: "Overview", harden: "Harden", detect: "Detect", supply: "Supply",
           privacy: "Privacy", care: "Care" }[category] || ""
}

// The question each pillar answers, and in one line what it covers.
var TAB_INTROS = {
  harden: { question: "Can someone get in?",
            text: "Settings that make this machine harder to break into." },
  detect: { question: "Is something bad already here?",
            text: "Signs of malware, virus scanning with ClamUI, and rootkit checks." },
  supply: { question: "Can you trust what you installed?",
            text: "Packages with known vulnerabilities, known-malicious components, and plugins." },
  privacy: { question: "What does this machine give away?",
             text: "What it tells the networks it joins and the companies behind its apps." },
  care: { question: "Is the system tidy?",
          text: "Space you can reclaim and traces you can clear." }
}

function tabIntro(tab) {
  return TAB_INTROS[tab] || { question: "", text: "" }
}

function tooltip(report, running) {
  if (running && !report) return "Vigil: checking"
  if (!report) return "Vigil"
  var f = countBy(report, "", "fail")
  var w = countBy(report, "", "warn")
  var parts = ["Vigil " + report.score + "/100"]
  if (f) parts.push(f + " to fix")
  if (w) parts.push(w + " to improve")
  return plain(parts.join(" · "), 80)
}

// Exported for the Node tests; the QML engine has no `module`.
if (typeof module !== "undefined") {
  module.exports = {
    plain: plain, parseReport: parseReport, parseFixResult: parseFixResult, terminalScript: terminalScript,
    terminalAction: terminalAction, launcherPath: launcherPath, canRun: canRun, checksFor: checksFor,
    topFindings: topFindings, countBy: countBy, statusGlyph: statusGlyph, levelText: levelText,
    tooltip: tooltip, confirmation: confirmation, helperInfo: helperInfo, isHelperAction: isHelperAction,
    categoryLabel: categoryLabel, tabIntro: tabIntro, appCommand: appCommand, APP_ACTIONS: APP_ACTIONS,
    shortDate: shortDate, historySummary: historySummary, VIGIL_MARK: VIGIL_MARK,
    relativeDay: relativeDay, sourceLine: sourceLine, lastRunLine: lastRunLine,
    TERMINAL_ACTIONS: TERMINAL_ACTIONS, HELPER_ACTIONS: HELPER_ACTIONS, HELPER_INFO: HELPER_INFO,
    SYSCTL_LINES: SYSCTL_LINES
  }
}
