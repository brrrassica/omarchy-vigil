// Pure logic for the Vigil panel: validating the helper's report, the closed
// tables of actions, and display helpers. No QML types are used here, so the
// file is loaded unchanged by the tests in tests/model.test.mjs.
//
// Everything that comes back from bin/vigil is treated as untrusted input:
// it is size-checked by the caller, parsed here, and every field is checked
// for type, range and length before the panel shows it. A report that does
// not match the shape is rejected whole rather than trimmed into shape.

// Must match manifest.json and VERSION in bin/vigil (a test checks). The
// helper runs from disk every time, but this file stays loaded until the
// shell restarts, so after an update the two can differ for a while.
var VERSION = "0.30.0"
var MAX_REPORT_CHARS = 512 * 1024
var MAX_CHECKS = 160
var MAX_STR = 400
var MAX_DETAIL = 4000

var CATEGORIES = ["harden", "detect", "supply", "privacy", "care"]
var STATUSES = ["fail", "warn", "unknown", "info", "pass", "na"]
var FIX_KINDS = ["terminal", "helper", "app", "docs", "none"]
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
// need root. Every other action is one of the constant scripts below: shown in
// full on the confirmation card, then run as you, as root through pkexec
// (Omarchy's password dialog asks; cancelling it changes nothing), or, for
// tools that ask questions as they go, in a visible terminal.
// No value from the report, a file or the network is ever put into a script:
// the report only names an action id, and an unknown id does nothing.

var HELPER_ACTIONS = ["ssh-perms", "gnupg-perms", "optout-on", "optout-off", "clean-thumbnails", "empty-trash",
                      "credential-perms", "integrity-accept", "arch-audit-refresh", "osv-refresh", "aur-refresh",
                      "virus-scan-now", "clean-user", "clean-app-cache", "remove-secret-lines"]

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
  "clean-user": { title: "Clear thumbnails, the trash and unused caches",
                  what: ["The no-root half of Clean all."] },
  "remove-secret-lines": { title: "Remove leaked keys from your shell history",
                          what: ["Deletes the lines in your shell history that contain the keys Vigil found. Nothing else changes.",
                                 "Close your other terminal windows first: an open shell can write its history back.",
                                 "Also revoke those keys with the service that issued them: they may already have been read."] },
  "clean-app-cache": { title: "Clear unused application caches",
                       what: ["Deletes files in ~/.cache that no app has read or written for a week.",
                              "Caches in use are left alone; apps rebuild anything they need."] },
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
  "virus-scan-now": { title: "Scan your home folder for viruses now",
                      what: ["Runs ClamAV on your whole home folder as you, in the background. Nothing is deleted.",
                             "It can take a while. Vigil also does this in each weekly check."] },
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

// "How to fix" on an open finding: the helper's own words when it gave any,
// otherwise what the fix button does.
function howTo(check) {
  if (!check || check.status === "pass" || check.status === "na") return ""
  if (check.howto) return check.howto
  if (!check.fix || check.fix.kind === "none") return ""
  if (check.fix.kind === "app") return "Press " + check.fix.label + "."
  var a = check.fix.kind === "helper" ? helperInfo(check.fix.action)
    : (check.fix.kind === "terminal" ? terminalAction(check.fix.action) : null)
  if (!a) return ""
  var plainLines = a.what.filter(function(l) { return l.indexOf("Technical:") !== 0 })
  return "Press " + check.fix.label + ": " + plainLines.join(" ")
    + (check.fix.kind === "terminal" ? " It shows what it will do and asks before changing anything." : "")
}

// The confirmation card of any runnable action: its title, what it does in
// plain words, and the exact commands it starts ({ who, text } each), so every
// root step is on the card in full before you press Run. home is your home
// folder, which the root scripts get as HOME.
function confirmation(kind, id, report, home) {
  var card = confirmationText(kind, id, report)
  if (!card) return null
  var tools = report && report.tools ? report.tools : {}
  card.commands = kind === "terminal" ? actionCommands(id, tools, home)
    : kind === "clean-all" && cleanAllPlan(report).system ? actionCommands("clean-system", tools, home)
    : kind === "update-sources" || kind === "full-scan" ? runCommands(kind, report)
    : []
  return card
}

// The argv of one step and the script it runs, for the card: the program and
// its options on the first line, then the script exactly as it is passed.
function commandText(argv) {
  return argv.slice(0, -1).join(" ") + "\n" + argv[argv.length - 1]
}

function actionCommands(id, tools, home) {
  if (runMode(id) === "terminal") {
    var body = actionBody(terminalAction(id), tools)
    return body === "" ? [] : [{ who: "In a terminal, as you, after you press Enter there:", text: body }]
  }
  var steps = actionPlan(id, tools, home)
  var out = []
  for (var i = 0; i < steps.length; i++)
    out.push({ who: steps[i].asRoot ? "As root, through pkexec (Omarchy asks for your password):"
                                    : (i > 0 ? "Then, as you:" : "As you, no password:"),
               text: commandText(steps[i].argv) })
  return out
}

// The run cards' root steps, exactly as the helper starts them: the ClamAV
// signatures and a Bumblebee update behind one password prompt (each only when
// it applies), and in Run all the password scan. The rest runs as you.
function runCommands(kind, report) {
  if (!report || toolDir(report.tools, "pkexec") === "") return []
  var signatures = report.sources.some(function(s) { return s.id === "signatures" })
  var bumblebee = report.checks.some(function(c) { return c.id === "bumblebee" && c.fix.action === "update-bumblebee" })
  var out = []
  if (signatures || bumblebee)
    out.push({ who: "As root, through pkexec (Omarchy asks for your password):",
               text: commandText([PKEXEC, BASH, "-c", rootUpdatesScript(signatures, bumblebee)]) })
  if (kind === "full-scan")
    out.push({ who: "As root, through pkexec, for the password scan (only account names are kept):",
               text: commandText([PKEXEC, BASH, "-c", NO_PASSWORD_STEP]) })
  return out
}

function confirmationText(kind, id, report) {
  if (kind === "clean-all") return cleanAllConfirmation(report)
  if (kind === "ignore") return ignoreConfirmation(id, report)
  if (kind === "trash") return trashConfirmation(id, report)
  if (kind === "trash-all") return trashAllConfirmation(report)
  if (kind === "update-sources") return updateConfirmation(report)
  if (kind === "full-scan") return fullScanConfirmation(report)
  if (kind === "daily-check") return dailyConfirmation(report)
  if (kind === "weekly-check") return weeklyConfirmation(report)
  var a = kind === "helper" ? helperInfo(id) : (kind === "terminal" ? terminalAction(id) : null)
  if (!a) return null
  var lines = a.what.slice(0)
  if (id === "install-helpers" && report && report.missing && report.missing.length)
    lines.unshift("Missing now: " + report.missing.map(function(m) { return HELPER_NAMES[m] }).join(", ") + ".")
  if (kind === "terminal") {
    var mode = runMode(id)
    lines.push(mode === "terminal" ? "Opens a terminal: this tool asks you questions as it goes."
      : mode === "root" ? "Omarchy asks for your password, then Vigil shows the result here."
      : "Vigil shows the result here. No password needed.")
  }
  return { title: a.title, lines: lines }
}

// Find one item of a check in the report by its id: a virus detection
// ("detection") or a leftover of an app that is gone ("leftover").
function findItem(report, id, kind) {
  if (!report || typeof id !== "string" || !/^[0-9a-f]{16}$/.test(id)) return null
  for (var i = 0; i < report.checks.length; i++) {
    var items = report.checks[i].items || []
    for (var j = 0; j < items.length; j++) if (items[j].id === id && items[j].kind === kind) return items[j]
  }
  return null
}

function detectionItem(report, id) { return findItem(report, id, "detection") }
function leftoverItem(report, id) { return findItem(report, id, "leftover") }

// The leftovers Move all to trash would move: every listed item not kept.
function leftoverTrashIds(report) {
  if (!report || !report.checks) return []
  var out = []
  for (var i = 0; i < report.checks.length; i++) {
    var items = report.checks[i].items || []
    for (var j = 0; j < items.length; j++)
      if (items[j].kind === "leftover" && !items[j].kept) out.push(items[j].id)
  }
  return out
}

var TRASH_LINES = [
  "It goes to the trash, not away: open the trash in your file manager and choose Restore to put it back where it was.",
  "Emptying the trash deletes it for good. So does Empty on the Trash row and Clean all on this tab, which empty the trash too.",
  "If you install the app again, it starts with fresh settings unless you restore this first.",
  "Technical: renames it into ~/.local/share/Trash/files and records where it came from in ~/.local/share/Trash/info, the freedesktop.org trash every file manager reads. Nothing is copied or deleted. Vigil checks again that no installed app uses it before it moves anything."]

function trashConfirmation(id, report) {
  var item = leftoverItem(report, id)
  if (!item || item.kept) return null
  return { title: "Move this to the trash?", lines: [item.text].concat(TRASH_LINES) }
}

function trashAllConfirmation(report) {
  var ids = leftoverTrashIds(report)
  if (ids.length === 0) return null
  var lines = []
  for (var i = 0; i < ids.length && i < 40; i++) lines.push(leftoverItem(report, ids[i]).text)
  if (ids.length > 40) lines.push("… and " + (ids.length - 40) + " more")
  lines.push("Items you marked Keep stay where they are.")
  return { title: "Move " + ids.length + (ids.length === 1 ? " item" : " items") + " to the trash?",
           lines: lines.concat(TRASH_LINES) }
}

function ignoreConfirmation(id, report) {
  var item = detectionItem(report, id)
  if (!item || item.ignored) return null
  return { title: "Mark this as a false positive?", lines: [
    item.text,
    "A false positive is a safe file ClamAV mistakes for a virus. Only mark it if you are sure, for example a game or app file you got from its official source.",
    "Not sure? Open ClamUI: it can look the file up on VirusTotal, where many virus scanners check it.",
    "Vigil stops counting this file only while it stays exactly as it is now. If it ever changes, Vigil reports it again.",
    "Technical: records the SHA-256 of this file in ~/.local/state/omarchy-vigil/ignored-detections.json"] }
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
    what: ["Puts " + name + " back the way it was before Vigil changed it.",
           "If someone has edited the file since, it is left alone. " + afterText,
           "Technical: deletes " + path + " if its first line is still the Vigil marker"],
    run: "f=" + path + "; "
         + "[ -e \"$f\" ] || { echo 'Nothing to undo.'; exit 0; }; "
         + "[ \"$(/usr/bin/head -n 1 -- \"$f\")\" = '" + VIGIL_MARK + "' ] "
         + "|| { echo 'The file was changed since Vigil wrote it, so it was left alone.'; exit 1; }; "
         + "sudo /usr/bin/rm -f -- \"$f\" && " + after
  }
}

// How an action runs. Most run without a terminal: "root" ones through pkexec,
// so Omarchy's own password dialog asks, "user" ones as you; the panel shows
// what they printed. Only tools that ask you questions as they go (Omarchy's
// updater and setup wizards, the orphan review, choosing an SSH passphrase)
// keep a terminal.
var TERMINAL_ONLY = ["update", "update-firmware", "fido2", "undo-fido2", "fingerprint", "undo-fingerprint", "sudo-passwordless-off",
                     "docker-group-off", "clean-orphans", "ssh-passphrase"]
var USER_MODE = ["allow-idle", "restart", "run-arch-audit", "show-ld-preload", "show-plugins", "screen-lock-default",
                 "hand-over-schedules", "undo-schedules", "update-flatpaks", "wifi-autojoin-off", "undo-wifi-autojoin"]
var PKEXEC = "/usr/bin/pkexec"
var BASH = "/usr/bin/bash"

function runMode(id) {
  if (!terminalAction(id)) return ""
  if (inList(id, TERMINAL_ONLY)) return "terminal"
  return inList(id, USER_MODE) ? "user" : "root"
}

// The command lines of an action's body: the script with its sudo prefixes
// removed when it runs as root (it already is), or a tool resolved to a
// trusted path.
function actionBody(a, tools) {
  if (a.tool) {
    var dir = toolDir(tools, a.tool)
    return dir === "" ? "" : dir + "/" + a.tool + a.args
  }
  if (a.source) {
    var sdir = toolDir(tools, a.source)
    return sdir === "" ? "" : "source " + sdir + "/" + a.source + " && " + a.run
  }
  return usesSh(a, tools) + a.run
}

// Omarchy commands a script calls (its `uses`), resolved like every other
// Omarchy tool to a root-owned file in /usr/bin or /usr/share/omarchy/bin and
// set at the top as shell variables, so the script names them by absolute path
// (omarchy-plugin-disable becomes $omarchy_plugin_disable). One that is not
// found is left empty, and the script skips that step.
function usesSh(a, tools) {
  var out = ""
  var names = a.uses || []
  for (var i = 0; i < names.length; i++) {
    var dir = toolDir(tools, names[i])
    out += names[i].replace(/-/g, "_") + "=" + (dir === "" ? "" : dir + "/" + names[i]) + "\n"
  }
  return out
}

function stripSudo(script) {
  return script.replace(/(^|[\s;&|(!])sudo /g, "$1")
}

// The processes to run for an action outside a terminal, in order:
// [{ argv, asRoot }]. home is your home folder, for the scripts that need it.
function actionPlan(id, tools, home) {
  var a = terminalAction(id)
  var mode = runMode(id)
  if (!a || mode === "terminal" || mode === "") return []
  var body = actionBody(a, tools)
  if (body === "") return []
  if (mode === "user") return [{ argv: [BASH, "-c", "set -e\n" + body], asRoot: false }]
  if (toolDir(tools, "pkexec") === "" || typeof home !== "string" || !/^\/[^\0\n]{0,200}$/.test(home)) return []
  // The first line says the password was accepted, for the progress bar.
  var steps = [{ argv: [PKEXEC, "/usr/bin/env", "HOME=" + home, BASH, "-c",
                        "set -e\necho VIGIL-STEP 0\n" + stripSudo(body)], asRoot: true }]
  if (a.then) steps.push({ argv: [BASH, "-c", "set -e\n" + a.then], asRoot: false })
  return steps
}

// Each entry: title, what (lines shown before anything runs), and either a
// constant `run` script or an Omarchy `tool` (resolved to a root-owned path
// in /usr/bin or /usr/share/omarchy/bin by the helper) with constant `args`.
// Shared by the package-cache fix and Clean all: show the size before and after.
var PKG_DU = "$(/usr/bin/du -sh /var/cache/pacman/pkg 2>/dev/null | /usr/bin/cut -f1)"
var PACCACHE_RUN = "before=" + PKG_DU + "; sudo /usr/bin/paccache -rk2; sudo /usr/bin/paccache -ruk0; "
  + "echo \"Package cache: $before before, " + PKG_DU + " now.\""

// Must match OLD_SERVICES in bin/vigil (a test checks).
var OLD_SERVICES = ["telnet.socket", "rsh.socket", "rlogin.socket", "ftpd.service", "tftpd.socket",
                    "tftpd.service", "xinetd.service", "ypserv.service", "ypbind.service"]

// Installs or updates Bumblebee, as root: the pinned BUMBLEBEE_VERSION, the
// download capped in bytes and checked against the SHA-256 written in the
// helper, installed only as a regular file, and never run as root. The helper runs
// the same script in Run list update. Must equal BUMBLEBEE_SCRIPT in bin/vigil
// (a test checks).
var BUMBLEBEE_VERSION = "0.1.2"
var BUMBLEBEE_INSTALL = "set -o pipefail\nv=0.1.2\ncase \"$(/usr/bin/uname -m)\" in x86_64) a=amd64; want=53b080cf3ddb692b0c4e5492ef4785b4c54daf1624fcd0fcba3958116a0be8d9 ;; aarch64) a=arm64; want=cb641a1023b12cd7b1411ebef5c7d426f7ecd81770a15a85873c5334a0e6b74d ;; *) echo 'Bumblebee has no build for this computer.'; exit 0 ;; esac\nt=$(/usr/bin/mktemp -d); trap '/usr/bin/rm -rf \"$t\"' EXIT\nf=\"bumblebee_${v}_linux_${a}.tar.gz\"\n/usr/bin/curl -q -fsSL --proto =https --proto-redir =https --max-time 180 --max-filesize 67108864 -- \"https://github.com/perplexityai/bumblebee/releases/download/v${v}/$f\" | /usr/bin/head -c 67108865 > \"$t/$f\" || { echo 'Bumblebee could not be downloaded.'; exit 1; }\nif [ \"$(/usr/bin/stat -c %s \"$t/$f\")\" -gt 67108864 ]; then echo 'The Bumblebee download was too large, so it was not installed.'; exit 1; fi\nhave=$(/usr/bin/sha256sum \"$t/$f\" | /usr/bin/cut -d' ' -f1)\nif [ \"$have\" != \"$want\" ]; then echo \"Bumblebee $v did not match the checksum Vigil has for it, so it was not installed.\"; exit 1; fi\n/usr/bin/tar --no-same-owner --no-same-permissions -xzf \"$t/$f\" -C \"$t\" bumblebee\nif [ ! -f \"$t/bumblebee\" ] || [ -L \"$t/bumblebee\" ]; then echo 'Bumblebee was not a plain program file, so it was not installed.'; exit 1; fi\nif [ -f /usr/local/bin/bumblebee ] && [ ! -L /usr/local/bin/bumblebee ] && /usr/bin/cmp -s \"$t/bumblebee\" /usr/local/bin/bumblebee; then echo \"Bumblebee $v is already installed.\"; exit 0; fi\n/usr/bin/install -D -o root -g root -m 0755 \"$t/bumblebee\" /usr/local/bin/bumblebee\necho \"Bumblebee $v is installed.\"\n"

// The helper's other root steps, so the run cards can show them exactly as the
// helper runs them. Must equal SIGNATURES_SCRIPT and ROOT_STEP in bin/vigil, and
// rootUpdatesScript must build what root_updates_argv does (a test checks).
var SIGNATURES_SCRIPT = "if /usr/bin/systemctl is-active --quiet clamav-freshclam.service; then start=$(/usr/bin/date +%s); /usr/bin/systemctl kill --signal=SIGUSR1 --kill-whom=main clamav-freshclam.service || exit 4; for i in $(/usr/bin/seq 120); do if /usr/bin/journalctl -u clamav-freshclam.service --since \"@$start\" -o cat --no-pager 2>/dev/null | /usr/bin/grep -qE 'daily\\.c[lv]d (database is up-to-date|updated)'; then exit 0; fi; [ \"$(/usr/bin/stat -c %Y /var/lib/clamav/freshclam.dat 2>/dev/null || echo 0)\" -gt \"$start\" ] && exit 0; /usr/bin/sleep 1; done; exit 3; else /usr/bin/freshclam >/dev/null 2>&1; rc=$?; [ \"$rc\" -le 1 ] || exit 5; fi"
var NO_PASSWORD_STEP = "/usr/bin/awk -F: '$2 == \"\" { print $1 }' /etc/shadow"

function rootUpdatesScript(signatures, bumblebee) {
  var parts = []
  if (signatures) parts.push("( " + SIGNATURES_SCRIPT + " ) >/dev/null 2>&1; echo \"VIGIL-SIG $?\"")
  if (bumblebee) parts.push("( set -e\n" + BUMBLEBEE_INSTALL + ") >/dev/null 2>&1; echo \"VIGIL-BEE $?\"")
  return parts.join("\n")
}

// The user-level scripts that keep notes in ~/.local/state/omarchy-vigil walk
// there one folder at a time, as the helper does: a link, or anything that is
// not a folder of yours, is refused, never followed or repaired. With create,
// a missing folder is made, mode 0700. The last folder is left in $s.
function stateDirSh(extra, create) {
  return "s=\"$HOME\"\n"
    + "for p in .local state omarchy-vigil" + (extra ? " " + extra : "") + "; do\n"
    + "  s=\"$s/$p\"\n"
    + (create ? "  [ -e \"$s\" ] || [ -L \"$s\" ] || /usr/bin/mkdir -m 0700 -- \"$s\"\n" : "")
    + "  if [ -L \"$s\" ] || { [ -e \"$s\" ] && { [ ! -d \"$s\" ] || [ ! -O \"$s\" ]; }; }; then\n"
    + "    echo \"Refused: $s is a link or not a folder of yours, so nothing was changed.\"; exit 1\n"
    + "  fi\n"
    + "done\n"
}

// The scheduled-scan hand-over: one marker per change, so Undo restores
// exactly those. Must match HANDOVER_DIR and CLAMUI_SETTINGS in bin/vigil.
// A marker is a fresh file renamed into place, so a link planted at its name
// is replaced, never written through; Undo counts only regular files.
var MARK_SH = "mark() { t=$(/usr/bin/mktemp -p \"$s\" \".$1.XXXXXX\") && /usr/bin/mv -f -T -- \"$t\" \"$s/$1\"; }\n"
var MARKED_SH = "marked() { [ -f \"$s/$1\" ] && [ ! -L \"$s/$1\" ]; }\n"
var CLAMUI_SETTINGS_SH = "  case $k in native) f=\"$HOME/.config/clamui/settings.json\" ;;\n"
  + "    *) f=\"$HOME/.var/app/io.github.linx_systems.ClamUI/config/clamui/settings.json\" ;; esac\n"
// Changes one setting in ClamUI's settings.json, keeping everything else: jq
// writes a fresh file beside it, which takes the original's mode and is renamed
// over it. Callers check first that the file is a regular file, not a link.
var CLAMUI_EDIT_SH = "edit() {\n"
  + "  t=$(/usr/bin/mktemp \"$1.vigil-XXXXXX\") || return 1\n"
  + "  if /usr/bin/jq \"$2\" \"$1\" > \"$t\" && /usr/bin/chmod --reference=\"$1\" \"$t\" && /usr/bin/mv -f -T -- \"$t\" \"$1\"; then return 0; fi\n"
  + "  /usr/bin/rm -f -- \"$t\"; return 1\n"
  + "}\n"

var TERMINAL_ACTIONS = {
  "firewall-on": {
    title: "Turn the firewall on",
    what: ["Blocks other computers from connecting to yours unless you allowed it.",
           "Apps on this computer still reach the internet as usual. The firewall stays on after restarts.",
           "Technical: ufw --force enable, then systemctl enable --now ufw.service"],
    run: "sudo /usr/bin/ufw --force enable && sudo /usr/bin/systemctl enable --now ufw.service && echo 'The firewall is on.'"
  },
  "firewall-deny-in": {
    title: "Block incoming connections by default",
    what: ["Other computers can no longer connect to this one, except where you added a rule yourself.",
           "Apps on this computer still reach the internet as usual.",
           "Technical: sudo ufw default deny incoming, then sudo ufw reload"],
    run: "sudo /usr/bin/ufw default deny incoming && sudo /usr/bin/ufw reload"
  },
  "install-ufw": {
    title: "Install and turn on the firewall",
    what: ["Installs the ufw firewall, blocks incoming connections and turns it on, now and after restarts.",
           "Apps on this computer still reach the internet as usual.",
           "Technical: pacman -S ufw, ufw default deny incoming, ufw enable"],
    run: "/usr/bin/pacman -S --needed --noconfirm ufw && /usr/bin/ufw default deny incoming && /usr/bin/ufw --force enable "
      + "&& /usr/bin/systemctl enable --now ufw.service && echo 'The firewall is on.'"
  },
  "sysctl-harden": {
    title: "Turn on kernel and network protections",
    what: ["Switches on protections built into Linux that make it harder for a harmful program to spy on",
           "other programs or take over the system, and for other machines to redirect your traffic.",
           "Nothing you use should change. Undo appears on this finding afterwards.",
           "Technical: writes /etc/sysctl.d/90-omarchy-vigil.conf and loads it with sysctl --system"],
    run: dropIn("/etc/sysctl.d/90-omarchy-vigil.conf", SYSCTL_LINES) + " && sudo /usr/bin/sysctl --system >/dev/null && echo 'Settings applied.'"
  },
  "llmnr-off": {
    title: "Turn off LLMNR name lookups",
    what: ["Stops other machines on the local network from answering when this computer looks up a name,",
           "a trick used on shared Wi-Fi to capture passwords. Normal browsing is not affected.",
           "Undo appears on this finding afterwards.",
           "Technical: writes /etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf, restarts systemd-resolved"],
    run: "sudo /usr/bin/install -d -m 0755 /etc/systemd/resolved.conf.d && "
         + dropIn("/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf", [VIGIL_MARK, "[Resolve]", "LLMNR=no"])
         + " && sudo /usr/bin/systemctl restart systemd-resolved.service"
  },
  "dns-fallback-off": {
    title: "Turn off the hidden DNS fallback",
    what: ["When your own DNS servers stop answering, lookups no longer go quietly to Google, Cloudflare or Quad9.",
           "If your DNS fails, websites stop loading instead, which you notice. Undo appears on this finding afterwards.",
           "Technical: writes /etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf with an empty FallbackDNS="],
    run: "sudo /usr/bin/install -d -m 0755 /etc/systemd/resolved.conf.d && "
         + dropIn("/etc/systemd/resolved.conf.d/90-omarchy-vigil-fallback.conf", [VIGIL_MARK, "[Resolve]", "FallbackDNS="])
         + " && sudo /usr/bin/systemctl restart systemd-resolved.service"
  },
  "sshd-harden": {
    title: "Let SSH accept keys only",
    what: ["Other computers can log in only with an SSH key, never by guessing a password, and never as root.",
           "Stops without changing anything if you have no authorized key, so you cannot lock yourself out.",
           "Technical: writes /etc/ssh/sshd_config.d/00-omarchy-vigil.conf, checks it with sshd -t, reloads sshd"],
    run: "test -s \"$HOME/.ssh/authorized_keys\" || { echo 'No keys in ~/.ssh/authorized_keys. Add one first.'; exit 1; }; "
         + dropIn("/etc/ssh/sshd_config.d/00-omarchy-vigil.conf",
                  [VIGIL_MARK, "PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no"])
         + " && if sudo /usr/bin/sshd -t; then sudo /usr/bin/systemctl reload sshd.service; "
         + "else sudo /usr/bin/rm -f /etc/ssh/sshd_config.d/00-omarchy-vigil.conf; echo 'sshd rejected the change, so it was removed.'; exit 1; fi"
  },
  "connectivity-off": {
    title: "Turn off the connectivity check",
    what: ["Stops this computer contacting a server every few minutes to see whether it is online.",
           "Wi-Fi login pages in hotels and airports may no longer open by themselves. Undo appears on this finding.",
           "Technical: writes /etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf, reloads NetworkManager"],
    run: dropIn("/etc/NetworkManager/conf.d/90-omarchy-vigil-connectivity.conf", [VIGIL_MARK, "[connectivity]", "enabled=false"])
         + " && sudo /usr/bin/systemctl reload NetworkManager.service"
  },
  "mac-randomize": {
    title: "Use a different hardware address on each network",
    what: ["Each Wi-Fi network sees its own address for this computer, so shops and airports cannot recognise",
           "you from place to place. Applies the next time you connect. Undo appears on this finding afterwards.",
           "Technical: writes /etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf, reloads NetworkManager"],
    run: "if /usr/bin/grep -rqs '^wifi.backend=iwd' /etc/NetworkManager; then echo 'NetworkManager uses iwd here. Add AddressRandomization=network under [General] in /etc/iwd/main.conf instead.'; exit 1; fi; "
         + dropIn("/etc/NetworkManager/conf.d/90-omarchy-vigil-mac.conf",
                  [VIGIL_MARK, "[device]", "wifi.scan-rand-mac-address=yes", "[connection]",
                   "wifi.cloned-mac-address=stable", "ethernet.cloned-mac-address=stable"])
         + " && sudo /usr/bin/systemctl reload NetworkManager.service"
  },
  "avahi-quiet": {
    title: "Stop announcing this computer on the network",
    what: ["Other devices on your network no longer see this computer and its services. Printers still work.",
           "Changes nothing unless the setting is exactly where expected, keeps a copy of the original, and",
           "puts it back if Avahi does not restart. Undo appears on this finding afterwards.",
           "Technical: sets disable-publishing=yes in /etc/avahi/avahi-daemon.conf, restarts avahi-daemon"],
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
    what: ["Programs need your password again before they can change the system.",
           "Technical: runs the Omarchy command omarchy-sudo-passwordless --disable"],
    tool: "omarchy-sudo-passwordless", args: " --disable"
  },
  "docker-group-off": {
    title: "Leave the docker group",
    what: ["Programs you run can no longer use Docker to take full control of the computer without a password.",
           "Docker commands then need sudo.",
           "Technical: runs the Omarchy command omarchy-remove-security-sudoless-docker"],
    tool: "omarchy-remove-security-sudoless-docker", args: ""
  },
  "fido2": {
    title: "Use a security key for sudo",
    what: ["Lets a security key such as a YubiKey confirm system changes. Have the key plugged in;",
           "Omarchy walks you through it.",
           "Technical: runs omarchy-setup-security-fido2"],
    tool: "omarchy-setup-security-fido2", args: ""
  },
  "undo-fido2": {
    title: "Stop using a security key",
    what: ["Your security key no longer confirms system changes. Your password works as before.",
           "Omarchy also removes the key settings and the packages it installed for them.",
           "Technical: runs omarchy-remove-security-fido2"],
    tool: "omarchy-remove-security-fido2", args: ""
  },
  "fingerprint": {
    title: "Use your fingerprint",
    what: ["Lets your fingerprint confirm system changes and unlock the screen. Your password keeps working too.",
           "Omarchy installs the reader driver, then asks you to touch the sensor several times to save",
           "your fingerprint and checks that it works. Have the laptop open.",
           "Technical: runs omarchy-setup-security-fingerprint (fprintd, for sudo, polkit and the lock screen)"],
    tool: "omarchy-setup-security-fingerprint", args: ""
  },
  "undo-fingerprint": {
    title: "Stop using your fingerprint",
    what: ["Your fingerprint no longer confirms system changes or unlocks the screen. Your password works as before.",
           "Omarchy also deletes your saved fingerprints from this computer and removes the reader driver.",
           "Technical: runs omarchy-remove-security-fingerprint"],
    tool: "omarchy-remove-security-fingerprint", args: ""
  },
  // Finds the networks itself (open or WEP, joining by themselves) and records
  // each one it changed, so Undo puts back exactly those. Must match WIFI_MARK
  // and open_autojoin_networks in bin/vigil.
  "wifi-autojoin-off": {
    title: "Stop joining open Wi-Fi by itself",
    what: ["Saved Wi-Fi networks without a password stop joining by themselves. They stay saved,",
           "and you can still join one by hand when you mean to. NetworkManager may ask for your password.",
           "Technical: nmcli connection modify <network> connection.autoconnect no, for open and WEP networks only"],
    // The list of changed networks is never written through a link: it is
    // rebuilt in a fresh file (earlier entries kept) and renamed into place on
    // the way out, also when a step fails, so Undo still knows every change.
    run: stateDirSh("", true)
      + "m=\"$s/wifi-autojoin-off\"\n"
      + "if [ -L \"$m\" ] || { [ -e \"$m\" ] && [ ! -f \"$m\" ]; }; then "
      + "echo 'Refused: the list of networks Vigil changed is a link or not a plain file, so nothing was changed.'; exit 1; fi\n"
      + "w=$(/usr/bin/mktemp -p \"$s\" .wifi-autojoin-off.XXXXXX)\n"
      + "trap 'if [ -s \"$w\" ]; then /usr/bin/mv -f -T -- \"$w\" \"$m\"; else /usr/bin/rm -f -- \"$w\"; fi' EXIT\n"
      + "if [ -f \"$m\" ]; then /usr/bin/cat < \"$m\" > \"$w\"; fi\n"
      + "n=0\n"
      + "while IFS= read -r line; do\n"
      + "  u=${line%%:*}; rest=${line#*:}; t=${rest%%:*}; a=${rest#*:}\n"
      + "  [[ $u =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || continue\n"
      + "  [ \"$t\" = 802-11-wireless ] && [ \"$a\" = yes ] || continue\n"
      + "  k=$(/usr/bin/nmcli -g 802-11-wireless-security.key-mgmt connection show \"$u\" 2>/dev/null) || continue\n"
      + "  if [ -z \"$k\" ] || [ \"$k\" = none ]; then\n"
      + "    /usr/bin/nmcli connection modify \"$u\" connection.autoconnect no\n"
      + "    echo \"$u\" >> \"$w\"; n=$((n+1))\n"
      + "  fi\n"
      + "done < <(/usr/bin/nmcli -t -f UUID,TYPE,AUTOCONNECT connection show)\n"
      + "echo \"Stopped auto-joining $n open network(s). They stay saved.\""
  },
  "undo-wifi-autojoin": {
    title: "Let those Wi-Fi networks join by themselves again",
    what: ["The open networks Vigil stopped from joining by themselves join by themselves again.",
           "Technical: nmcli connection modify <network> connection.autoconnect yes, for the networks Vigil recorded"],
    run: stateDirSh("", false)
      + "m=\"$s/wifi-autojoin-off\"\n"
      + "if [ ! -f \"$m\" ] || [ -L \"$m\" ]; then echo 'Nothing to undo.'; exit 0; fi\n"
      + "while IFS= read -r u; do\n"
      + "  [[ $u =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || continue\n"
      + "  /usr/bin/nmcli connection modify \"$u\" connection.autoconnect yes || true\n"
      + "done < \"$m\"\n"
      + "/usr/bin/rm -f -- \"$m\"; echo 'Those networks join by themselves again.'"
  },
  "update-flatpaks": {
    title: "Update your Flatpak apps",
    what: ["Installs the waiting updates for your Flatpak apps, ClamUI among them, from Flathub.",
           "Apps installed for every account on this computer may ask for your password.",
           "Technical: flatpak update --noninteractive"],
    run: "/usr/bin/flatpak update --noninteractive && echo 'Your Flatpak apps are up to date.'"
  },
  "update-bumblebee": {
    title: "Update Bumblebee",
    what: ["Installs Bumblebee " + BUMBLEBEE_VERSION + " from Perplexity, the version this Vigil was reviewed with.",
           "It is installed only if it matches the checksum written into Vigil.",
           "List update under Run now on the Overview does this too, behind the same password prompt.",
           "Technical: release archive over HTTPS, size-capped, SHA-256 checked, installed as root to /usr/local/bin/bumblebee"],
    run: BUMBLEBEE_INSTALL
  },
  "update-firmware": {
    title: "Update firmware",
    what: ["Installs the firmware updates fwupd found for this computer, from LVFS where hardware makers publish them.",
           "Keep the laptop plugged in. Some updates finish during a restart; Omarchy tells you when.",
           "Technical: runs omarchy-update-firmware (fwupdmgr refresh, then fwupdmgr update)"],
    tool: "omarchy-update-firmware", args: ""
  },
  "update": {
    title: "Update the system",
    what: ["Installs every waiting update, including security fixes. Restart afterwards if Vigil asks you to.",
           "Technical: runs omarchy-update"],
    tool: "omarchy-update", args: ""
  },
  "allow-idle": {
    title: "Turn Stay Awake off",
    what: ["The screen locks by itself again when you are away.",
           "Technical: runs omarchy-toggle-idle allow-idle"],
    tool: "omarchy-toggle-idle", args: " allow-idle"
  },
  "install-clamav": {
    title: "Install ClamAV",
    what: ["Installs the ClamAV virus scanner and downloads its list of known viruses.",
           "Technical: pacman -S clamav, freshclam, systemctl enable clamav-freshclam"],
    run: "/usr/bin/pacman -S --needed --noconfirm clamav && /usr/bin/freshclam && /usr/bin/systemctl enable --now clamav-freshclam.service "
      + "&& echo 'ClamAV is installed and keeps its signatures up to date.'"
  },
  "freshclam-service": {
    title: "Keep virus signatures up to date",
    what: ["Turns on the ClamAV service that downloads new virus signatures several times a day,",
           "and gets them once now.",
           "Technical: sudo systemctl enable --now clamav-freshclam.service"],
    run: "sudo /usr/bin/systemctl enable --now clamav-freshclam.service"
  },
  "install-osv-scanner": {
    title: "Install osv-scanner",
    what: ["Installs the tool Vigil uses to check your npm and Bun packages against known malware.",
           "It sends only package names and versions to OSV.dev, never your files.",
           "Technical: pacman -S osv-scanner"],
    run: "/usr/bin/pacman -S --needed --noconfirm osv-scanner && echo 'osv-scanner is installed.'"
  },
  "freshclam": {
    title: "Update virus signatures now",
    what: ["Downloads the newest virus signatures from ClamAV.",
           "Technical: sudo freshclam"],
    run: "sudo /usr/bin/freshclam"
  },
  "install-clamui": {
    title: "Install ClamUI",
    what: ["Installs ClamUI, an app for virus scans and quarantine, with ClamAV and its virus signatures,",
           "and turns on the service that keeps the signatures up to date.",
           "Both come from the Arch repositories, so the Omarchy update keeps them current.",
           "Technical: pacman -S clamav clamui, freshclam, enable clamav-freshclam"],
    run: "/usr/bin/pacman -S --needed --noconfirm clamav clamui && /usr/bin/freshclam "
      + "&& /usr/bin/systemctl enable --now clamav-freshclam.service && echo 'ClamUI is installed.'"
  },


  "old-services-off": {
    title: "Switch off old network services",
    what: ["Switches off any telnet, rsh, rlogin, FTP, TFTP, NIS or xinetd service that is on. Nothing is uninstalled.",
           "To turn one back on later: sudo systemctl enable --now <name>",
           "Technical: sudo systemctl disable --now for each one that is switched on"],
    run: "for u in " + OLD_SERVICES.join(" ") + "; do "
      + "if /usr/bin/systemctl is-enabled --quiet \"$u\" 2>/dev/null || /usr/bin/systemctl is-active --quiet \"$u\"; "
      + "then echo \"Switching off $u\"; sudo /usr/bin/systemctl disable --now \"$u\"; fi; done"
  },
  "install-helpers": {
    title: "Install the missing helpers",
    what: ["Installs the tools Vigil works with that are missing: ClamAV (virus scanner) with its service",
           "that keeps virus signatures up to date, arch-audit (known security holes), osv-scanner",
           "(malicious packages), fwupd (firmware updates), ClamUI (virus scans and quarantine) and Bumblebee by Perplexity",
           "(known-compromised packages). Ones you already have are left alone.",
           "Bumblebee " + BUMBLEBEE_VERSION + " comes from Perplexity on GitHub, installed only if it matches the checksum",
           "written into Vigil. The rest come from the Arch repositories,",
           "so the Omarchy update keeps them current.",
           "Technical: pacman -S --needed clamav clamui arch-audit osv-scanner fwupd, enable clamav-freshclam, bumblebee to /usr/local/bin"],
    // What the progress bar says at each "VIGIL-STEP n" line the script prints.
    stages: ["Installing ClamAV, ClamUI, arch-audit, osv-scanner and fwupd from the Arch repositories",
             "Turning on automatic virus signature updates",
             "Downloading Bumblebee from Perplexity and checking it"],
    // ClamUI from the Arch repositories, unless you already have it as a Flatpak.
    run: "echo VIGIL-STEP 1\n"
      + "c=clamui; [ -d \"$HOME/.local/share/flatpak/app/io.github.linx_systems.ClamUI\" ] && c=\n"
      + "/usr/bin/pacman -S --needed --noconfirm clamav $c arch-audit osv-scanner fwupd\necho 'Packages installed.'\n"
      + "echo VIGIL-STEP 2\n"
      + "/usr/bin/systemctl enable --now clamav-freshclam.service\n"
      + "echo VIGIL-STEP 3\n"
      + "if [ ! -x /usr/local/bin/bumblebee ]; then\n"
      + "  ( set -e\n" + BUMBLEBEE_INSTALL + ") || echo 'Bumblebee could not be installed now; press Install again later.'\n"
      + "fi\n"
  },
  "restart": {
    title: "Restart the computer",
    what: ["Restarts now so the updated kernel, with its security fixes, takes over.",
           "Save your work and close your apps first.",
           "Technical: systemctl reboot"],
    run: "/usr/bin/systemctl reboot"
  },
  "install-arch-audit": {
    title: "Install arch-audit",
    what: ["Installs the tool that checks your packages against the Arch security team list of known holes.",
           "Technical: pacman -S arch-audit"],
    run: "/usr/bin/pacman -S --needed --noconfirm arch-audit && echo 'arch-audit is installed.'"
  },
  "run-arch-audit": {
    title: "List packages with known security holes",
    what: ["Shows installed packages with a known security hole that an update already fixes. Changes nothing.",
           "Technical: arch-audit --upgradable (contacts security.archlinux.org)"],
    run: "/usr/bin/arch-audit --upgradable && echo 'Done. Nothing listed means nothing to fix.'"
  },
  "clean-pacman-cache": {
    title: "Free space in the package cache",
    what: ["Deletes old downloaded package files. The two newest versions of each installed package stay,",
           "so a bad update can still be rolled back, as Omarchy does.",
           "Technical: sudo paccache -rk2, then sudo paccache -ruk0"],
    run: PACCACHE_RUN
  },

  "clean-orphans": {
    title: "Review leftover packages",
    what: ["Lists packages that were installed only for something you have since removed,",
           "and asks before removing any.",
           "Technical: runs the Omarchy command omarchy-update-orphan-pkgs"],
    tool: "omarchy-update-orphan-pkgs", args: ""
  },
  "show-listeners": {
    title: "Show which programs accept network connections",
    what: ["Lists each open port and the program behind it. Changes nothing.",
           "Technical: sudo ss -tulpn"],
    run: "sudo /usr/bin/ss -tulpn"
  },
  "show-ld-preload": {
    title: "Show the system-wide preload file",
    what: ["Prints /etc/ld.so.preload and who owns it, so you or a helper can see what it loads. Changes nothing.",
           "Technical: ls -l and cat /etc/ld.so.preload"],
    run: "/usr/bin/ls -l /etc/ld.so.preload; echo; /usr/bin/cat /etc/ld.so.preload"
  },
  "hand-over-schedules": {
    title: "Let Vigil run the scheduled scans",
    what: ["Turns off the other schedules that repeat what Vigil already runs:",
           "the scheduled scan in ClamUI (its own setting is switched off too, so ClamUI shows it as off),",
           "and the Bumblebee plugin, which Vigil replaces. Your scans still run, once, on the Vigil schedule.",
           "ClamUI is left alone if any of its schedules also covers folders outside your home folder.",
           "Undo turns back on exactly what this turned off. No password needed.",
           "Technical: systemctl --user disable --now clamui-scheduled-scan.timer, scheduled_scans_enabled false in ClamUI settings.json, omarchy-plugin-disable io.github.duketopceo.bumblebee"],
    uses: ["omarchy-plugin-disable"],
    // The script checks again what the helper checked, so it never turns off a
    // ClamUI scan that covers more than your home folder, or a Bumblebee plugin
    // when Vigil has no Bumblebee of its own. Both ClamUI installs (Arch and
    // Flatpak) share one timer, so a single schedule that reaches outside your
    // home folder, or a settings file that cannot be checked, keeps all of
    // ClamUI as it is.
    run: stateDirSh("handed-over", true) + MARK_SH + CLAMUI_EDIT_SH
      + "home_only='.scheduled_scans_enabled == true and (.schedule_targets | type == \"array\" and length > 0 and "
      + "all(.[]; type == \"string\" and (. == $h or startswith($h + \"/\") or . == \"~\" or startswith(\"~/\")) "
      + "and (contains(\"/../\") | not) and (endswith(\"/..\") | not)))'\n"
      + "ok=''; other=''\n"
      + "for k in native flatpak; do\n"
      + CLAMUI_SETTINGS_SH
      + "  if [ -L \"$f\" ] || { [ -e \"$f\" ] && [ ! -f \"$f\" ]; }; then other=1\n"
      + "  elif [ -f \"$f\" ]; then\n"
      + "    if /usr/bin/jq -e --arg h \"$HOME\" \"$home_only\" \"$f\" >/dev/null 2>&1; then ok=\"$ok $k\"\n"
      + "    elif ! /usr/bin/jq -e '.scheduled_scans_enabled != true' \"$f\" >/dev/null 2>&1; then other=1; fi\n"
      + "  fi\n"
      + "done\n"
      + "if [ -n \"$other\" ]; then ok=''; "
      + "echo 'ClamUI: left as it is, since a schedule also covers folders outside your home folder or could not be checked.'; fi\n"
      + "w=\"$HOME/.config/systemd/user/timers.target.wants/clamui-scheduled-scan.timer\"\n"
      + "if [ -n \"$ok\" ] && { [ -e \"$w\" ] || [ -L \"$w\" ]; }; then\n"
      + "  /usr/bin/systemctl --user disable --now clamui-scheduled-scan.timer\n"
      + "  mark clamui-timer; echo 'ClamUI scheduled scan: off.'\n"
      + "fi\n"
      + "for k in $ok; do\n"
      + CLAMUI_SETTINGS_SH
      + "  edit \"$f\" '.scheduled_scans_enabled = false'\n"
      + "  mark \"clamui-setting-$k\"; echo 'ClamUI setting Scheduled scans: off.'\n"
      + "done\n"
      + "p=io.github.duketopceo.bumblebee; c=\"$HOME/.config/omarchy/shell.json\"\n"
      + "if [ -n \"$omarchy_plugin_disable\" ] && [ -x /usr/local/bin/bumblebee ] && [ ! -L /usr/local/bin/bumblebee ] "
      + "&& [ -d \"$HOME/.config/omarchy/plugins/$p\" ] && [ -f \"$c\" ] && /usr/bin/jq -e --arg id \"$p\" "
      + "'((.disabledPlugins // []) | index($id) | not) and (tostring | contains(\"\\\"\" + $id + \"\\\"\"))' \"$c\" >/dev/null 2>&1; then\n"
      + "  \"$omarchy_plugin_disable\" \"$p\"\n"
      + "  mark bumblebee-plugin; echo 'Bumblebee plugin: off. Vigil runs Bumblebee in its daily check.'\n"
      + "fi\n"
      + "echo 'Done. Vigil runs these on its own schedule now.'"
  },
  "undo-schedules": {
    title: "Turn the other scheduled scans back on",
    what: ["Turns back on what Let Vigil run them turned off, and nothing else:",
           "the scheduled scan in ClamUI and its setting, and the Bumblebee plugin.",
           "Technical: systemctl --user enable --now clamui-scheduled-scan.timer, scheduled_scans_enabled true, omarchy-plugin-enable io.github.duketopceo.bumblebee"],
    uses: ["omarchy-plugin-enable"],
    run: stateDirSh("handed-over", false) + MARKED_SH + CLAMUI_EDIT_SH
      + "if marked clamui-timer; then\n"
      + "  if [ -f \"$HOME/.config/systemd/user/clamui-scheduled-scan.timer\" ]; then\n"
      + "    /usr/bin/systemctl --user enable --now clamui-scheduled-scan.timer; echo 'ClamUI scheduled scan: on.'\n"
      + "  fi\n"
      + "  /usr/bin/rm -f -- \"$s/clamui-timer\"\n"
      + "fi\n"
      + "for k in native flatpak; do\n"
      + "  marked \"clamui-setting-$k\" || continue\n"
      + CLAMUI_SETTINGS_SH
      + "  if [ -f \"$f\" ] && [ ! -L \"$f\" ] && /usr/bin/jq -e 'type == \"object\"' \"$f\" >/dev/null 2>&1; then\n"
      + "    edit \"$f\" '.scheduled_scans_enabled = true'; echo 'ClamUI setting Scheduled scans: on.'\n"
      + "  fi\n"
      + "  /usr/bin/rm -f -- \"$s/clamui-setting-$k\"\n"
      + "done\n"
      + "if marked bumblebee-plugin; then\n"
      + "  if [ -n \"$omarchy_plugin_enable\" ]; then\n"
      + "    \"$omarchy_plugin_enable\" io.github.duketopceo.bumblebee; echo 'Bumblebee plugin: on.'\n"
      + "    /usr/bin/rm -f -- \"$s/bumblebee-plugin\"\n"
      + "  else echo 'The Omarchy plugin command was not found, so the Bumblebee plugin stays off for now.'; fi\n"
      + "fi\n"
      + "/usr/bin/rmdir -- \"$s\" 2>/dev/null || true"
  },
  "show-plugins": {
    title: "List installed Omarchy plugins",
    what: ["Shows every plugin you have installed. Changes nothing.",
           "Remove one you do not use with: omarchy plugin remove <id>",
           "Technical: omarchy plugin list"],
    tool: "omarchy-plugin-list", args: ""
  },

  "ssh-passphrase": {
    title: "Add a passphrase to your SSH keys",
    what: ["Protects each SSH key that has no passphrase, so a stolen copy is useless; it asks you for the new one.",
           "Servers that trust the key keep working.",
           "Technical: ssh-keygen -p for each private key in ~/.ssh without a passphrase"],
    // Key file names never go into a program's arguments, which every account
    // can read in /proc/<pid>/cmdline (ssh-keygen -p waits there for the
    // passphrase): each key is opened by the shell on descriptor 3, grep reads
    // it from stdin, and ssh-keygen gets /proc/self/fd/3, which names no file.
    // The name shown in the terminal goes through printf %q, so control
    // characters in it are printed as $'\E...' escapes, never sent to the terminal.
    run: "found=0; for k in \"$HOME\"/.ssh/*; do "
      + "[ -f \"$k\" ] && [ ! -L \"$k\" ] || continue; "
      + "/usr/bin/grep -q 'PRIVATE KEY' < \"$k\" 2>/dev/null || continue; "
      + "if /usr/bin/ssh-keygen -y -P '' -f /proc/self/fd/3 3< \"$k\" >/dev/null 2>&1; then found=1; "
      + "printf 'Passphrase for ~/.ssh/%q\\n' \"${k##*/}\"; /usr/bin/ssh-keygen -p -f /proc/self/fd/3 3< \"$k\"; fi; done; "
      + "[ \"$found\" = 1 ] || echo 'Every key already has a passphrase.'"
  },
  "screen-lock-default": {
    title: "Lock the screen after 5 minutes away",
    what: ["Locks the screen after 5 minutes without use, the Omarchy default.",
           "Technical: sets idle.lock to 300 in ~/.config/omarchy/shell.json with the helper Omarchy ships"],
    source: "omarchy-shell-config",
    run: "commit \"$NORMALIZE | .idle = ((.idle | if type == \\\"object\\\" then . else {} end) + {lock: 300})\" "
      + "&& echo 'The screen now locks after 5 minutes idle.'"
  },
  "firewire-off": {
    title: "Turn off FireWire",
    what: ["Stops the FireWire port from working, so a plugged-in device cannot read memory directly.",
           "Takes full effect after a restart. Undo appears on this finding afterwards.",
           "Technical: writes /etc/modprobe.d/90-omarchy-vigil-firewire.conf"],
    run: "sudo /usr/bin/install -d -m 0755 /etc/modprobe.d && "
      + dropIn("/etc/modprobe.d/90-omarchy-vigil-firewire.conf", [VIGIL_MARK,
          "install firewire-core /bin/false", "install firewire-ohci /bin/false", "install ohci1394 /bin/false"])
  },
  "undo-protocols": undoDropIn("network protocols", "/etc/modprobe.d/90-omarchy-vigil-protocols.conf",
    "They can load again straight away.", "echo 'Removed. These protocols can load again.'"),
  "undo-firewire": undoDropIn("FireWire", "/etc/modprobe.d/90-omarchy-vigil-firewire.conf",
    "The drivers can load again after the next restart.", "echo 'Removed. FireWire works again after a restart.'"),
  "clean-system": {
    title: "Free space in the package cache and trim system logs",
    what: ["Deletes old downloaded package files, keeping the two newest versions of each for rollback,",
           "and system logs older than two weeks.",
           "Technical: sudo paccache -rk2, sudo paccache -ruk0, sudo journalctl --vacuum-time=2weeks"],
    run: PACCACHE_RUN + "; sudo /usr/bin/journalctl --vacuum-time=2weeks"
  },

  "clean-journal": {
    title: "Trim system logs",
    what: ["Deletes system logs older than two weeks.",
           "Technical: sudo journalctl --vacuum-time=2weeks"],
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
    what: ["Puts back the Avahi settings file as it was before Vigil first changed it, and restarts Avahi.",
           "Edits made to the file since then are lost.",
           "Technical: moves /etc/avahi/avahi-daemon.conf.vigil-backup back into place"],
    run: "b=/etc/avahi/avahi-daemon.conf.vigil-backup; "
         + "[ -f \"$b\" ] || { echo 'There is no backup to restore.'; exit 0; }; "
         + "sudo /usr/bin/mv -f -- \"$b\" /etc/avahi/avahi-daemon.conf && sudo /usr/bin/systemctl restart avahi-daemon.service"
  }
}

// App actions open another program you installed, with a fixed argv and no
// shell. The helper reports how the app is installed; anything else is "".
// "Learn more" pages, opened in the browser. Only these can be opened;
// nothing from the report ever becomes a URL.
var DOCS = {
  "arch-ssh-keys": "https://wiki.archlinux.org/title/SSH_keys",
  "arch-fwupd": "https://wiki.archlinux.org/title/Fwupd",
  "arch-flatpak": "https://wiki.archlinux.org/title/Flatpak",
  "arch-gnupg": "https://wiki.archlinux.org/title/GnuPG",
  "arch-dm-crypt": "https://wiki.archlinux.org/title/Dm-crypt",
  "arch-faillock": "https://wiki.archlinux.org/title/Security#Lock_out_user_after_three_failed_login_attempts",
  "arch-autostart": "https://wiki.archlinux.org/title/Autostarting",
  "arch-aur": "https://wiki.archlinux.org/title/Arch_User_Repository",
  "bumblebee": "https://github.com/perplexityai/bumblebee",
  "black-ops": "https://github.com/brightwalker25/omarchy-black-ops",
  "arch-users": "https://wiki.archlinux.org/title/Users_and_groups",
  "attack-history": "https://attack.mitre.org/techniques/T1070/003/",
  "arch-xdg": "https://wiki.archlinux.org/title/XDG_Base_Directory"
}

function docsUrl(id) {
  if (typeof id !== "string") return ""
  return Object.prototype.hasOwnProperty.call(DOCS, id) ? DOCS[id] : ""
}

function docsCommand(id, tools) {
  var url = docsUrl(id)
  var dir = toolDir(tools, "xdg-open")
  return url === "" || dir === "" ? [] : [dir + "/xdg-open", url]
}

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
  var body = actionBody(a, tools)
  if (body === "") return ""
  var intro = ["Vigil: " + a.title, ""].concat(a.what).concat(["",
    body.indexOf("sudo ") !== -1 ? "You will be asked for your password." : "No password needed."])
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
  if (fixObj.kind === "docs") return docsCommand(fixObj.action, tools).length > 0
  if (fixObj.kind === "helper") return isHelperAction(fixObj.action)
  if (fixObj.kind === "terminal") {
    if (runMode(fixObj.action) === "terminal")
      return launcherPath(tools) !== "" && terminalScript(fixObj.action, tools) !== ""
    return actionPlan(fixObj.action, tools, "/home/check").length > 0
  }
  return false
}

// ---------------------------------------------------------------------------
// Clean all (Care tab). Runs the cleanups the Care checks currently offer, in
// at most two steps: the no-root ones through the helper (`fix clean-user`),
// the root ones in one pkexec run (`clean-system`), so you are asked once.
// Orphaned packages are left out on purpose: removing packages can take away
// something you use, so that stays a separate, reviewed step.

var CLEAN_ALL = { "clean-thumbnails": "user", "empty-trash": "user", "clean-app-cache": "user",
                  "clean-pacman-cache": "system", "clean-journal": "system" }

function cleanAllPlan(report) {
  var plan = { user: false, system: false, items: [] }
  if (!report || !report.checks) return plan
  var systemOk = actionPlan("clean-system", report.tools, "/home/check").length > 0
  for (var i = 0; i < report.checks.length; i++) {
    var c = report.checks[i]
    if (c.category !== "care" || !c.fix || c.fix.kind === "none") continue
    if (!Object.prototype.hasOwnProperty.call(CLEAN_ALL, c.fix.action)) continue
    var side = CLEAN_ALL[c.fix.action]
    if (side === "system" && !systemOk) continue
    if (side === "user") plan.user = true
    else plan.system = true
    plan.items.push(c.title + ": " + c.summary.replace(/\.$/, ""))
  }
  return plan
}

function cleanAllConfirmation(report) {
  var plan = cleanAllPlan(report)
  if (plan.items.length === 0) return null
  var lines = plan.items.slice(0)
  if (plan.user) lines.push("Files are cleared right away. The trash cannot be restored; caches rebuild themselves.")
  if (plan.system) lines.push("For the package cache and logs, Omarchy asks for your password once.")
  lines.push("Orphaned packages and leftover app data are left out: they deserve a look, so review them one by one at the bottom of this tab.")
  return { title: "Clean all", lines: lines }
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
  if (f.kind === "docs" && docsUrl(f.action) === "") return { kind: "none", action: "", label: "" }
  return { kind: f.kind, action: f.action, label: plain(f.label, 60) }
}

function validCheck(c) {
  if (!c || typeof c !== "object") return null
  if (!isString(c.id, 40) || !/^[a-z0-9-]+$/.test(c.id)) return null
  if (!inList(c.category, CATEGORIES) || !inList(c.status, STATUSES)) return null
  if (!isString(c.title, MAX_STR) || !isString(c.summary, MAX_STR)) return null
  if (!isString(c.why, MAX_STR * 2) || !isString(c.detail, MAX_DETAIL)) return null
  if (c.howto !== undefined && !isString(c.howto, MAX_STR * 2)) return null
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
  if (dismissed && (!dismissible || c.status === "pass" || c.status === "na")) return null
  var dismissedAt = ""
  if (c.dismissedAt !== undefined && c.dismissedAt !== "") {
    if (!isString(c.dismissedAt, 10) || !/^\d{4}-\d{2}-\d{2}$/.test(c.dismissedAt)) return null
    dismissedAt = c.dismissedAt
  }
  // One line per item, each with its own buttons: a virus detection (False
  // positive) or a leftover of an app that is gone (Move to trash, Keep).
  var items = []
  if (c.items !== undefined) {
    if (!Array.isArray(c.items) || c.items.length > 500) return null
    for (var k = 0; k < c.items.length; k++) {
      var it = c.items[k]
      if (!it || typeof it !== "object" || typeof it.ignored !== "boolean" || !isString(it.text, 400)
          || typeof it.id !== "string" || (it.id !== "" && !/^[0-9a-f]{16}$/.test(it.id))) return null
      var leftover = it.kind === "leftover"
      if (it.kind !== undefined && !leftover) return null
      if (leftover && (it.id === "" || typeof it.kept !== "boolean" || it.ignored)) return null
      if (!leftover && it.kept !== undefined) return null
      items.push({ id: it.id, kind: leftover ? "leftover" : "detection", text: plain(it.text, 400),
                   ignored: it.ignored, kept: leftover ? it.kept : false })
    }
  }
  return {
    items: items,
    id: c.id, category: c.category, status: c.status, weight: c.weight,
    title: plain(c.title, 80), summary: plain(c.summary, MAX_STR), why: plain(c.why, MAX_STR * 2),
    detail: plain(c.detail, MAX_DETAIL), howto: plain(c.howto || "", MAX_STR * 2), fix: f, undo: undo,
    dismissible: dismissible, dismissed: dismissed, dismissedAt: dismissedAt
  }
}

var SOURCE_IDS = ["signatures", "virus-scan", "arch-audit", "osv", "aur", "password-check", "bumblebee", "firmware",
                  "pending-updates", "flatpak", "downloads-scan",
                  "bumblebee-list"]
var SOURCE_STATES = ["ok", "stale", "never", "failed"]
var DATE_RE = /^\d{4}-\d{2}-\d{2}$/

function parseSources(list) {
  if (list === undefined) return []
  if (!Array.isArray(list) || list.length > 40) return null
  var out = []
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    if (!e || typeof e !== "object") return null
    if (isString(e.id, 40) && !inList(e.id, SOURCE_IDS)) continue      // from a newer helper: skipped
    if (!inList(e.id, SOURCE_IDS) || !inList(e.state, SOURCE_STATES)) return null
    if (!isString(e.label, 40) || !isString(e.date, 10) || !isString(e.tried, 10)) return null
    if ((e.date !== "" && !DATE_RE.test(e.date)) || (e.tried !== "" && !DATE_RE.test(e.tried))) return null
    var time = e.time === undefined ? "" : e.time
    if (!isString(time, 5) || (time !== "" && !/^\d{2}:\d{2}$/.test(time))) return null
    var by = e.by === undefined ? "" : e.by
    if (!inList(by, ["", "ClamUI"])) return null
    out.push({ id: e.id, label: plain(e.label, 40), date: e.date, time: time, state: e.state, tried: e.tried, by: by })
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
  var scan = SCAN_SOURCES.indexOf(src.id) !== -1
  if (src.state === "never") return scan ? "not run yet" : "not updated yet"
  if (src.state === "failed")
    return (scan ? "last run failed" : "last update failed") + (src.date !== "" ? "; last good " + relativeDay(src.date, now) : "")
  var when = relativeDay(src.date, now) + (src.time ? " at " + src.time : "") + (src.by ? " (by " + src.by + ")" : "")
  return src.state === "stale" ? "out of date (" + when + ")" : (scan ? "ran " : "updated ") + when
}

function lastRunLine(run, now) {
  if (!run || run.at === "") return "No update yet. It runs within a day, or press List update under Run now."
  var time = run.at.substring(11, 16)
  return "Last update " + relativeDay(run.at, now) + " at " + time
    + (run.ok ? ". Every source refreshed." : ". Some sources did not refresh; Vigil tries again tomorrow.")
}

var SCAN_SOURCES = ["virus-scan", "downloads-scan", "bumblebee", "firmware", "password-check"]

// The Overview's LAST RUN list: every scan (with the quick check first),
// then every source update, each with when it last ran or updated.
function lastRunRows(report, now) {
  if (!report) return []
  var rows = [{ label: "Scans", value: "", heading: true, problem: false },
              { label: "Quick check (every row)", heading: false, problem: false,
                value: "ran " + relativeDay(report.generatedAt, now) + " at " + report.generatedAt.substring(11, 16) }]
  var add = function(scan) {
    for (var i = 0; i < report.sources.length; i++) {
      var src = report.sources[i]
      if ((SCAN_SOURCES.indexOf(src.id) !== -1) !== scan) continue
      rows.push({ label: src.label, value: sourceLine(src, now), heading: false,
                  problem: src.state === "failed" || src.state === "stale" })
    }
  }
  add(true)
  rows.push({ label: "Updates", value: "", heading: true, problem: false })
  add(false)
  if (rows[rows.length - 1].heading) rows.pop()
  return rows
}

function pad2(n) { return (n < 10 ? "0" : "") + n }

// A local Date from "YYYY-MM-DD HH:MM" (or "YYYY-MM-DDTHH:MM..."), or null.
function localDate(str) {
  var m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?/.exec(String(str))
  if (!m) return null
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4] || 0), Number(m[5] || 0))
}

// When something next runs, in words: "today at 14:30", "tomorrow at 09:52",
// "in 6 days". Something already due runs at Vigil's next background check
// (nextCheck); "" when there is nothing to run. Times are this computer's
// local time.
function countdown(when, now, nextCheck) {
  var due = when === "now" ? null : localDate(when)
  if (when !== "now" && !due) return ""
  if (!due || due <= now) due = nextCheck && nextCheck > now ? nextCheck : now
  var today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  var day = new Date(due.getFullYear(), due.getMonth(), due.getDate())
  var days = Math.round((day - today) / 86400000)
  var at = " at " + pad2(due.getHours()) + ":" + pad2(due.getMinutes())
  if (days <= 0) return "today" + at
  if (days === 1) return "tomorrow" + at
  return "in " + days + " days"
}

// The lines under the buttons: when each automatic run comes next.
// refreshMinutes is how often Vigil checks in the background.
function scheduleLines(report, autoUpdate, now, refreshMinutes) {
  if (!report) return []
  if (!autoUpdate) return ["Automatic updates and scans are off (Vigil settings)."]
  var checked = localDate(report.generatedAt)
  var nextCheck = checked ? new Date(checked.getTime() + (refreshMinutes || 30) * 60000) : null
  var out = []
  // What each one runs is in the Last run list, where every row names its
  // schedule ("daily check", "weekly check", "list update").
  var d = countdown(report.nextDaily, now, nextCheck)
  if (d !== "") out.push("Next daily check: " + d)
  var f = countdown(report.nextFullScan, now, nextCheck)
  if (f !== "") out.push("Next weekly check: " + f)
  var u = countdown(report.nextUpdate, now, nextCheck)
  if (u !== "") out.push("Next list update: " + u)
  if (report.lastRun && report.lastRun.at !== "" && !report.lastRun.ok)
    out.push("The last update could not reach every source; Vigil tries again tomorrow.")
  return out
}

// The two lines under each run button: when that check next runs by itself
// ("next" over "today 21:40"). Run all has no schedule of its own; it runs
// the other three at once.
function runCaptions(report, autoUpdate, now, refreshMinutes) {
  var out = { daily: "", weekly: "", update: "", all: "all three\nnow" }
  if (!report) return out
  if (!autoUpdate) {
    out.daily = out.weekly = out.update = "by hand\nonly"
    return out
  }
  var checked = localDate(report.generatedAt)
  var nextCheck = checked ? new Date(checked.getTime() + (refreshMinutes || 30) * 60000) : null
  var keys = { daily: report.nextDaily, weekly: report.nextFullScan, update: report.nextUpdate }
  for (var k in keys) {
    var when = countdown(keys[k], now, nextCheck)
    out[k] = when === "" ? "" : "next\n" + when.replace(" at ", " ")
  }
  return out
}

// What the Overview says under the run buttons besides the countdowns.
function scheduleNotes(report, autoUpdate) {
  if (!report) return []
  if (!autoUpdate) return ["Background checks are off (Vigil settings): they run only when you press a button."]
  if (report.lastRun && report.lastRun.at !== "" && !report.lastRun.ok)
    return ["The last update could not reach every source; Vigil tries again tomorrow."]
  return []
}

// The line beside the panel's title. The Overview shows the score in large
// type, so there it says when Vigil last checked instead.
function heroMeta(report, tab, checking, now) {
  if (!report) return checking ? "Checking\u2026" : "Not checked yet"
  if (tab === "overview") {
    var at = localDate(report.generatedAt)
    if (checking) return "Checking\u2026"
    if (at) return "Checked " + relativeDay(report.generatedAt, now) + " at " + pad2(at.getHours()) + ":" + pad2(at.getMinutes())
  }
  return levelText(report) + " \u00b7 " + report.score + "/100"
}

// The key hints at the bottom, for the tab you are on.
function keyHints(tab, version) {
  var keys = ["\u2190 \u2192 or 1\u20136 tabs"]
  if (tab === "overview") keys.push("R run all", "U list update")
  else keys.push("\u2191 \u2193 rows", "Enter details", "F fix", "D reviewed")
  if (tab === "care") keys.push("C clean all")
  return keys.join(" \u00b7 ") + (version ? " \u00b7 Vigil " + version : "")
}

// A progress line from a running update or scan, or null.
function parseProgress(line) {
  var d
  try { d = JSON.parse(line) } catch (e) { return null }
  var p = d && typeof d === "object" ? d.progress : null
  if (!p || typeof p !== "object") return null
  var n = function(v, max) { return typeof v === "number" && isFinite(v) && v >= 0 && v <= max }
  if (!n(p.step, 20) || !n(p.of, 20) || p.step < 1 || p.step > p.of || !isString(p.doing, 120)
      || !n(p.done, 1e8) || !n(p.total, 1e8)) return null
  var part = p.total > 0 ? Math.min(1, p.done / p.total) : 0
  // The helper gives each step its share of the bar (the virus scan most of it);
  // without that, every step counts the same.
  var share = function(v) { return typeof v === "number" && isFinite(v) && v >= 0 && v <= 1 }
  var fraction = share(p.at) && share(p.span) && p.at + p.span <= 1.0001
    ? p.at + p.span * part : (p.step - 1 + part) / p.of
  return { step: Math.round(p.step), of: Math.round(p.of), doing: plain(p.doing, 120),
           done: Math.round(p.done), total: Math.round(p.total),
           fraction: Math.min(1, fraction) }
}

// A scan or update started elsewhere (another monitor, or before the shell
// restarted): its progress, step 0 when it has not said yet, null when none
// runs, undefined when the value is not valid.
function parseRunningValue(r) {
  if (r === undefined || r === null) return null
  if (typeof r !== "object" || Array.isArray(r)) return undefined
  if (r.step === 0 && r.of === 0) return { step: 0, of: 0, doing: "", done: 0, total: 0, fraction: 0 }
  var p = parseProgress(JSON.stringify({ progress: r }))
  return p === null ? undefined : p
}

// The `vigil running` answer: { ok, running } or null.
function parseRunning(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > 2048) return null
  var d
  try { d = JSON.parse(text) } catch (e) { return null }
  if (!d || typeof d !== "object") return null
  var r = parseRunningValue(d.running)
  return r === undefined ? null : { running: r }
}

// What the progress line under the bar says.
function progressText(p) {
  if (!p) return ""
  if (p.step === 0) return "Working\u2026"
  var s = "Step " + p.step + " of " + p.of + ": " + p.doing
  if (p.total > 0) s += " (" + p.done.toLocaleString() + " of " + p.total.toLocaleString() + " files)"
  else if (p.done > 0) s += " (" + p.done.toLocaleString() + " files)"
  return s
}

// How far an action running in the panel is. Its scripts print lines
// "VIGIL-STEP n"; only the number is read from the output, and the text shown
// comes from the action's own `stages`.
function actionStage(output) {
  var re = /^VIGIL-STEP ([0-9])$/gm, m, n = -1
  while ((m = re.exec(String(output))) !== null) n = Math.max(n, Number(m[1]))
  return n
}

function actionProgress(id, stage, stepIndex, steps) {
  var a = terminalAction(id)
  var stages = a && a.stages ? a.stages : []
  var count = Array.isArray(steps) ? steps.length : 0
  if (count > 0 && steps[0].asRoot && stepIndex === 0 && stage < 0)
    return { fraction: 0.02, text: "Waiting for your password\u2026" }
  if (stages.length > 0 && stage >= 1 && stage <= stages.length)
    return { fraction: (stage - 0.5) / stages.length,
             text: "Step " + stage + " of " + stages.length + ": " + stages[stage - 1] }
  return { fraction: count > 0 ? (stepIndex + 0.5) / count : 0.5, text: "Working\u2026" }
}

// What an action printed, without its progress lines.
function actionOutputText(output) {
  return String(output).replace(/^VIGIL-STEP [0-9]\n?/gm, "")
}

// What the red Install button lists, by id from the report's "missing".
var HELPER_NAMES = { "clamav": "ClamAV", "arch-audit": "arch-audit", "osv-scanner": "osv-scanner", "fwupd": "fwupd",
                     "clamui": "ClamUI", "bumblebee": "Bumblebee" }

function missingLabel(report) {
  if (!report || !report.missing || report.missing.length === 0) return ""
  var names = []
  for (var i = 0; i < report.missing.length; i++) names.push(HELPER_NAMES[report.missing[i]])
  return "MISSING " + names.join(", ") + ". INSTALL"
}

// The four run buttons share one helper: what each runs, in the names the
// Last run list uses, one numbered line each.
function runLines(report, ids) {
  var has = function(id) {
    for (var i = 0; i < report.sources.length; i++) if (report.sources[i].id === id) return true
    return false
  }
  var what = {
    "settings": "Quick check: every row in every tab, from your settings and files (a second or so).",
    "downloads-scan": "Virus scan of ~/Downloads: what is new there since the last scan.",
    "pending-updates": "System update lookup: waiting system and Omarchy updates (nothing is installed).",
    "flatpak": "Flatpak update lookup, and the updates for your own Flatpak apps (no password).",
    "bumblebee": "Bumblebee scan: your npm, Bun and other packages against the Bumblebee list.",
    "virus-scan": "Virus scan of ~: your whole home folder, Downloads included. This can take a while.",
    "firmware": "Firmware lookup: firmware updates for this computer, from LVFS.",
    "password-check": "Password scan: every account has a password. Omarchy asks for your password.",
    "signatures": "Virus signatures (ClamAV). Omarchy asks for your password, because ClamAV keeps them in a system folder.",
    "arch-audit": "Arch security list: known holes in your packages, from the Arch security team.",
    "osv": "OSV malware list: malicious npm and Bun packages, from OSV.dev.",
    "aur": "AUR package status: whether your AUR packages are still maintained.",
    "bumblebee-list": "Bumblebee list: known-compromised packages, from Perplexity. An older Bumblebee is"
      + " updated to " + BUMBLEBEE_VERSION + " with the same password prompt as the signatures."
  }
  var lines = [], n = 1
  for (var i = 0; i < ids.length; i++)
    if (ids[i] === "settings" || has(ids[i])) lines.push((n++) + ". " + what[ids[i]])
  return lines
}

var UPDATE_IDS = ["signatures", "arch-audit", "osv", "aur", "bumblebee-list"]
var DAILY_IDS = ["pending-updates", "flatpak", "bumblebee", "downloads-scan", "settings"]
var WEEKLY_IDS = ["firmware", "virus-scan"]
var DONE_LINE = "The panel shows the progress, and you get a notification when it is done."

// Run list update: the lists Vigil checks against, and the one step that asks.
function updateConfirmation(report) {
  if (!report) return null
  var lines = runLines(report, UPDATE_IDS)
  if (lines.length === 0) lines = ["Nothing to update yet. Install ClamAV, arch-audit or osv-scanner (Detect and Supply tabs) to add them."]
  else lines.unshift("Downloads the latest of everything Vigil checks against:")
  lines.push("No scan runs. " + DONE_LINE)
  lines.push("Technical: wake clamav-freshclam (pkexec), arch-audit --upgradable, osv-scanner, an AUR lookup and Perplexity threat_intel, both with curl")
  return { title: "Run list update", lines: lines }
}

// Run daily check: light work, no password.
function dailyConfirmation(report) {
  if (!report) return null
  return { title: "Run daily check", lines: ["Runs the daily check now, in this order:"]
    .concat(runLines(report, DAILY_IDS)).concat([CARE_RUN_LINE, "No password needed. " + DONE_LINE]) }
}

// Run weekly check: the long one.
function weeklyConfirmation(report) {
  if (!report) return null
  var lines = runLines(report, WEEKLY_IDS)
  if (lines.length === 0) lines = ["Nothing to run yet. Install ClamUI (Detect tab) to add the scan of your home folder."]
  return { title: "Run weekly check", lines: ["Runs the weekly check now, in this order:"]
    .concat(lines).concat(["No password needed. You can close this panel. " + DONE_LINE]) }
}

// Run all: the list update, the daily check and the weekly check, plus the
// password scan. The scan of your home folder covers Downloads, so Downloads
// is not scanned twice. The steps that ask for your password come first.
function fullScanConfirmation(report) {
  if (!report) return null
  var ids = UPDATE_IDS.slice(0, 1).concat(["password-check"]).concat(UPDATE_IDS.slice(1))
    .concat(DAILY_IDS.filter(function(id) { return id !== "downloads-scan" })).concat(WEEKLY_IDS)
  return { title: "Run all", lines: ["Runs the list update, the daily check and the weekly check, in this order:"]
    .concat(runLines(report, ids))
    .concat(["The virus scan of ~ includes Downloads, so ~/Downloads is not scanned twice.", CARE_RUN_LINE,
             "Omarchy asks for your password at the start, up to twice. " + DONE_LINE]) }
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

// The version a report says it came from, without trusting anything else in it.
function reportVersion(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_REPORT_CHARS) return ""
  var d
  try { d = JSON.parse(text) } catch (e) { return "" }
  return d && typeof d === "object" && isString(d.version, 20) && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(d.version)
    ? d.version : ""
}

// Which part of a rejected report failed, in a few words, for the status line.
function reportProblem(text) {
  if (typeof text !== "string" || text.length === 0) return "it was empty"
  if (text.length > MAX_REPORT_CHARS) return "it was too large"
  var d
  try { d = JSON.parse(text) } catch (e) { return "it was not JSON" }
  if (!d || typeof d !== "object" || d.schema !== 1) return "unknown format"
  if (!Array.isArray(d.checks)) return "no checks"
  for (var i = 0; i < d.checks.length; i++) {
    if (!validCheck(d.checks[i])) {
      var id = d.checks[i] && isString(d.checks[i].id, 40) && /^[a-z0-9-]+$/.test(d.checks[i].id) ? d.checks[i].id : "?"
      return "the " + id + " check"
    }
  }
  if (parseSources(d.sources) === null) return "the Last run list"
  if (parseLastRun(d.lastRun) === null) return "the last update"
  if (parseHistory(d.history) === null) return "the score history"
  if (d.running !== undefined && parseRunningValue(d.running) === undefined) return "the running scan"
  return "the report"
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
      if (!/^omarchy-[a-z0-9-]{1,60}$/.test(name) && name !== "xdg-open" && name !== "pkexec") return null
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
  // "" (nothing set up), "now" (due already), or a local "YYYY-MM-DD HH:MM".
  var optionalDate = function(v) {
    if (v === undefined || v === "" || v === "now") return v === undefined ? "" : v
    return isString(v, 16) && /^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$/.test(v) ? v : null
  }
  var nextUpdate = optionalDate(d.nextUpdate)
  var nextFullScan = optionalDate(d.nextFullScan)
  var nextDaily = optionalDate(d.nextDaily)
  var missing = []
  if (d.missing !== undefined) {
    if (!Array.isArray(d.missing) || d.missing.length > 20) return null
    for (var mi = 0; mi < d.missing.length; mi++) {
      if (!isString(d.missing[mi], 40)) return null
      // A helper this panel does not know yet (a newer helper) is skipped.
      if (!Object.prototype.hasOwnProperty.call(HELPER_NAMES, d.missing[mi])) continue
      if (missing.indexOf(d.missing[mi]) !== -1) return null
      missing.push(d.missing[mi])
    }
  }
  if (nextUpdate === null || nextFullScan === null || nextDaily === null) return null
  var running = parseRunningValue(d.running)
  if (running === undefined) return null
  return {
    running: running,
    sources: sources,
    lastRun: lastRun,
    nextUpdate: nextUpdate,
    nextFullScan: nextFullScan,
    nextDaily: nextDaily,
    missing: missing,
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
  return { ok: d.ok, message: plain(d.message, 240), stopped: d.stopped === true }
}

// ---------------------------------------------------------------------------
// Display

// With Vigil's own weekly run switched off, the other apps' schedules are
// the only ones, so they are not "twice" and nothing is offered.
function withSettings(report, autoUpdate) {
  if (!report || autoUpdate !== false) return report
  var out = Object.assign({}, report)
  out.checks = report.checks.map(function(c) {
    if (c.id !== "other-schedules" || c.status !== "info") return c
    return Object.assign({}, c, {
      status: "na",
      summary: "The Vigil weekly scan is off in its settings, so these schedules are your only ones.",
      fix: { kind: "none", action: "", label: "" }, howto: ""
    })
  })
  return out
}

// The schedule each tab row belongs to: 1 daily check, 2 weekly check,
// 3 list update. Every other row comes from the quick check (0), which runs
// with every check, the daily one included.
var CHECK_SCHEDULE = { "virus-scan": 1, "updates": 1, "flatpak-apps": 1, "bumblebee": 1, "firmware": 2,
                       "scanner-arch-audit": 3, "malicious-packages": 3, "aur-status": 3,
                       "scanner-clamav": 3 }

// Care rows that are never part of Clean all: removing packages, or settings
// you might want back, deserves a look item by item. They sort last on the
// Care tab, under their own heading.
var CARE_SEPARATE = ["orphans", "leftovers"]
var CARE_SEPARATE_HEADING = "NOT IN CLEAN ALL"
var CARE_SEPARATE_NOTE = "Removing packages, or settings you may want back, deserves a look. Clean all never touches these: review them one by one."

function separateFromCleanAll(check) {
  return !!check && check.category === "care" && inList(check.id, CARE_SEPARATE)
}

// Which group a row belongs to on its tab, in the order the tab shows them:
// the quick check, then what the daily check, the weekly check and the list
// update bring in; on the Care tab, what Clean all covers, then what it
// leaves alone.
function rowGroup(c) {
  if (separateFromCleanAll(c)) return 100
  return CHECK_SCHEDULE.hasOwnProperty(c.id) ? CHECK_SCHEDULE[c.id] : 0
}

// The quick check reads settings and files on this computer (no network, no
// scan, about a second): every refreshMinutes, whenever the panel opens, on a
// middle-click of the lighthouse, and first in every daily check. Its
// heading says how often, from the setting.
function quickCheckHeading(refreshMinutes) {
  var n = Math.max(5, Math.min(1440, Math.round(Number(refreshMinutes) || 30)))
  var every = n % 60 === 0 ? (n === 60 ? "EVERY HOUR" : "EVERY " + (n / 60) + " HOURS") : "EVERY " + n + " MINUTES"
  return "QUICK CHECK \u00b7 " + every
}

var GROUP_HEADINGS = { 0: "QUICK CHECK", 1: "DAILY CHECK", 2: "WEEKLY CHECK", 3: "LIST UPDATE", 100: CARE_SEPARATE_HEADING }

// The heading above a row, or "": at the start of each group, on tabs that
// have more than one. The Care tab names its groups for Clean all.
function rowHeading(checks, index, refreshMinutes) {
  if (!checks || index < 0 || index >= checks.length) return ""
  var g = rowGroup(checks[index])
  if (index > 0 && rowGroup(checks[index - 1]) === g) return ""
  var groups = {}
  for (var i = 0; i < checks.length; i++) groups[rowGroup(checks[i])] = true
  if (Object.keys(groups).length < 2) return ""
  if (checks[index].category === "care") return g === 100 ? CARE_SEPARATE_HEADING : "IN CLEAN ALL"
  if (g === 0) return quickCheckHeading(refreshMinutes)
  return GROUP_HEADINGS.hasOwnProperty(g) ? GROUP_HEADINGS[g] : ""
}

// The line under a heading, or "": only the Care rows Clean all leaves alone.
function rowHeadingNote(checks, index) {
  return rowHeading(checks, index) === CARE_SEPARATE_HEADING ? CARE_SEPARATE_NOTE : ""
}

function checksFor(report, category) {
  if (!report) return []
  var out = []
  for (var i = 0; i < report.checks.length; i++)
    if (report.checks[i].category === category) out.push(report.checks[i])
  // Grouped like the Last run list: the quick check first, then
  // the daily check, weekly check, list update and ClamAV's own updates.
  // Within a group, worst first; reviewed warnings sort after the
  // information rows, just above "pass".
  // On the Care tab, what Clean all leaves alone comes last.
  function group(c) { return rowGroup(c) + (separateFromCleanAll(c) ? CARE_SEPARATE.indexOf(c.id) / 10 : 0) }
  function rank(c) { return c.dismissed ? STATUSES.indexOf("info") + 0.5 : STATUSES.indexOf(c.status) }
  out.sort(function(a, b) {
    var d = group(a) - group(b) || rank(a) - rank(b)
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

// What a pillar row on the Overview says: how many findings of each kind it shows.
function pillarCounts(fails, warns, notes) {
  var parts = []
  if (fails) parts.push(fails + " to fix")
  if (warns) parts.push(warns + " to improve")
  if (notes) parts.push(notes + (notes === 1 ? " note" : " notes"))
  return parts.length ? parts.join(" \u00b7 ") : "\u2713 all good"
}

// The security pillars. Care is upkeep, not security: its rows never count
// toward the score or notify, and no run cleans anything.
var SECURITY_PILLARS = ["harden", "detect", "supply", "privacy"]

// Which of a pillar's findings matter most, for the caption under its tab:
// the most urgent kind only, as a number over a word ("2" over "to fix"), so
// every tab's caption has the same two lines; its tooltip has every count.
// tone is "urgent" (to fix), "warn" (to improve) or "dim" (nothing to do).
function caption(count, label, tone) {
  return { count: String(count), label: label, tone: tone, text: count + " " + label }
}

function tabCaption(report, tab) {
  if (!report) return { count: "", label: "", tone: "dim", text: "" }
  if (tab === "care") {
    var warn = countBy(report, "care", "warn")
    var tidy = warn + countBy(report, "care", "info") + countBy(report, "care", "fail")
    return tidy ? caption(tidy, "to tidy", warn ? "warn" : "dim") : caption("\u2713", "tidy", "dim")
  }
  var cats = tab === "overview" ? SECURITY_PILLARS : (inList(tab, SECURITY_PILLARS) ? [tab] : [])
  if (cats.length === 0) return { count: "", label: "", tone: "dim", text: "" }
  var f = 0, w = 0, n = 0
  for (var i = 0; i < cats.length; i++) {
    f += countBy(report, cats[i], "fail")
    w += countBy(report, cats[i], "warn")
    n += countBy(report, cats[i], "info")
  }
  if (f) return caption(f, "to fix", "urgent")
  if (w) return caption(w, "to improve", "warn")
  if (n) return caption(n, n === 1 ? "note" : "notes", "dim")
  return caption("\u2713", "all good", "dim")
}

// Every count of a tab, for its tooltip and the top of its page.
function tabCounts(report, tab) {
  if (!report) return ""
  var cats = tab === "overview" ? SECURITY_PILLARS : (inList(tab, SECURITY_PILLARS.concat(["care"])) ? [tab] : [])
  if (cats.length === 0) return ""
  var f = 0, w = 0, n = 0
  for (var i = 0; i < cats.length; i++) {
    f += countBy(report, cats[i], "fail")
    w += countBy(report, cats[i], "warn")
    n += countBy(report, cats[i], "info")
  }
  return (tab === "overview" ? "Security: " : "") + pillarCounts(f, w, n)
}

var CARE_NOTE = "Care is separate from security: it never counts toward the score, and the checks above never clean anything. Vigil cleans only when you press a button on the Care tab."
var CARE_TAB_NOTE = "Separate from security: not part of the score, the daily check, the weekly check or the list update. Nothing is cleaned until you press a button."
var CARE_RUN_LINE = "Nothing on the Care tab is cleaned: that happens only when you press a button there."

function categoryLabel(category) {
  return { overview: "Overview", harden: "Harden", detect: "Detect", supply: "Supply",
           privacy: "Privacy", care: "Care" }[category] || ""
}

// The question each pillar answers, and in one line what it covers.
var TAB_INTROS = {
  harden: { question: "Can someone get in?",
            text: "Settings that make this machine harder to break into." },
  detect: { question: "Is something bad already here?",
            text: "Signs of malware: startup files, changed system files, and ClamAV virus scans." },
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
    plain: plain, parseReport: parseReport, reportVersion: reportVersion, reportProblem: reportProblem,
    VERSION: VERSION, parseFixResult: parseFixResult, terminalScript: terminalScript,
    terminalAction: terminalAction, actionPlan: actionPlan, runMode: runMode, stripSudo: stripSudo, launcherPath: launcherPath, canRun: canRun, checksFor: checksFor, withSettings: withSettings,
    topFindings: topFindings, countBy: countBy, statusGlyph: statusGlyph, levelText: levelText,
    tooltip: tooltip, confirmation: confirmation, helperInfo: helperInfo, isHelperAction: isHelperAction,
    categoryLabel: categoryLabel, pillarCounts: pillarCounts, tabCaption: tabCaption, tabCounts: tabCounts,
    CARE_NOTE: CARE_NOTE, rowHeading: rowHeading, rowHeadingNote: rowHeadingNote, quickCheckHeading: quickCheckHeading, runCaptions: runCaptions,
    scheduleNotes: scheduleNotes, heroMeta: heroMeta, keyHints: keyHints, separateFromCleanAll: separateFromCleanAll,
    CARE_SEPARATE_HEADING: CARE_SEPARATE_HEADING, CARE_SEPARATE_NOTE: CARE_SEPARATE_NOTE, CARE_TAB_NOTE: CARE_TAB_NOTE, CARE_RUN_LINE: CARE_RUN_LINE, tabIntro: tabIntro, cleanAllPlan: cleanAllPlan,
    howTo: howTo, docsUrl: docsUrl, docsCommand: docsCommand, DOCS: DOCS, appCommand: appCommand, APP_ACTIONS: APP_ACTIONS,
    shortDate: shortDate, historySummary: historySummary, VIGIL_MARK: VIGIL_MARK,
    relativeDay: relativeDay, sourceLine: sourceLine, lastRunLine: lastRunLine, countdown: countdown, scheduleLines: scheduleLines,
    BUMBLEBEE_INSTALL: BUMBLEBEE_INSTALL, BUMBLEBEE_VERSION: BUMBLEBEE_VERSION,
    SIGNATURES_SCRIPT: SIGNATURES_SCRIPT, NO_PASSWORD_STEP: NO_PASSWORD_STEP, rootUpdatesScript: rootUpdatesScript,
    parseProgress: parseProgress, parseRunning: parseRunning, detectionItem: detectionItem, leftoverItem: leftoverItem, leftoverTrashIds: leftoverTrashIds, actionStage: actionStage, actionProgress: actionProgress,
    actionOutputText: actionOutputText, progressText: progressText, lastRunRows: lastRunRows, missingLabel: missingLabel,
    TERMINAL_ACTIONS: TERMINAL_ACTIONS, HELPER_ACTIONS: HELPER_ACTIONS, HELPER_INFO: HELPER_INFO,
    SYSCTL_LINES: SYSCTL_LINES
  }
}
