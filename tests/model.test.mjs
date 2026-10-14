// Tests for Model.js. Run with: node --test tests/
import { test } from "node:test"
import assert from "node:assert/strict"
import { createRequire } from "node:module"
import { execFileSync, spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import path from "node:path"

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const M = require(path.join(here, "..", "Model.js"))

const TOOLS = {
  "omarchy-launch-floating-terminal-with-presentation": "/usr/bin",
  "omarchy-setup-security-fido2": "/usr/bin",
  "omarchy-update-firmware": "/usr/bin",
  "omarchy-remove-security-fido2": "/usr/bin",
  "omarchy-setup-security-fingerprint": "/usr/bin",
  "omarchy-remove-security-fingerprint": "/usr/bin",
  "omarchy-sudo-passwordless": "/usr/bin",
  "omarchy-remove-security-sudoless-docker": "/usr/bin",
  "omarchy-update": "/usr/bin",
  "omarchy-pkg-add": "/usr/share/omarchy/bin",
  "omarchy-update-orphan-pkgs": "/usr/bin",
  "omarchy-toggle-idle": "/usr/bin",
  "omarchy-shell-config": "/usr/share/omarchy/bin",
  "omarchy-plugin-list": "/usr/share/omarchy/bin",
  "omarchy-plugin-disable": "/usr/share/omarchy/bin",
  "omarchy-plugin-enable": "/usr/share/omarchy/bin",
  "xdg-open": "/usr/bin",
  "pkexec": "/usr/bin"
}

function check(over = {}) {
  return Object.assign({
    id: "firewall", category: "harden", title: "Firewall", status: "fail",
    summary: "off", why: "because", detail: "", weight: 3,
    fix: { kind: "terminal", action: "firewall-on", label: "Turn it on" }
  }, over)
}

function report(over = {}) {
  return Object.assign({
    schema: 1, version: "0.1.0", generatedAt: "2026-10-12T10:00:00+0000", score: 70, level: "fail",
    counts: {}, checks: [check()], tools: TOOLS, new: []
  }, over)
}

const parse = (o) => M.parseReport(JSON.stringify(o))

test("accepts a well-formed report", () => {
  const r = parse(report())
  assert.equal(r.checks.length, 1)
  assert.equal(r.score, 70)
})

test("accepts the real helper output", () => {
  const out = execFileSync("/usr/bin/python3", ["-I", "-S", path.join(here, "..", "bin", "vigil"), "audit", "--peek"])
  assert.ok(M.parseReport(out.toString().trim()))
})

test("rejects malformed reports whole", () => {
  assert.equal(M.parseReport(""), null)
  assert.equal(M.parseReport("{"), null)
  assert.equal(M.parseReport("x".repeat(512 * 1024 + 1)), null)
  assert.equal(parse(report({ schema: 2 })), null)
  assert.equal(parse(report({ score: 101 })), null)
  assert.equal(parse(report({ score: "70" })), null)
  assert.equal(parse(report({ level: "great" })), null)
  assert.equal(parse(report({ checks: [check(), check()] })), null, "duplicate ids")
  assert.equal(parse(report({ checks: [check({ status: "pwned" })] })), null)
  assert.equal(parse(report({ checks: [check({ id: "../x" })] })), null)
  assert.equal(parse(report({ checks: [check({ weight: 1.5 })] })), null)
  assert.equal(parse(report({ checks: [check({ weight: Infinity })] })), null)
  assert.equal(parse(report({ checks: [check({ summary: "x".repeat(401) })] })), null)
  assert.equal(parse(report({ checks: Array.from({ length: 161 }, (_, i) => check({ id: "c" + i })) })), null)
  assert.equal(parse(report({ tools: { "omarchy-update": "/home/me/bin" } })), null)
  assert.equal(parse(report({ tools: { "rm": "/usr/bin" } })), null)
  assert.equal(parse(report({ new: ["not-a-check"] })), null)
})

test("unknown fix actions are downgraded to no fix", () => {
  const r = parse(report({ checks: [check({ fix: { kind: "terminal", action: "rm-rf", label: "x" } })] }))
  assert.equal(r.checks[0].fix.kind, "none")
  const h = parse(report({ checks: [check({ fix: { kind: "helper", action: "nope", label: "x" } })] }))
  assert.equal(h.checks[0].fix.kind, "none")
  assert.equal(parse(report({ checks: [check({ fix: { kind: "shell", action: "x", label: "x" } })] })), null)
})

test("__proto__ keys do not pollute", () => {
  const text = JSON.stringify(report()).replace('"tools":{', '"tools":{"__proto__":"/usr/bin",')
  assert.equal(M.parseReport(text), null)
  assert.equal(({}).polluted, undefined)
})

test("plain strips markup, controls and bidi, and caps", () => {
  assert.equal(M.plain('<img src="http://x/">a&b'), 'img src="http://x/"ab')
  assert.equal(M.plain("a‮b\u0007c"), "a b c")
  assert.equal(M.plain("x".repeat(50), 10).length, 10)
  const r = parse(report({ checks: [check({ title: "<b>Fire</b>wall", detail: "a<img>" })] }))
  assert.equal(r.checks[0].title, "bFire/bwall")
  assert.equal(r.checks[0].detail, "aimg")
})

test("terminal scripts: closed set, tool dirs enforced", () => {
  assert.equal(M.terminalScript("nope", TOOLS), "")
  assert.equal(M.terminalScript("__proto__", TOOLS), "")
  assert.equal(M.terminalScript("constructor", TOOLS), "")
  assert.equal(M.terminalScript("update", {}), "")
  assert.equal(M.terminalScript("update", { "omarchy-update": "/tmp" }), "")
  assert.match(M.terminalScript("update", TOOLS), /\( set -e; \/usr\/bin\/omarchy-update \)$/)
  assert.match(M.terminalScript("update", TOOLS), /\/usr\/bin\/omarchy-update/)
  assert.equal(M.launcherPath({}), "")
  assert.equal(M.launcherPath(TOOLS), "/usr/bin/omarchy-launch-floating-terminal-with-presentation")
})

test("every terminal script is valid bash and asks before running", () => {
  for (const id of Object.keys(M.TERMINAL_ACTIONS)) {
    const a = M.TERMINAL_ACTIONS[id]
    for (const line of [a.title].concat(a.what)) {
      assert.ok(!line.includes("'"), `${id}: single quote in text would break the script`)
    }
    const script = M.terminalScript(id, TOOLS)
    assert.ok(script.length > 0, id)
    assert.match(script, /read -r -p 'Press Enter to continue, or Ctrl\+C to cancel\. ' _ && \( set -e; /, id)
    // The launcher wraps the script as: bash -c "omarchy-show-logo; $cmd; ..."
    const wrapped = `omarchy-show-logo; ${script}; code=$?`
    const res = spawnSync("/usr/bin/bash", ["-n", "-c", wrapped])
    assert.equal(res.status, 0, `${id}: ${res.stderr}`)
  }
})

test("sysctl drop-in carries the Vigil marker and only key=value lines", () => {
  assert.match(M.SYSCTL_LINES[0], /^# Written by Vigil/)
  for (const l of M.SYSCTL_LINES.slice(1)) assert.match(l, /^[a-z0-9_.]+=[0-9]+$/)
})

test("canRun", () => {
  assert.equal(M.canRun({ kind: "helper", action: "ssh-perms" }, {}), true)
  assert.equal(M.canRun({ kind: "helper", action: "x" }, {}), false)
  assert.equal(M.canRun({ kind: "terminal", action: "firewall-on" }, TOOLS), true)
  assert.equal(M.canRun({ kind: "terminal", action: "firewall-on" }, {}), false, "no launcher")
  assert.equal(M.canRun({ kind: "none", action: "" }, TOOLS), false)
})

test("every action has a confirmation", () => {
  for (const id of M.HELPER_ACTIONS) assert.ok(M.confirmation("helper", id), id)
  for (const id of Object.keys(M.TERMINAL_ACTIONS)) assert.ok(M.confirmation("terminal", id), id)
  assert.equal(M.confirmation("helper", "__proto__"), null)
  assert.equal(M.confirmation("shell", "update"), null)
})

test("ordering and counts", () => {
  const r = parse(report({ checks: [
    check({ id: "a", status: "pass", weight: 3 }),
    check({ id: "b", status: "warn", weight: 1 }),
    check({ id: "c", status: "fail", weight: 1 }),
    check({ id: "d", status: "warn", weight: 0 }),
    check({ id: "e", status: "info", category: "detect", weight: 0 })
  ] }))
  assert.deepEqual(M.topFindings(r).map((c) => c.id), ["c", "b"])
  assert.deepEqual(M.checksFor(r, "harden").map((c) => c.id), ["c", "b", "d", "a"])
  assert.equal(M.countBy(r, "harden", "warn"), 2)
  assert.equal(M.countBy(r, "", "info"), 1)
  assert.match(M.tooltip(r, false), /^Vigil 70\/100/)
})

test("app actions: fixed argv per install kind, nothing else", () => {
  assert.deepEqual(M.appCommand("open-clamui", { clamui: "flatpak" }), ["/usr/bin/flatpak", "run", "io.github.linx_systems.ClamUI"])
  assert.deepEqual(M.appCommand("open-clamui", { clamui: "native" }), ["/usr/bin/clamui"])
  assert.deepEqual(M.appCommand("open-clamui", { clamui: "" }), [])
  assert.deepEqual(M.appCommand("open-clamui", { clamui: "__proto__" }), [])
  assert.deepEqual(M.appCommand("open-clamui", {}), [])
  assert.deepEqual(M.appCommand("constructor", { clamui: "native" }), [])
  assert.equal(M.canRun({ kind: "app", action: "open-clamui" }, {}, { clamui: "native" }), true)
  assert.equal(M.canRun({ kind: "app", action: "open-clamui" }, {}, { clamui: "" }), false)
})

test("apps field is validated", () => {
  assert.equal(parse(report({ apps: { clamui: "/tmp/evil" } })), null)
  assert.equal(parse(report({ apps: "native" })), null)
  assert.equal(parse(report({ apps: { clamui: "flatpak" } })).apps.clamui, "flatpak")
  assert.equal(parse(report()).apps.clamui, "")
  const r = parse(report({ checks: [check({ fix: { kind: "app", action: "open-anything", label: "x" } })] }))
  assert.equal(r.checks[0].fix.kind, "none")
})

test("pillars are the only categories", () => {
  for (const cat of ["harden", "detect", "supply", "privacy", "care"]) {
    assert.ok(parse(report({ checks: [check({ category: cat })] })), cat)
  }
  assert.equal(parse(report({ checks: [check({ category: "scan" })] })), null)
})

import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, mkdirSync, symlinkSync, statSync, lstatSync, readdirSync } from "node:fs"
import { tmpdir } from "node:os"

// Run a terminal action's body for real, with its /etc paths moved into a
// temporary directory and sudo and service restarts made harmless.
function runUndo(id, setup) {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-undo-"))
  let body = M.TERMINAL_ACTIONS[id].run
  body = body.split("/etc/").join(dir + "/etc/").split("sudo ").join("")
    .split("/usr/bin/systemctl").join("/usr/bin/true").split("/usr/bin/sysctl").join("/usr/bin/true")
  setup(dir)
  const res = spawnSync("/usr/bin/bash", ["-c", "( set -e; " + body + " )"], { encoding: "utf8" })
  return { dir, status: res.status, out: res.stdout + res.stderr }
}

function place(dir, rel, text) {
  const full = dir + rel
  execFileSync("/usr/bin/mkdir", ["-p", path.dirname(full)])
  writeFileSync(full, text)
  return full
}

test("undo removes only files that still carry the Vigil marker", () => {
  const rel = "/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf"
  let f
  let r = runUndo("undo-llmnr", (d) => { f = place(d, rel, M.VIGIL_MARK + "\n[Resolve]\nLLMNR=no\n") })
  assert.equal(r.status, 0, r.out)
  assert.equal(existsSync(f), false)
  rmSync(r.dir, { recursive: true })

  r = runUndo("undo-llmnr", (d) => { f = place(d, rel, "# mine now\n" + M.VIGIL_MARK + "\n") })
  assert.equal(r.status, 1)
  assert.match(r.out, /left alone/)
  assert.equal(existsSync(f), true)
  rmSync(r.dir, { recursive: true })

  r = runUndo("undo-llmnr", () => {})
  assert.equal(r.status, 0)
  assert.match(r.out, /Nothing to undo/)
  rmSync(r.dir, { recursive: true })
})

test("avahi undo restores the backup", () => {
  let conf
  const r = runUndo("undo-avahi", (d) => {
    conf = place(d, "/etc/avahi/avahi-daemon.conf", "[publish]\ndisable-publishing=yes\n")
    place(d, "/etc/avahi/avahi-daemon.conf.vigil-backup", "[publish]\n#disable-publishing=no\n")
  })
  assert.equal(r.status, 0, r.out)
  assert.equal(readFileSync(conf, "utf8"), "[publish]\n#disable-publishing=no\n")
  assert.equal(existsSync(conf + ".vigil-backup"), false)
  rmSync(r.dir, { recursive: true })
})

test("undo, review and history fields are validated", () => {
  const undo = (u) => parse(report({ checks: [check({ undo: u })] }))
  assert.equal(undo({ action: "undo-sysctl", label: "Undo" }).checks[0].undo.action, "undo-sysctl")
  assert.equal(undo({ action: "", label: "" }).checks[0].undo.action, "")
  assert.equal(undo({ action: "firewall-on", label: "x" }), null, "undo must be an undo- action")
  assert.equal(undo({ action: "undo-anything", label: "x" }), null)
  assert.equal(undo("undo-sysctl"), null)

  const warn = { status: "warn", weight: 1 }
  assert.ok(parse(report({ checks: [check(Object.assign({ dismissible: true, dismissed: true, dismissedAt: "2026-10-12" }, warn))] })))
  assert.equal(parse(report({ checks: [check(Object.assign({ dismissible: false, dismissed: true }, warn))] })), null)
  assert.ok(parse(report({ checks: [check({ status: "fail", dismissible: true, dismissed: true })] })))
  assert.equal(parse(report({ checks: [check({ status: "pass", dismissible: true, dismissed: true })] })), null)
  assert.equal(parse(report({ checks: [check(Object.assign({ dismissible: "yes" }, warn))] })), null)
  assert.equal(parse(report({ checks: [check(Object.assign({ dismissible: true, dismissed: true, dismissedAt: "<b>" }, warn))] })), null)

  assert.deepEqual(parse(report({ history: [{ date: "2026-10-11", score: 70 }, { date: "2026-10-12", score: 80 }] })).history.length, 2)
  assert.equal(parse(report({ history: [{ date: "yesterday", score: 70 }] })), null)
  assert.equal(parse(report({ history: [{ date: "2026-10-12", score: 101 }] })), null)
  assert.equal(parse(report({ history: [{ date: "2026-10-12", score: 7.5 }] })), null)
  assert.equal(parse(report({ history: Array.from({ length: 61 }, () => ({ date: "2026-10-12", score: 1 })) })), null)
})

test("reviewed warnings drop out of findings and counts", () => {
  const r = parse(report({ checks: [
    check({ id: "a", status: "warn", weight: 2, dismissible: true, dismissed: true }),
    check({ id: "b", status: "warn", weight: 1, dismissible: true }),
    check({ id: "c", status: "info", weight: 0 }),
    check({ id: "d", status: "pass", weight: 1 })
  ] }))
  assert.deepEqual(M.topFindings(r).map((c) => c.id), ["b"])
  assert.equal(M.countBy(r, "harden", "warn"), 1)
  assert.deepEqual(M.checksFor(r, "harden").map((c) => c.id), ["b", "c", "a", "d"])
})

test("history helpers", () => {
  assert.equal(M.shortDate("2026-10-12"), "Oct 12")
  assert.equal(M.shortDate("2026-13-01"), "")
  assert.equal(M.historySummary([]), "")
  assert.match(M.historySummary([{ date: "2026-10-12", score: 80 }]), /^Today 80/)
  assert.equal(M.historySummary([{ date: "2026-10-01", score: 60 }, { date: "2026-10-12", score: 85 }, { date: "2026-10-05", score: 40 }].slice(0, 2)),
    "Oct 1 60 → Oct 12 85 · low 60, high 85")
})

test("every pillar and tab label is one word", () => {
  for (const cat of ["overview", "harden", "detect", "supply", "privacy", "care"]) {
    assert.match(M.categoryLabel(cat), /^[A-Z][a-z]+$/, cat)
  }
})

test("each pillar opens with a question and a one-line explanation", () => {
  for (const cat of ["harden", "detect", "supply", "privacy", "care"]) {
    const intro = M.tabIntro(cat)
    assert.match(intro.question, /^[A-Z].*\?$/, cat)
    assert.ok(intro.text.length > 0 && intro.text.length <= 90, cat)
  }
  assert.deepEqual(M.tabIntro("overview"), { question: "", text: "" })
})

test("feedsDue is a strict boolean", () => {
  assert.equal(parse(report()).feedsDue, false)
  assert.equal(parse(report({ feedsDue: true })).feedsDue, true)
  assert.equal(parse(report({ feedsDue: "yes" })), null)
})

test("feedsUpdated is a date or empty", () => {
  assert.equal(parse(report()).feedsUpdated, "")
  assert.equal(parse(report({ feedsUpdated: "2026-10-12" })).feedsUpdated, "2026-10-12")
  assert.equal(parse(report({ feedsUpdated: "<b>soon</b>" })), null)
  assert.ok(M.confirmation("helper", "virus-scan-now"))
})

test("sources and last run are validated and worded plainly", () => {
  const good = { id: "arch-audit", label: "Known vulnerabilities", date: "2026-10-12", state: "ok", tried: "" }
  const r = parse(report({ sources: [good], lastRun: { at: "2026-10-12 09:41", ok: true } }))
  assert.equal(r.sources[0].label, "Known vulnerabilities")
  assert.equal(r.lastRun.at, "2026-10-12 09:41")
  assert.deepEqual(parse(report()).sources, [])
  assert.equal(parse(report()).lastRun.at, "")
  // A source a newer helper reports is skipped, not a reason to reject everything.
  assert.deepEqual(parse(report({ sources: [Object.assign({}, good, { id: "some-new-source" }), good] })).sources.map(x => x.id), [good.id])
  assert.equal(parse(report({ sources: [Object.assign({}, good, { id: { evil: 1 } })] })), null)
  assert.equal(parse(report({ sources: [Object.assign({}, good, { state: "great" })] })), null)
  assert.equal(parse(report({ sources: [Object.assign({}, good, { date: "<img>" })] })), null)
  assert.equal(parse(report({ lastRun: { at: "now", ok: true } })), null)
  assert.equal(parse(report({ lastRun: { at: "2026-10-12 09:41", ok: "yes" } })), null)

  const now = new Date(2026, 9, 12, 15, 0)
  assert.equal(M.sourceLine({ state: "ok", date: "2026-10-12" }, now), "updated today")
  assert.equal(M.sourceLine({ state: "ok", date: "2026-10-11" }, now), "updated yesterday")
  assert.equal(M.sourceLine({ state: "failed", date: "2026-10-03", tried: "2026-10-12" }, now), "last update failed; last good Oct 3")
  assert.equal(M.sourceLine({ state: "never", date: "" }, now), "not updated yet")
  assert.match(M.lastRunLine({ at: "2026-10-12 09:41", ok: true }, now), /^Last update today at 09:41\. Every source refreshed\.$/)
  assert.match(M.lastRunLine({ at: "2026-10-05 09:41", ok: false }, now), /did not refresh/)
  assert.equal(M.sourceLine({ id: "virus-scan", state: "ok", date: "2026-10-12" }, now), "ran today")
  assert.equal(M.sourceLine({ id: "virus-scan", state: "never", date: "" }, now), "not run yet")
})

// ---------------------------------------------------------------------------
// Clean all (Care tab)

function careReport(extra = {}) {
  const care = (id, title, summary, kind, action) => check({
    id, category: "care", title, status: "info", summary, weight: 0,
    fix: kind ? { kind, action, label: "x" } : { kind: "none", action: "", label: "" }
  })
  return parse(report(Object.assign({
    checks: [
      care("thumbnails", "Thumbnail cache", "12.0 MB.", "helper", "clean-thumbnails"),
      care("trash", "Trash", "Empty.", null),
      care("pacman-cache", "Package cache", "3.1 GB.", "terminal", "clean-pacman-cache"),
      care("orphans", "Orphaned packages", "2 orphaned packages.", "terminal", "clean-orphans"),
      care("journal", "System logs", "Logs take up 400M.", "terminal", "clean-journal"),
      check()
    ]
  }, extra)))
}

test("clean all covers the offered cleanups and never orphans", () => {
  const plan = M.cleanAllPlan(careReport())
  assert.equal(plan.user, true)
  assert.equal(plan.system, true)
  assert.deepEqual(plan.items, ["Thumbnail cache: 12.0 MB", "Package cache: 3.1 GB", "System logs: Logs take up 400M"])
  const card = M.confirmation("clean-all", "care", careReport())
  assert.equal(card.title, "Clean all")
  assert.ok(card.lines.some(l => l.startsWith("Orphaned packages and leftover app data are left out")))
  assert.ok(card.lines.some(l => l.includes("Omarchy asks for your password once")))
})

test("clean all without a terminal launcher keeps only the no-root part", () => {
  const plan = M.cleanAllPlan(careReport({ tools: {} }))
  assert.equal(plan.user, true)
  assert.equal(plan.system, false)
  assert.deepEqual(plan.items, ["Thumbnail cache: 12.0 MB"])
  assert.ok(!M.confirmation("clean-all", "care", careReport({ tools: {} })).lines.some(l => l.includes("asks for your password")))
})

test("clean all has nothing to offer on a tidy system or without a report", () => {
  assert.equal(M.cleanAllPlan(null).items.length, 0)
  assert.equal(M.confirmation("clean-all", "care", null), null)
  assert.equal(M.cleanAllPlan(parse(report())).items.length, 0)
})

test("clean all and the Lynis copy are fixed scripts with absolute paths", () => {
  const sys = M.terminalScript("clean-system", TOOLS)
  assert.match(sys, /sudo \/usr\/bin\/paccache -rk2/)
  assert.match(sys, /sudo \/usr\/bin\/journalctl --vacuum-time=2weeks/)
  assert.equal(M.terminalAction("password-check"), null)        // now Omarchy's password dialog, not a terminal
  assert.match(M.terminalScript("old-services-off", TOOLS), /sudo \/usr\/bin\/systemctl disable --now "\$u"/)
  assert.match(M.terminalScript("restart", TOOLS), /\/usr\/bin\/systemctl reboot \)$/)
  assert.ok(M.isHelperAction("clean-user"))
})

// ---------------------------------------------------------------------------
// Learn more pages and How to fix

test("learn-more pages come only from the fixed table", () => {
  assert.equal(M.docsUrl("arch-dm-crypt"), "https://wiki.archlinux.org/title/Dm-crypt")
  for (const bad of ["lynis-auth-9262", "lynis-../x", "https://evil.example", "", null, "toString", "__proto__"])
    assert.equal(M.docsUrl(bad), "", String(bad))
  for (const url of Object.values(M.DOCS)) assert.match(url, /^https:\/\/(wiki\.archlinux\.org|github\.com|attack\.mitre\.org)\//)
  assert.deepEqual(M.docsCommand("arch-users", TOOLS), ["/usr/bin/xdg-open", "https://wiki.archlinux.org/title/Users_and_groups"])
  assert.deepEqual(M.docsCommand("arch-users", {}), [])
  const r = parse(report({ checks: [check({ status: "info", fix: { kind: "docs", action: "nope", label: "Learn more" } })] }))
  assert.equal(r.checks[0].fix.kind, "none")
})

test("how to fix comes from the helper, or from what the fix button does", () => {
  const r = parse(report({ checks: [
    check({ id: "a", howto: "Do this." }),
    check({ id: "b", fix: { kind: "terminal", action: "firewall-on", label: "Turn it on" } }),
    check({ id: "c", status: "pass" }),
    check({ id: "d", fix: { kind: "none", action: "", label: "" } })
  ] }))
  assert.equal(M.howTo(r.checks[0]), "Do this.")
  assert.match(M.howTo(r.checks[1]), /^Press Turn it on: Blocks other computers .* It shows what it will do and asks before changing anything\.$/)
  assert.ok(!M.howTo(r.checks[1]).includes("Technical:"))
  assert.equal(M.howTo(r.checks[2]), "")
  assert.equal(M.howTo(r.checks[3]), "")
  assert.equal(parse(report({ checks: [check({ howto: 5 })] })), null)
})

test("pillar rows count what each pillar shows", () => {
  assert.equal(M.pillarCounts(0, 0, 0), "✓ all good")
  assert.equal(M.pillarCounts(2, 1, 3), "2 to fix · 1 to improve · 3 notes")
  assert.equal(M.pillarCounts(0, 0, 1), "1 note")
})


test("run cards: each lists its own schedule; Run all scans ~ but not ~/Downloads again", () => {
  const src = id => ({ id, label: "x", date: "", time: "", state: "never", tried: "" })
  const r = parse(report({ sources: ["downloads-scan", "virus-scan", "firmware", "password-check", "signatures",
                                     "arch-audit", "pending-updates"].map(src) }))
  const all = M.confirmation("full-scan", "all", r)
  assert.equal(all.title, "Run all")
  const steps = all.lines.filter(l => /^\d+\. /.test(l)).map(l => l.replace(/^\d+\. /, "").split(/[:.]/)[0])
  assert.deepEqual(steps, ["ClamAV signatures", "Password check", "Arch security list", "System update check",
                           "Settings checks", "Firmware check", "ClamAV scan of ~"])
  assert.ok(all.lines.some(l => l.includes("notification")))
  const daily = M.confirmation("daily-check", "all", r)
  assert.equal(daily.title, "Run daily check")
  assert.ok(daily.lines.some(l => l.startsWith("2. ClamAV scan of ~/Downloads")))
  assert.ok(!daily.lines.some(l => /password\./.test(l) && !/No password/.test(l)))
  const weekly = M.confirmation("weekly-check", "all", r)
  assert.deepEqual(weekly.lines.slice(1, 3).map(l => l.split(":")[0]), ["1. Firmware check", "2. ClamAV scan of ~"])
  for (const k of ["full-scan", "daily-check", "weekly-check", "update-sources"])
    assert.equal(M.confirmation(k, "all", null), null)
})

test("every terminal says what it does, plainly, then the technical part", () => {
  for (const [id, a] of Object.entries(M.TERMINAL_ACTIONS)) {
    assert.ok(a.what.length >= 2, id)
    assert.ok(!a.what[0].startsWith("Technical:") && !a.what[0].startsWith("Runs:"), id)
    assert.ok(a.what[a.what.length - 1].startsWith("Technical: "), id)
    const script = M.terminalScript(id, TOOLS)
    if (script) assert.match(script, /'(You will be asked for your password\.|No password needed\.)'/, id)
  }
})

test("schedule lines: countdowns with the time, in local time", () => {
  const now = new Date(2026, 9, 12, 10, 0)
  const r = { generatedAt: "2026-10-12T09:58:00+0200", lastRun: { at: "2026-10-12 09:52", ok: true },
              nextUpdate: "2026-10-19 09:52", nextFullScan: "2026-10-12 21:15", nextDaily: "2026-10-13 07:40" }
  assert.deepEqual(M.scheduleLines(r, true, now, 30), [
    "Next daily check: tomorrow at 07:40",
    "Next weekly check: today at 21:15",
    "Next update check: in 7 days"])
  // Already due: it runs at the next background check, 30 minutes after the last one.
  assert.equal(M.scheduleLines(Object.assign({}, r, { nextDaily: "now" }), true, now, 30)[0],
    "Next daily check: today at 10:28")
  assert.equal(M.scheduleLines(Object.assign({}, r, { nextDaily: "" }), true, now, 30).length, 2)  // nothing daily set up
  assert.equal(M.countdown("2026-10-13 08:05", now, null), "tomorrow at 08:05")
  assert.equal(M.countdown("2026-10-12", now, null), "today at 10:00")       // older helper: date only
  assert.equal(M.countdown("", now, null), "")
  assert.deepEqual(M.scheduleLines(r, false, now, 30), ["Automatic updates and scans are off (Vigil settings)."])
  assert.match(M.scheduleLines(Object.assign({}, r, { lastRun: { at: "2026-10-12 09:52", ok: false } }), true, now, 30)[3],
    /could not reach every source/)
  assert.equal(parse(report({ nextFullScan: "2026-10-19 08:00" })).nextFullScan, "2026-10-19 08:00")
  assert.equal(parse(report({ nextDaily: "2026-10-13 08:00" })).nextDaily, "2026-10-13 08:00")
  assert.equal(parse(report({ nextUpdate: "now" })).nextUpdate, "now")
  assert.equal(parse(report({ nextFullScan: "<b>" })), null)
  assert.equal(parse(report({ nextDaily: "<b>" })), null)
})
test("progress lines are validated and worded", () => {
  const p = M.parseProgress(JSON.stringify({ progress: { step: 3, of: 4, doing: "ClamAV scan of ~", done: 500, total: 1000 } }))
  assert.equal(p.fraction, (2 + 0.5) / 4)
  assert.match(M.progressText(p), /^Step 3 of 4: ClamAV scan of ~ \(500 of 1,?000 files\)$/)
  for (const bad of ['{"ok":true}', "nope", JSON.stringify({ progress: { step: 5, of: 4, doing: "x", done: 0, total: 0 } }),
                     JSON.stringify({ progress: { step: 1, of: 1, doing: 7, done: 0, total: 0 } })])
    assert.equal(M.parseProgress(bad), null, bad)
})

test("last run: scans first, then updates, with times", () => {
  const r = parse(report({ generatedAt: "2026-10-12T10:02:00+0000", sources: [
    { id: "signatures", label: "ClamAV virus signatures", date: "2026-10-12", time: "08:00", state: "ok", tried: "" },
    { id: "virus-scan", label: "Virus scan (home folder)", date: "2026-10-11", time: "22:10", state: "ok", tried: "" },
    { id: "password-check", label: "Password check (Full scan button only)", date: "", time: "", state: "never", tried: "" }] }))
  const rows = M.lastRunRows(r, new Date(2026, 9, 12, 10, 5))
  assert.deepEqual(rows.map(x => [x.label, x.value]), [
    ["Scans", ""], ["Settings checks (daily check)", "ran today at 10:02"],
    ["Virus scan (home folder)", "ran yesterday at 22:10"], ["Password check (Full scan button only)", "not run yet"],
    ["Updates", ""], ["ClamAV virus signatures", "updated today at 08:00"]])
})

test("actions run without a terminal unless the tool asks questions", () => {
  assert.equal(M.runMode("update"), "terminal")
  assert.equal(M.runMode("ssh-passphrase"), "terminal")
  assert.equal(M.runMode("screen-lock-default"), "user")
  assert.equal(M.runMode("firewall-on"), "root")
  assert.equal(M.runMode("nope"), "")
  const fw = M.actionPlan("firewall-on", TOOLS, "/home/marc")
  assert.equal(fw.length, 1)
  assert.deepEqual(fw[0].argv.slice(0, 5), ["/usr/bin/pkexec", "/usr/bin/env", "HOME=/home/marc", "/usr/bin/bash", "-c"])
  assert.ok(!fw[0].argv[5].includes("sudo ") && fw[0].argv[5].includes("/usr/bin/ufw --force enable"))
  const ui = M.actionPlan("install-clamui", TOOLS, "/home/marc")
  assert.equal(ui.length, 1)                                                   // from the Arch repositories, as root
  assert.ok(ui[0].asRoot && ui[0].argv[5].includes("pacman -S --needed --noconfirm clamav clamui"))
  assert.deepEqual(M.actionPlan("update", TOOLS, "/home/marc"), [])           // terminal tools have no plan
  assert.deepEqual(M.actionPlan("firewall-on", Object.assign({}, TOOLS, { pkexec: "" }), "/home/marc"), [])
  assert.deepEqual(M.actionPlan("firewall-on", TOOLS, "relative"), [])
  assert.equal(M.stripSudo("sudo a && sudo b | sudo tee x; omarchy-sudo-passwordless"), "a && b | tee x; omarchy-sudo-passwordless")
  for (const id of Object.keys(M.TERMINAL_ACTIONS)) {
    for (const step of M.actionPlan(id, TOOLS, "/home/marc")) {
      const r = spawnSync("bash", ["-n", "-c", step.argv[step.argv.length - 1]])
      assert.equal(r.status, 0, id + ": " + r.stderr)
      // A read loop fed from a file or command is fine; any other read would wait for you.
      const fed = step.argv[step.argv.length - 1].replace(/while IFS= read -r \w+; do[\s\S]*?\ndone < [^\n]+/g, "")
      assert.ok(!/\bread\b/.test(fed), id + " would wait for input")
    }
  }
  const card = M.confirmation("terminal", "firewall-on", null)
  assert.ok(card.lines[card.lines.length - 1].startsWith("Omarchy asks for your password"))
})

test("update check card: lists what updates and where the password comes in", () => {
  const r = parse(report({ sources: [
    { id: "signatures", label: "ClamAV virus signatures", date: "", time: "", state: "never", tried: "" },
    { id: "arch-audit", label: "Arch vulnerability database", date: "", time: "", state: "never", tried: "" }] }))
  const card = M.confirmation("update-sources", "all", r)
  assert.equal(card.title, "Run update check")
  assert.match(card.lines[1], /^1\. ClamAV signatures\. Omarchy asks for your password/)
  assert.match(card.lines[2], /^2\. Arch security list: known holes/)
  assert.ok(card.lines[card.lines.length - 1].startsWith("Technical: "))
  const none = M.confirmation("update-sources", "all", parse(report()))
  assert.match(none.lines[0], /^Nothing to update yet/)
})

test("a scan or update done outside Vigil says so", () => {
  const src = { id: "virus-scan", label: "Virus scan", date: "2026-10-11", time: "21:30", state: "ok", tried: "", by: "ClamUI" }
  assert.equal(M.sourceLine(src, new Date(2026, 9, 12, 10, 0)), "ran yesterday at 21:30 (by ClamUI)")
  assert.equal(parse(report({ sources: [Object.assign({}, src, { by: "Someone" })] })), null)
})

test("missing helpers: a red Install button that names them, and one plan for all", () => {
  assert.equal(M.missingLabel(parse(report())), "")
  const r = parse(report({ missing: ["clamav", "clamui"] }))
  assert.equal(M.missingLabel(r), "MISSING ClamAV, ClamUI. INSTALL")
  assert.deepEqual(parse(report({ missing: ["some-new-helper", "clamav"] })).missing, ["clamav"])
  assert.equal(parse(report({ missing: [{ evil: 1 }] })), null)
  assert.equal(parse(report({ missing: ["clamav", "clamav"] })), null)
  const card = M.confirmation("terminal", "install-helpers", r)
  assert.equal(card.lines[0], "Missing now: ClamAV, ClamUI.")
  const plan = M.actionPlan("install-helpers", TOOLS, "/home/marc")
  assert.equal(plan.length, 1)
  assert.match(plan[0].argv[5], /pacman -S --needed --noconfirm clamav \$c arch-audit osv-scanner fwupd\n/)
  assert.match(plan[0].argv[5], /c=clamui; \[ -d "\$HOME\/\.local\/share\/flatpak\/app\/io\.github\.linx_systems\.ClamUI" \] && c=/)
  assert.ok(!plan[0].argv[5].includes("flathub"))
  assert.equal(M.missingLabel(parse(report({ missing: ["bumblebee"] }))), "MISSING Bumblebee. INSTALL")
})

test("Bumblebee is the version pinned in Vigil, from Perplexity's release on GitHub", () => {
  const body = M.BUMBLEBEE_INSTALL
  assert.ok(!body.includes("api.github.com") && !body.includes("checksums.txt"), "nothing from the network picks it")
  assert.match(body, /^v=\d+\.\d+\.\d+$/m)
  assert.match(body, /https:\/\/github\.com\/perplexityai\/bumblebee\/releases\/download\/v\$\{v\}/)
  assert.match(body, /a=amd64; want=[0-9a-f]{64} ;; aarch64\) a=arm64; want=[0-9a-f]{64} ;;/)
  for (const c of body.split("\n").filter(l => l.includes("/usr/bin/curl"))) {
    assert.match(c, /--proto =https --proto-redir =https --max-time \d+ --max-filesize \d+/)
    assert.match(c, /\| \/usr\/bin\/head -c \d+ > /, "capped while it streams")
  }
  assert.ok(!/\/usr\/local\/bin\/bumblebee (version|scan)/.test(body), "the installed program is never run as root")
  const install = M.actionPlan("install-helpers", TOOLS, "/home/marc")[0].argv[5]
  assert.ok(install.includes(body), "Install uses the same script")
  assert.equal(M.runMode("update-bumblebee"), "root")
})

test("the Bumblebee script installs the pinned archive, and refuses a bad checksum, a link, an oversized or failed download", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-bb-"))
  const bin = path.join(dir, "bin"); mkdirSync(bin)
  const arch = execFileSync("/usr/bin/uname", ["-m"], { encoding: "utf8" }).trim() === "aarch64" ? "arm64" : "amd64"
  const make = (name, link) => {
    const src = path.join(dir, name); mkdirSync(src)
    if (link) symlinkSync("/etc/hostname", path.join(src, "bumblebee"))
    else writeFileSync(path.join(src, "bumblebee"), "#!/bin/sh\necho " + name + "\n", { mode: 0o755 })
    const tgz = path.join(dir, name + ".tar.gz")
    execFileSync("/usr/bin/tar", ["-czf", tgz, "-C", src, "bumblebee"])
    return [tgz, execFileSync("/usr/bin/sha256sum", [tgz], { encoding: "utf8" }).split(" ")[0]]
  }
  // A stand-in for curl: the archive comes from the test folder, on stdout, as curl would send it.
  const curl = path.join(bin, "curl")
  writeFileSync(curl, `#!/bin/bash\n[ -f "${dir}/fail" ] && exit 22\ncat "${dir}/archive.tgz"\n`, { mode: 0o755 })
  const target = path.join(dir, "out", "bumblebee")
  const pinned = /a=amd64; want=([0-9a-f]{64}) ;; aarch64\) a=arm64; want=([0-9a-f]{64})/.exec(M.BUMBLEBEE_INSTALL)
  const run = (archive, sum, opts) => {
    execFileSync("/usr/bin/cp", [archive, path.join(dir, "archive.tgz")])
    if (opts && opts.fail) writeFileSync(path.join(dir, "fail"), ""); else rmSync(path.join(dir, "fail"), { force: true })
    let body = M.BUMBLEBEE_INSTALL.replaceAll("/usr/bin/curl", curl)
      .replaceAll("/usr/local/bin/bumblebee", target).replace("-o root -g root ", "")
      .replace(pinned[arch === "amd64" ? 1 : 2], sum)
    if (opts && opts.small) body = body.replace(/head -c \d+/, "head -c 101").replace(/-gt \d+ \]/, "-gt 100 ]")
    const r = spawnSync("/usr/bin/bash", ["-c", "set -e\n" + body], { encoding: "utf8" })
    return { status: r.status, text: r.stdout + r.stderr }
  }
  const [good, goodSum] = make("good", false)
  let r = run(good, goodSum)
  assert.equal(r.status, 0, r.text); assert.match(r.text, new RegExp("Bumblebee " + M.BUMBLEBEE_VERSION.replaceAll(".", "\\.") + " is installed"))
  assert.equal(readFileSync(target, "utf8"), "#!/bin/sh\necho good\n")
  r = run(good, goodSum)
  assert.equal(r.status, 0, r.text); assert.match(r.text, /already installed/)
  const [other] = make("other", false)
  r = run(other, goodSum)                                                         // archive differs from the pin
  assert.notEqual(r.status, 0); assert.match(r.text, /did not match the checksum/)
  assert.equal(readFileSync(target, "utf8"), "#!/bin/sh\necho good\n")
  const [linked, linkSum] = make("linked", true)
  r = run(linked, linkSum)
  assert.notEqual(r.status, 0); assert.match(r.text, /not a plain program file/)
  r = run(good, goodSum, { small: true })                                         // bigger than the cap
  assert.notEqual(r.status, 0); assert.match(r.text, /too large/)
  r = run(good, goodSum, { fail: true })
  assert.notEqual(r.status, 0); assert.match(r.text, /could not be downloaded/)
  assert.equal(readFileSync(target, "utf8"), "#!/bin/sh\necho good\n")
  rmSync(dir, { recursive: true, force: true })
})

test("an action in the panel shows how far it got; the words come from Vigil, not the output", () => {
  const steps = M.actionPlan("install-helpers", TOOLS, "/home/marc")
  assert.match(steps[0].argv[5], /^set -e\necho VIGIL-STEP 0\n/)
  assert.equal(M.actionProgress("install-helpers", -1, 0, steps).text, "Waiting for your password…")
  assert.equal(M.actionStage("VIGIL-STEP 0\nresolving dependencies\nVIGIL-STEP 2\n"), 2)
  assert.equal(M.actionStage("VIGIL-STEP 7 rm -rf\n VIGIL-STEP 9\nVIGIL-STEP 12\n"), -1)
  const p = M.actionProgress("install-helpers", 3, 0, steps)
  assert.equal(p.text, "Step 3 of 3: Downloading Bumblebee from Perplexity and checking it")
  assert.ok(p.fraction > 0.75 && p.fraction < 0.9)
  assert.equal(M.actionProgress("install-helpers", 0, 0, steps).text, "Working…")
  assert.equal(M.actionProgress("install-helpers", 9, 0, steps).text, "Working…")
  assert.equal(M.actionOutputText("VIGIL-STEP 0\nPackages installed.\nVIGIL-STEP 2\n"), "Packages installed.\n")
  // Every stage is announced, in order, and a failed pacman stops the script.
  const all = steps.map(s => s.argv[s.argv.length - 1]).join("\n")
  assert.deepEqual([...all.matchAll(/^echo VIGIL-STEP ([0-9])$/gm)].map(m => Number(m[1])), [0, 1, 2, 3])
  assert.match(all, /^\/usr\/bin\/pacman -S --needed --noconfirm clamav \$c arch-audit osv-scanner fwupd$/m)
})

test("a scan started elsewhere is followed, and anything odd is refused", () => {
  assert.equal(parse(report()).running, null)
  const r = parse(report({ running: { step: 2, of: 3, doing: "ClamAV scan of ~", done: 5, total: 10 } }))
  assert.equal(r.running.step, 2)
  assert.equal(M.progressText(parse(report({ running: { step: 0, of: 0, doing: "", done: 0, total: 0 } })).running), "Working…")
  for (const bad of ["yes", [1], { step: 5, of: 3, doing: "x", done: 0, total: 0 }])
    assert.equal(parse(report({ running: bad })), null)
  assert.deepEqual(M.parseRunning('{"running":null}'), { running: null })
  assert.equal(M.parseRunning('{"running":{"step":1,"of":2,"doing":"x","done":0,"total":0}}').running.step, 1)
  assert.equal(M.parseRunning('{"running":"x"}'), null)
  assert.equal(M.parseRunning("nope"), null)
})

test("fingerprint setup and removal are Omarchy's own commands, in a terminal", () => {
  for (const [id, tool] of [["fingerprint", "omarchy-setup-security-fingerprint"],
                            ["undo-fingerprint", "omarchy-remove-security-fingerprint"],
                            ["undo-fido2", "omarchy-remove-security-fido2"]]) {
    assert.equal(M.runMode(id), "terminal", id)
    assert.equal(M.terminalAction(id).tool, tool)
    assert.match(M.terminalScript(id, TOOLS), new RegExp("/usr/bin/" + tool))
  }
  const r = parse(report({ checks: [check({ id: "strong-auth", status: "pass",
    undo: { action: "undo-fingerprint", label: "Stop using your fingerprint" } })] }))
  assert.equal(r.checks[0].undo.action, "undo-fingerprint")
  assert.equal(parse(report({ checks: [check({ undo: { action: "fingerprint", label: "x" } })] })), null)
})

test("a stopped run says so", () => {
  assert.deepEqual(M.parseFixResult('{"ok":true,"stopped":true,"message":"Stopped."}'),
                   { ok: true, message: "Stopped.", stopped: true })
  assert.equal(M.parseFixResult('{"ok":true,"message":"Done."}').stopped, false)
  assert.equal(M.parseFixResult('{"ok":true,"stopped":"yes","message":"Done."}').stopped, false)
})

test("hand-over turns off exactly the duplicate schedules, and Undo turns exactly those back on", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-handover-"))
  const home = path.join(dir, "home"), bin = path.join(dir, "bin"), log = path.join(dir, "log")
  const put = (rel, text, mode = 0o644) => {
    const f = path.join(home, rel)
    mkdirSync(path.dirname(f), { recursive: true })
    writeFileSync(f, text, { mode })
    return f
  }
  mkdirSync(bin, { recursive: true })
  for (const name of ["systemctl", "omarchy-plugin-disable", "omarchy-plugin-enable"])
    writeFileSync(path.join(bin, name), `#!/bin/bash\necho "${name} $*" >> "${log}"\n`, { mode: 0o755 })
  const wants = ".config/systemd/user/timers.target.wants/clamui-scheduled-scan.timer"
  put(".config/systemd/user/clamui-scheduled-scan.timer", "[Timer]\n")
  mkdirSync(path.dirname(path.join(home, wants)), { recursive: true })
  symlinkSync("../clamui-scheduled-scan.timer", path.join(home, wants))
  const settings = put(".config/clamui/settings.json", JSON.stringify({ scheduled_scans_enabled: true,
    schedule_time: "02:00", language: "de", schedule_targets: [home + "/Downloads", "~/Documents"] }), 0o600)
  const bee = path.join(dir, "bumblebee")
  writeFileSync(bee, "#!/bin/sh\n", { mode: 0o755 })
  mkdirSync(path.join(home, ".config/omarchy/plugins/io.github.duketopceo.bumblebee"), { recursive: true })
  const shell = put(".config/omarchy/shell.json",
    JSON.stringify({ bar: { layout: { right: [{ id: "io.github.duketopceo.bumblebee" }] } } }))
  const run = (id) => {
    // The Omarchy commands are named by absolute path (not found through PATH),
    // so the stand-ins replace those paths and PATH holds no stand-in.
    const body = M.actionPlan(id, TOOLS, home)[0].argv[2].replaceAll("/usr/bin/systemctl", path.join(bin, "systemctl"))
      .replaceAll("/usr/local/bin/bumblebee", bee).replaceAll("/usr/share/omarchy/bin/", bin + "/")
    return spawnSync("/usr/bin/bash", ["-c", body], { env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  }
  const marks = path.join(home, ".local/state/omarchy-vigil/handed-over")
  let r = run("hand-over-schedules")
  assert.equal(r.status, 0, r.stderr)
  const after = JSON.parse(readFileSync(settings, "utf8"))
  assert.deepEqual(after, { scheduled_scans_enabled: false, schedule_time: "02:00", language: "de",
                            schedule_targets: [home + "/Downloads", "~/Documents"] })
  assert.equal(statSync(settings).mode & 0o777, 0o600)
  assert.deepEqual(readdirSync(marks).sort(), ["bumblebee-plugin", "clamui-setting-native", "clamui-timer"])
  assert.match(readFileSync(log, "utf8"), /systemctl --user disable --now clamui-scheduled-scan.timer\nomarchy-plugin-disable io.github.duketopceo.bumblebee\n/)
  r = run("undo-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(JSON.parse(readFileSync(settings, "utf8")).scheduled_scans_enabled, true)
  assert.match(readFileSync(log, "utf8"), /systemctl --user enable --now clamui-scheduled-scan.timer\nomarchy-plugin-enable io.github.duketopceo.bumblebee\n$/)
  assert.equal(existsSync(marks), false)
  // A plugin you switched off yourself, and a ClamUI schedule already off, are left alone.
  writeFileSync(log, "")
  rmSync(path.join(home, wants))
  writeFileSync(settings, JSON.stringify({ scheduled_scans_enabled: false }))
  writeFileSync(shell, JSON.stringify({ disabledPlugins: ["io.github.duketopceo.bumblebee"], plugins: [{ id: "io.github.duketopceo.bumblebee" }] }))
  r = run("hand-over-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(log, "utf8"), "")
  assert.deepEqual(readdirSync(marks), [])
  // A ClamUI scan that reaches outside the home folder, and the plugin when Vigil has no
  // Bumblebee of its own, are never turned off, whatever the panel was shown.
  symlinkSync("../clamui-scheduled-scan.timer", path.join(home, wants))
  for (const targets of [[home, "/srv"], ["~/../../etc"], [], "x"]) {
    writeFileSync(settings, JSON.stringify({ scheduled_scans_enabled: true, schedule_targets: targets }))
    writeFileSync(shell, JSON.stringify({ plugins: [{ id: "io.github.duketopceo.bumblebee" }] }))
    rmSync(bee)
    r = run("hand-over-schedules")
    assert.equal(r.status, 0, r.stderr)
    assert.equal(readFileSync(log, "utf8"), "", JSON.stringify(targets))
    assert.equal(JSON.parse(readFileSync(settings, "utf8")).scheduled_scans_enabled, true)
    writeFileSync(bee, "#!/bin/sh\n", { mode: 0o755 })
    writeFileSync(shell, JSON.stringify({ disabledPlugins: ["io.github.duketopceo.bumblebee"] }))
  }
  rmSync(path.join(home, wants))
  // Undo with nothing recorded changes nothing.
  r = run("undo-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(log, "utf8"), "")
  rmSync(dir, { recursive: true, force: true })
})

test("with the Vigil weekly scan off, other schedules are not offered for hand-over", () => {
  const r = parse(report({ checks: [check({ id: "other-schedules", category: "detect", status: "info", weight: 0,
    fix: { kind: "terminal", action: "hand-over-schedules", label: "Let Vigil run them" } })] }))
  assert.equal(M.withSettings(r, true).checks[0].status, "info")
  const off = M.withSettings(r, false).checks[0]
  assert.equal(off.status, "na")
  assert.equal(off.fix.kind, "none")
  assert.equal(r.checks[0].status, "info")                      // the parsed report itself is untouched
})

test("virus detections each carry an id for Ignore, and the card says what ignoring means", () => {
  const items = [{ id: "0123456789abcdef", text: "~/Games/dx11.dll: Win.Trojan.Agent-1", ignored: false },
                 { id: "", text: "~/old.exe: Win.X-1", ignored: false }]
  const r = parse(report({ checks: [check({ id: "virus-scan", category: "detect", items })] }))
  assert.deepEqual(r.checks[0].items, items.map(i => Object.assign({ kind: "detection", kept: false }, i)))
  assert.equal(parse(report()).checks[0].items.length, 0)
  const card = M.confirmation("ignore", "0123456789abcdef", r)
  assert.equal(card.title, "Mark this as a false positive?")
  assert.equal(card.lines[0], "~/Games/dx11.dll: Win.Trojan.Agent-1")
  assert.ok(card.lines.some(l => /changes, Vigil reports it again/.test(l)))
  assert.equal(M.confirmation("ignore", "ffffffffffffffff", r), null)          // not in the report
  for (const bad of [{ id: "XYZ", text: "x", ignored: false }, { id: "", text: "x" },
                     { id: "../../etc/passwd", text: "x", ignored: true }])
    assert.equal(parse(report({ checks: [check({ items: [bad] })] })), null)
})


function leftoverReport(items) {
  return parse(report({ checks: [check({ id: "leftovers", category: "care", status: "info", weight: 0,
    title: "Leftover app data", fix: { kind: "docs", action: "arch-xdg", label: "Learn more" }, items })] }))
}

test("leftovers each carry Move to trash and Keep, and the cards say it goes to the trash", () => {
  const items = [
    { id: "0123456789abcdef", kind: "leftover", text: "~/.config/Slack: 210.0 MB, no installed app uses it", kept: false, ignored: false },
    { id: "fedcba9876543210", kind: "leftover", text: "~/.var/app/com.spotify.Client: 1.2 GB, data of a Flatpak app that is no longer installed", kept: true, ignored: false },
    { id: "00000000000000aa", kind: "leftover", text: "~/.local/bin/old: 0 B, a link to a program that is gone", kept: false, ignored: false }]
  const r = leftoverReport(items)
  assert.deepEqual(r.checks[0].items, items)
  assert.deepEqual(M.leftoverTrashIds(r), ["0123456789abcdef", "00000000000000aa"])     // kept ones stay

  const one = M.confirmation("trash", "0123456789abcdef", r, "/home/a")
  assert.equal(one.title, "Move this to the trash?")
  assert.equal(one.lines[0], items[0].text)
  assert.ok(one.lines.some(l => /choose Restore/.test(l)))
  assert.ok(one.lines.some(l => /deletes it for good/.test(l) && /Clean all/.test(l)))
  assert.deepEqual(one.commands, [])
  assert.equal(M.confirmation("trash", "fedcba9876543210", r), null)        // kept: no trash card
  assert.equal(M.confirmation("trash", "ffffffffffffffff", r), null)        // not in the report
  assert.equal(M.confirmation("ignore", "0123456789abcdef", r), null)       // a leftover is not a detection

  const all = M.confirmation("trash-all", "leftovers", r)
  assert.equal(all.title, "Move 2 items to the trash?")
  assert.deepEqual(all.lines.slice(0, 2), [items[0].text, items[2].text])
  assert.ok(all.lines.some(l => /marked Keep stay/.test(l)))
  assert.ok(!all.lines.some(l => /Spotify|spotify/.test(l)))
  assert.equal(M.confirmation("trash-all", "leftovers", leftoverReport([items[1]])), null)
  assert.equal(M.docsUrl("arch-xdg"), "https://wiki.archlinux.org/title/XDG_Base_Directory")
})

test("leftover items that do not match the shape reject the report", () => {
  const ok = { id: "0123456789abcdef", kind: "leftover", text: "x", kept: false, ignored: false }
  for (const bad of [Object.assign({}, ok, { id: "" }), Object.assign({}, ok, { kept: "no" }),
                     Object.assign({}, ok, { kept: undefined }), Object.assign({}, ok, { ignored: true }),
                     Object.assign({}, ok, { kind: "file" }), Object.assign({}, ok, { id: "../.ssh" }),
                     { id: "0123456789abcdef", text: "x", ignored: false, kept: true }])
    assert.equal(leftoverReport([bad]), null, JSON.stringify(bad))
})

test("each tab's caption shows its most urgent count; Overview sums the security pillars, never Care", () => {
  const c = (category, status, extra = {}) => check(Object.assign({ id: category + "-" + status + Math.random().toString(16).slice(2, 8),
    category, status, weight: 0, fix: { kind: "none", action: "", label: "" } }, extra))
  const r = parse(report({ checks: [c("harden", "fail", { weight: 3 }), c("harden", "warn", { weight: 1 }), c("detect", "info"),
    c("supply", "warn", { weight: 1 }), c("supply", "info"), c("privacy", "pass"), c("care", "warn"), c("care", "info"),
    c("care", "pass"), c("privacy", "warn", { weight: 1, dismissible: true, dismissed: true })] }))
  const cap = (tab) => { const x = M.tabCaption(r, tab); return [x.count, x.label, x.tone] }
  assert.deepEqual(cap("overview"), ["1", "to fix", "urgent"])
  assert.deepEqual(cap("harden"), ["1", "to fix", "urgent"])
  assert.deepEqual(cap("detect"), ["1", "note", "dim"])
  assert.deepEqual(cap("supply"), ["1", "to improve", "warn"])
  assert.deepEqual(cap("privacy"), ["\u2713", "all good", "dim"])         // a reviewed warning does not count
  assert.deepEqual(cap("care"), ["2", "to tidy", "warn"])                 // Care never says "to fix"
  assert.equal(M.tabCaption(r, "harden").text, "1 to fix")
  assert.equal(M.tabCaption(null, "harden").text, "")
  assert.equal(M.tabCounts(r, "overview"), "Security: 1 to fix \u00b7 2 to improve \u00b7 2 notes")
  assert.equal(M.tabCounts(r, "care"), "1 to improve \u00b7 1 note")
  const tidy = parse(report({ checks: [c("care", "pass"), c("harden", "info")] }))
  assert.deepEqual([M.tabCaption(tidy, "care").count, M.tabCaption(tidy, "care").label], ["\u2713", "tidy"])
  assert.deepEqual([M.tabCaption(tidy, "overview").count, M.tabCaption(tidy, "overview").label], ["1", "note"])
})

test("the Overview, the Care tab and the run cards say Care is never part of a run", () => {
  assert.match(M.CARE_NOTE, /never counts toward the score/)
  assert.match(M.CARE_NOTE, /only when you press a button on the Care tab/)
  assert.match(M.CARE_TAB_NOTE, /not part of the score or of the daily, weekly and update checks/)
  const r = parse(report())
  for (const kind of ["daily-check", "full-scan"])
    assert.ok(M.confirmation(kind, "all", r, "/home/a").lines.includes(M.CARE_RUN_LINE), kind)
})

test("on the Care tab, what Clean all leaves alone comes last, under its own heading", () => {
  const care = (id, status) => check({ id, category: "care", status, weight: 0, title: id, fix: { kind: "none", action: "", label: "" } })
  const r = parse(report({ checks: [care("leftovers", "info"), care("orphans", "info"), care("trash", "pass"),
    care("thumbnails", "warn"), care("journal", "info"), care("pacman-cache", "pass")] }))
  const rows = M.checksFor(r, "care")
  assert.deepEqual(rows.slice(-2).map(c => c.id), ["orphans", "leftovers"])
  assert.deepEqual(rows.map((c, i) => M.rowHeading(rows, i)), ["IN CLEAN ALL", "", "", "", M.CARE_SEPARATE_HEADING, ""])
  assert.deepEqual(rows.map((c, i) => M.rowHeadingNote(rows, i)), ["", "", "", "", M.CARE_SEPARATE_NOTE, ""])
  assert.equal(M.CARE_SEPARATE_HEADING, "NOT IN CLEAN ALL")
  assert.match(M.CARE_SEPARATE_NOTE, /Clean all never touches these/)
  // Only Care: another tab never gets the heading.
  const h = parse(report({ checks: [check({ id: "orphans", category: "harden" })] }))
  assert.equal(M.rowHeading(M.checksFor(h, "harden"), 0), "")
  assert.equal(M.rowHeading(rows, 99), "")
  // And Clean all never offers them, whatever they say.
  assert.ok(!M.cleanAllPlan(r).items.some(l => /orphans|leftovers/.test(l)))
})

test("pillar tabs head each group of rows with the check that brings it in, when there is more than one", () => {
  const h = (id, status = "warn") => check({ id, category: "harden", status, weight: 1 })
  const r = parse(report({ checks: [h("firmware"), h("firewall"), h("updates"), h("ssh-keys", "pass"), h("flatpak-apps")] }))
  const rows = M.checksFor(r, "harden")
  assert.deepEqual(rows.map(c => c.id), ["firewall", "ssh-keys", "updates", "flatpak-apps", "firmware"])
  assert.deepEqual(rows.map((c, i) => M.rowHeading(rows, i)), ["SETTINGS CHECKS", "", "DAILY CHECK", "", "WEEKLY CHECK"])
  const one = M.checksFor(parse(report({ checks: [h("firewall"), h("ssh-keys")] })), "harden")
  assert.deepEqual(one.map((c, i) => M.rowHeading(one, i)), ["", ""])        // one group: no heading
  assert.match(M.tabIntro("detect").text, /ClamAV/)
  assert.doesNotMatch(M.tabIntro("detect").text, /rootkit/)
})

test("each run button says when its check next runs by itself", () => {
  const now = new Date(2026, 9, 12, 10, 0)
  const r = { generatedAt: "2026-10-12T09:58:00+0200", lastRun: { at: "2026-10-12 09:52", ok: true },
              nextUpdate: "2026-10-19 09:52", nextFullScan: "2026-10-12 21:15", nextDaily: "now" }
  assert.deepEqual(M.runCaptions(r, true, now, 30),
    { daily: "next\ntoday 10:28", weekly: "next\ntoday 21:15", update: "next\nin 7 days", all: "all three\nnow" })
  assert.deepEqual(M.runCaptions(r, false, now, 30),
    { daily: "by hand\nonly", weekly: "by hand\nonly", update: "by hand\nonly", all: "all three\nnow" })
  assert.equal(M.runCaptions(Object.assign({}, r, { nextUpdate: "" }), true, now, 30).update, "")
  assert.deepEqual(M.scheduleNotes(r, true), [])
  assert.match(M.scheduleNotes(r, false)[0], /only when you press a button/)
  assert.match(M.scheduleNotes(Object.assign({}, r, { lastRun: { at: "x", ok: false } }), true)[0], /every source/)
})

test("the title line does not repeat the Overview's score, and key hints fit the tab", () => {
  const now = new Date(2026, 9, 12, 10, 0)
  const r = parse(report({ generatedAt: "2026-10-12T09:58:00+0200" }))
  assert.equal(M.heroMeta(r, "overview", false, now), "Checked today at 09:58")
  assert.equal(M.heroMeta(r, "harden", false, now), "Needs attention \u00b7 70/100")
  assert.equal(M.heroMeta(r, "overview", true, now), "Checking\u2026")
  assert.equal(M.heroMeta(null, "harden", false, now), "Not checked yet")
  assert.match(M.keyHints("overview", "0.30.0"), /R run all/)
  assert.doesNotMatch(M.keyHints("overview", ""), /F fix/)
  assert.match(M.keyHints("care", ""), /C clean all/)
  assert.doesNotMatch(M.keyHints("harden", ""), /C clean all/)
})

test("after an update, the panel names the new version instead of failing", () => {
  const manifest = JSON.parse(readFileSync(path.join(here, "..", "manifest.json"), "utf8"))
  assert.equal(M.VERSION, manifest.version)
  const helper = readFileSync(path.join(here, "..", "bin", "vigil"), "utf8")
  assert.match(helper, new RegExp('^VERSION = "' + M.VERSION.replaceAll(".", "\\.") + '"$', "m"))
  const text = JSON.stringify(report({ version: "9.9.9" }))
  assert.equal(M.reportVersion(text), "9.9.9")
  assert.equal(M.reportVersion('{"version": "<b>1</b>"}'), "")
  assert.equal(M.reportVersion("nope"), "")
})

test("a rejected report says which part failed", () => {
  const bad = report({ checks: [check({ id: "firmware", status: "superb" })] })
  assert.equal(parse(bad), null)
  assert.equal(M.reportProblem(JSON.stringify(bad)), "the firmware check")
  assert.equal(M.reportProblem(JSON.stringify(report({ lastRun: { at: "now", ok: true } }))), "the last update")
  assert.equal(M.reportProblem("{"), "it was not JSON")
  assert.equal(M.reportProblem(JSON.stringify(report({ checks: [check({ id: "<script>" , status: "x"})] }))), "the ? check")
})

test("the progress bar gives the long virus scan most of its length", () => {
  const p = M.parseProgress(JSON.stringify({ progress: { step: 9, of: 9, doing: "ClamAV scan of ~",
    done: 5082, total: 172762, at: 0.2, span: 0.8 } }))
  assert.ok(p.fraction > 0.2 && p.fraction < 0.25, String(p.fraction))          // 3% of the scan, not 89% of the bar
  const old = M.parseProgress(JSON.stringify({ progress: { step: 9, of: 9, doing: "x", done: 0, total: 0 } }))
  assert.ok(Math.abs(old.fraction - 8 / 9) < 1e-9)                              // no shares given: as before
  const bad = M.parseProgress(JSON.stringify({ progress: { step: 1, of: 2, doing: "x", done: 0, total: 0, at: 0.9, span: 0.9 } }))
  assert.equal(bad.fraction, 0)                                                // shares that do not fit are ignored
})

test("Stop auto-joining touches only open and WEP networks, and Undo only those", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-wifi-"))
  const home = path.join(dir, "home"); mkdirSync(home)
  const log = path.join(dir, "log"); writeFileSync(log, "")
  const U = (n) => `0000000${n}-0000-4000-8000-00000000000${n}`
  // A stand-in for nmcli: four saved networks.
  const nets = { [U(1)]: ["Cafe", "", "yes"], [U(2)]: ["Home", "wpa-psk", "yes"], [U(3)]: ["Old router", "none", "yes"],
                 [U(4)]: ["Airport", "", "no"], [U(5)]: ["Station", "owe", "yes"] }
  const fake = path.join(dir, "nmcli")
  writeFileSync(fake, `#!/bin/bash
case "$*" in
  "-t -f UUID,TYPE,AUTOCONNECT connection show")
${Object.entries(nets).map(([u, n]) => `    echo "${u}:802-11-wireless:${n[2]}"`).join("\n")}
    echo "not-a-uuid:802-11-wireless:yes"; echo "${U(6)}:ethernet:yes" ;;
  "-g 802-11-wireless-security.key-mgmt connection show "*)
    case "$5" in
${Object.entries(nets).map(([u, n]) => `      ${u}) echo "${n[1]}" ;;`).join("\n")}
    esac ;;
  *) echo "nmcli $*" >> "${log}" ;;
esac
`, { mode: 0o755 })
  const run = (id) => {
    const body = M.actionPlan(id, TOOLS, home)[0].argv[2].replaceAll("/usr/bin/nmcli", fake)
    return spawnSync("/usr/bin/bash", ["-c", body], { env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  }
  let r = run("wifi-autojoin-off")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(log, "utf8"),
    `nmcli connection modify ${U(1)} connection.autoconnect no\nnmcli connection modify ${U(3)} connection.autoconnect no\n`)
  assert.match(r.stdout, /Stopped auto-joining 2 open network/)
  writeFileSync(log, "")
  r = run("undo-wifi-autojoin")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(log, "utf8"),
    `nmcli connection modify ${U(1)} connection.autoconnect yes\nnmcli connection modify ${U(3)} connection.autoconnect yes\n`)
  assert.equal(existsSync(path.join(home, ".local/state/omarchy-vigil/wifi-autojoin-off")), false)
  writeFileSync(log, "")
  r = run("undo-wifi-autojoin")
  assert.match(r.stdout, /Nothing to undo/); assert.equal(readFileSync(log, "utf8"), "")
  rmSync(dir, { recursive: true, force: true })
})


test("every Last run row names a schedule line, and the helper lists them in schedule order", () => {
  const helper = readFileSync(path.join(here, "..", "bin", "vigil"), "utf8")
  const body = helper.slice(helper.indexOf("def source_status"), helper.indexOf("def feeds_updated"))
  const order = [...body.matchAll(/\b(DAILY|WEEKLY|UPDATE|Run all only)\b/g)].map(m => m[1])
  // Scans, then updates, each in schedule order (the password check, which
  // follows no schedule line, ends the scans).
  assert.equal(order.join(" "), "DAILY DAILY WEEKLY WEEKLY Run all only DAILY UPDATE UPDATE")
  for (const line of M.scheduleLines({ generatedAt: "2026-10-12T09:58:00+0200", lastRun: { at: "", ok: true },
      nextUpdate: "2026-10-19 09:52", nextFullScan: "2026-10-12 21:15", nextDaily: "2026-10-13 07:40" },
      true, new Date(2026, 9, 12, 10, 0), 30)) {
    const name = /^Next (\w+ check):/.exec(line)[1]
    assert.ok(helper.includes('" (' + name + ')"'), name + " is not a Last run suffix")
  }
})

test("tab rows: settings checks, then daily, weekly and update check rows, worst first in each", () => {
  const c = (id, status, weight) => ({ id, category: "detect", status, weight: weight || 1, dismissed: false })
  const r = { checks: [c("scanner-clamav", "pass"), c("firmware", "warn"), c("virus-scan", "pass"),
                       c("aur-status", "fail"), c("screen-lock", "pass"), c("firewall", "fail")] }
  assert.deepEqual(M.checksFor(r, "detect").map(x => x.id),
    ["firewall", "screen-lock", "virus-scan", "firmware", "aur-status", "scanner-clamav"])  // update check: worst first
})

test("Add a passphrase never puts SSH key file names in a program's arguments", () => {
  // /proc/<pid>/cmdline is readable by every account; ssh-keygen -p sits there
  // waiting for the passphrase. Stand-ins record their arguments and read the
  // key through descriptor 3, which is how the real ssh-keygen opens it.
  const home = mkdtempSync(path.join(tmpdir(), "vigil-ssh-"))
  const ssh = path.join(home, ".ssh"); mkdirSync(ssh, { mode: 0o700 })
  writeFileSync(path.join(ssh, "id_work_secret_project"), "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", { mode: 0o600 })
  writeFileSync(path.join(ssh, "known_hosts"), "github.com ssh-ed25519 AAAA\n")
  const log = path.join(home, "argv.log")
  const bin = path.join(home, "bin"); mkdirSync(bin)
  const keygen = path.join(bin, "ssh-keygen"), grep = path.join(bin, "grep")
  writeFileSync(keygen, `#!/bin/bash\necho "ssh-keygen $*" >> "${log}"\nhead -c 40 /proc/self/fd/3 >> "${log}"\necho >> "${log}"\nexit 0\n`, { mode: 0o755 })
  writeFileSync(grep, `#!/bin/bash\necho "grep $*" >> "${log}"\nexec /usr/bin/grep "$@"\n`, { mode: 0o755 })
  const body = M.TERMINAL_ACTIONS["ssh-passphrase"].run
    .replaceAll("/usr/bin/ssh-keygen", keygen).replaceAll("/usr/bin/grep", grep)
  const r = spawnSync("/usr/bin/bash", ["-c", body], { encoding: "utf8", env: { HOME: home, PATH: "/usr/bin:/bin" } })
  assert.equal(r.status, 0, r.stderr)
  const seen = readFileSync(log, "utf8")
  assert.ok(!seen.includes("id_work_secret_project") && !seen.includes(".ssh"), seen)
  assert.match(seen, /^ssh-keygen -y -P {2}-f \/proc\/self\/fd\/3\n-----BEGIN OPENSSH PRIVATE KEY-----/m)   // the key itself, by descriptor
  assert.match(seen, /^ssh-keygen -p -f \/proc\/self\/fd\/3$/m)
  assert.equal((seen.match(/^ssh-keygen -p /gm) || []).length, 1)                                        // known_hosts is not a key
  rmSync(home, { recursive: true, force: true })
})

// A home with ClamUI's schedule, its timer, Vigil's Bumblebee and the Bumblebee
// plugin, and stand-ins for systemctl and Omarchy's plugin commands.
function handoverHome() {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-handover-"))
  const home = path.join(dir, "home"), bin = path.join(dir, "bin"), log = path.join(dir, "log")
  mkdirSync(bin, { recursive: true }); writeFileSync(log, "")
  for (const name of ["systemctl", "omarchy-plugin-disable", "omarchy-plugin-enable"])
    writeFileSync(path.join(bin, name), `#!/bin/bash\necho "${name} $*" >> "${log}"\n`, { mode: 0o755 })
  const put = (rel, text, mode = 0o644) => {
    const f = path.join(home, rel)
    mkdirSync(path.dirname(f), { recursive: true })
    writeFileSync(f, text, { mode })
    return f
  }
  put(".config/systemd/user/clamui-scheduled-scan.timer", "[Timer]\n")
  const wants = path.join(home, ".config/systemd/user/timers.target.wants/clamui-scheduled-scan.timer")
  mkdirSync(path.dirname(wants), { recursive: true })
  symlinkSync("../clamui-scheduled-scan.timer", wants)
  const settings = put(".config/clamui/settings.json",
    JSON.stringify({ scheduled_scans_enabled: true, schedule_targets: ["~/Downloads"] }), 0o600)
  const bee = path.join(dir, "bumblebee"); writeFileSync(bee, "#!/bin/sh\n", { mode: 0o755 })
  mkdirSync(path.join(home, ".config/omarchy/plugins/io.github.duketopceo.bumblebee"), { recursive: true })
  put(".config/omarchy/shell.json", JSON.stringify({ plugins: [{ id: "io.github.duketopceo.bumblebee" }] }))
  const run = (id) => {
    const body = M.actionPlan(id, TOOLS, home)[0].argv[2].replaceAll("/usr/bin/systemctl", path.join(bin, "systemctl"))
      .replaceAll("/usr/local/bin/bumblebee", bee).replaceAll("/usr/share/omarchy/bin/", bin + "/")
    return spawnSync("/usr/bin/bash", ["-c", body], { env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  }
  const state = path.join(home, ".local/state/omarchy-vigil")
  return { dir, home, log, put, settings, run, state, marks: path.join(state, "handed-over"),
           logged: () => readFileSync(log, "utf8"), on: (f) => JSON.parse(readFileSync(f, "utf8")).scheduled_scans_enabled }
}

test("hand-over leaves ClamUI alone when another of its schedules reaches outside the home folder", () => {
  const h = handoverHome()
  // Both ClamUI installs share one timer. The Arch one scans only ~/Downloads,
  // but the Flatpak one also scans /srv: turning the timer off would stop that too.
  const flat = h.put(".var/app/io.github.linx_systems.ClamUI/config/clamui/settings.json",
    JSON.stringify({ scheduled_scans_enabled: true, schedule_targets: ["~/Pictures", "/srv"] }), 0o600)
  let r = h.run("hand-over-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /ClamUI: left as it is/)
  assert.ok(!/clamui|systemctl/.test(h.logged()), h.logged())
  assert.equal(h.on(h.settings), true); assert.equal(h.on(flat), true)
  assert.deepEqual(readdirSync(h.marks), ["bumblebee-plugin"])                  // the plugin still hands over
  h.put(".config/omarchy/shell.json", JSON.stringify({ disabledPlugins: ["io.github.duketopceo.bumblebee"] }))
  // A settings file that cannot be checked (not JSON, or a link) also keeps ClamUI as it is.
  for (const bad of ["not json", "link"]) {
    rmSync(flat)
    if (bad === "link") symlinkSync(h.settings, flat); else writeFileSync(flat, bad)
    writeFileSync(h.log, "")
    r = h.run("hand-over-schedules")
    assert.equal(r.status, 0, r.stderr)
    assert.equal(h.logged(), "", bad)
    assert.equal(h.on(h.settings), true, bad)
  }
  // A Flatpak ClamUI with its schedule off does not hold back the Arch one.
  rmSync(flat); writeFileSync(flat, JSON.stringify({ scheduled_scans_enabled: false, schedule_targets: ["/srv"] }))
  r = h.run("hand-over-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.match(h.logged(), /systemctl --user disable --now clamui-scheduled-scan.timer/)
  assert.equal(h.on(h.settings), false); assert.equal(h.on(flat), false)
  rmSync(h.dir, { recursive: true, force: true })
})

test("hand-over and its Undo refuse links planted in their way", () => {
  const h = handoverHome()
  const victim = path.join(h.dir, "victim")
  writeFileSync(victim, "must survive")
  // A link at a marker's name is replaced by the marker, never written through.
  mkdirSync(h.marks, { recursive: true })
  symlinkSync(victim, path.join(h.marks, "clamui-timer"))
  let r = h.run("hand-over-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(victim, "utf8"), "must survive")
  for (const m of ["clamui-timer", "clamui-setting-native", "bumblebee-plugin"])
    assert.ok(lstatSync(path.join(h.marks, m)).isFile(), m)
  assert.deepEqual(readdirSync(h.marks).filter(n => n.startsWith(".")), [])  // no temporary left behind
  // ClamUI's settings: edited through a fresh file, so its mode is kept and no link is followed.
  assert.equal(statSync(h.settings).mode & 0o777, 0o600)
  // Undo counts only regular markers: a link there is not a record of a change.
  r = h.run("undo-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(h.on(h.settings), true)
  writeFileSync(h.log, "")
  mkdirSync(h.marks, { recursive: true })
  symlinkSync(victim, path.join(h.marks, "bumblebee-plugin"))
  r = h.run("undo-schedules")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(h.logged(), "")
  assert.equal(readFileSync(victim, "utf8"), "must survive")
  rmSync(h.marks, { recursive: true })
  // A state folder (or one above it) that is a link is refused before anything changes.
  for (const linked of [h.state, path.dirname(h.state)]) {
    const elsewhere = path.join(h.dir, "elsewhere-" + path.basename(linked))
    mkdirSync(elsewhere)
    rmSync(linked, { recursive: true, force: true })
    symlinkSync(elsewhere, linked)
    for (const id of ["hand-over-schedules", "undo-schedules"]) {
      writeFileSync(h.log, "")
      r = h.run(id)
      assert.equal(r.status, 1, id + " " + linked)
      assert.match(r.stdout, /^Refused: .* is a link or not a folder of yours, so nothing was changed\.$/m)
      assert.equal(h.logged(), "", id)
      assert.equal(h.on(h.settings), true, id)
      assert.deepEqual(readdirSync(elsewhere), [], id)
    }
    rmSync(linked)
  }
  rmSync(h.dir, { recursive: true, force: true })
})

test("Stop auto-joining refuses a planted link, keeps earlier records, and records what it changed even if a step fails", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "vigil-wifi-links-"))
  const home = path.join(dir, "home"); mkdirSync(home)
  const log = path.join(dir, "log"); writeFileSync(log, "")
  const U = (n) => `0000000${n}-0000-4000-8000-00000000000${n}`
  const fake = path.join(dir, "nmcli")
  const nets = path.join(dir, "nets")
  writeFileSync(fake, `#!/bin/bash
case "$*" in
  "-t -f UUID,TYPE,AUTOCONNECT connection show") cat "${nets}" ;;
  "-g 802-11-wireless-security.key-mgmt connection show "*) echo "" ;;
  *"${U(9)}"*) exit 1 ;;
  *) echo "nmcli $*" >> "${log}" ;;
esac
`, { mode: 0o755 })
  const run = (id) => spawnSync("/usr/bin/bash", ["-c", M.actionPlan(id, TOOLS, home)[0].argv[2].replaceAll("/usr/bin/nmcli", fake)],
                                { env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  const state = path.join(home, ".local/state/omarchy-vigil"), m = path.join(state, "wifi-autojoin-off")
  writeFileSync(nets, `${U(1)}:802-11-wireless:yes\n`)
  let r = run("wifi-autojoin-off")
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(m, "utf8"), U(1) + "\n")
  // A second run adds to the list, so Undo still restores the first network.
  writeFileSync(nets, `${U(2)}:802-11-wireless:yes\n`)
  r = run("wifi-autojoin-off")
  assert.equal(readFileSync(m, "utf8"), U(1) + "\n" + U(2) + "\n")
  // A step that fails stops the run, but what changed before it is recorded.
  writeFileSync(nets, `${U(3)}:802-11-wireless:yes\n${U(9)}:802-11-wireless:yes\n`)
  r = run("wifi-autojoin-off")
  assert.notEqual(r.status, 0)
  assert.equal(readFileSync(m, "utf8"), U(1) + "\n" + U(2) + "\n" + U(3) + "\n")
  assert.deepEqual(readdirSync(state).filter(n => n.startsWith(".")), [])
  // A link planted at the list is refused, and the file it points to is untouched.
  const victim = path.join(dir, "victim"); writeFileSync(victim, "must survive")
  rmSync(m); symlinkSync(victim, m)
  writeFileSync(log, ""); writeFileSync(nets, `${U(4)}:802-11-wireless:yes\n`)
  r = run("wifi-autojoin-off")
  assert.equal(r.status, 1)
  assert.match(r.stdout, /^Refused: the list of networks Vigil changed is a link/m)
  assert.equal(readFileSync(log, "utf8"), ""); assert.equal(readFileSync(victim, "utf8"), "must survive")
  r = run("undo-wifi-autojoin")
  assert.match(r.stdout, /Nothing to undo/); assert.equal(readFileSync(log, "utf8"), "")
  // So is a state folder that is a link.
  rmSync(state, { recursive: true })
  const elsewhere = path.join(dir, "elsewhere"); mkdirSync(elsewhere)
  symlinkSync(elsewhere, state)
  for (const id of ["wifi-autojoin-off", "undo-wifi-autojoin"]) {
    r = run(id)
    assert.equal(r.status, 1, id)
    assert.match(r.stdout, /^Refused: /m)
    assert.deepEqual(readdirSync(elsewhere), [], id)
  }
  assert.equal(readFileSync(log, "utf8"), "")
  rmSync(dir, { recursive: true, force: true })
})

test("Add a passphrase shows key names escaped, so a name cannot send control codes to the terminal", () => {
  const home = mkdtempSync(path.join(tmpdir(), "vigil-ssh-names-"))
  const ssh = path.join(home, ".ssh"); mkdirSync(ssh, { mode: 0o700 })
  const evil = "id\x1b]0;pwned\x07\x1b[2J"
  writeFileSync(path.join(ssh, evil), "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", { mode: 0o600 })
  const bin = path.join(home, "bin"); mkdirSync(bin)
  const keygen = path.join(bin, "ssh-keygen")
  writeFileSync(keygen, "#!/bin/bash\nexit 0\n", { mode: 0o755 })
  const body = M.TERMINAL_ACTIONS["ssh-passphrase"].run.replaceAll("/usr/bin/ssh-keygen", keygen)
  const r = spawnSync("/usr/bin/bash", ["-c", body], { encoding: "utf8", env: { HOME: home, PATH: "/usr/bin:/bin", LC_ALL: "C" } })
  assert.equal(r.status, 0, r.stderr)
  assert.ok(!/[\x00-\x08\x0b-\x1f\x7f]/.test(r.stdout), JSON.stringify(r.stdout))
  assert.equal(r.stdout, "Passphrase for ~/.ssh/$'id\\E]0;pwned\\a\\E[2J'\n")
  rmSync(home, { recursive: true, force: true })
})

test("every confirmation shows in full the commands Run starts, root steps included", () => {
  const home = "/home/marc"
  const r = parse(report())
  for (const id of Object.keys(M.TERMINAL_ACTIONS)) {
    const card = M.confirmation("terminal", id, r, home)
    const mode = M.runMode(id)
    if (mode === "terminal") {
      assert.equal(card.commands.length, 1, id)
      assert.ok(M.terminalScript(id, TOOLS).endsWith("( set -e; " + card.commands[0].text + " )"), id)
      continue
    }
    const plan = M.actionPlan(id, TOOLS, home)
    assert.equal(card.commands.length, plan.length, id)
    plan.forEach((step, i) => {
      const shown = card.commands[i]
      // The whole argv, the script last and unabridged.
      assert.equal(shown.text, step.argv.slice(0, -1).join(" ") + "\n" + step.argv[step.argv.length - 1], id)
      assert.equal(/^As root, through pkexec/.test(shown.who), step.asRoot, id)
    })
    if (mode === "root") assert.ok(card.commands[0].text.startsWith("/usr/bin/pkexec /usr/bin/env HOME=/home/marc /usr/bin/bash -c\n"), id)
  }
  // Helper actions run Vigil's own code as you: nothing to show as a command.
  assert.deepEqual(M.confirmation("helper", "ssh-perms", r, home).commands, [])
  // The plugin commands are named by absolute path in what the card shows.
  const hand = M.confirmation("terminal", "hand-over-schedules", r, home).commands[0].text
  assert.match(hand, /^omarchy_plugin_disable=\/usr\/share\/omarchy\/bin\/omarchy-plugin-disable$/m)
  assert.ok(!/^\s*omarchy-plugin-disable /m.test(hand))
  const missing = M.confirmation("terminal", "hand-over-schedules", parse(report({ tools: { pkexec: "/usr/bin" } })), home)
  assert.match(missing.commands[0].text, /^omarchy_plugin_disable=$/m)               // not found: that step is skipped
})

test("run cards show the helper's root steps exactly as the helper starts them", () => {
  const sig = { id: "signatures", label: "ClamAV signatures", date: "", time: "", state: "never", tried: "" }
  const older = check({ id: "bumblebee", category: "supply", status: "info", weight: 0,
                        fix: { kind: "terminal", action: "update-bumblebee", label: "Update Bumblebee" } })
  const card = (kind, over) => M.confirmation(kind, "all", parse(report(over)), "/home/marc").commands
  assert.deepEqual(card("update-sources", {}), [])                                       // nothing runs as root
  let c = card("update-sources", { sources: [sig] })
  assert.equal(c.length, 1)
  assert.equal(c[0].text, "/usr/bin/pkexec /usr/bin/bash -c\n" + M.rootUpdatesScript(true, false))
  assert.ok(c[0].text.includes(M.SIGNATURES_SCRIPT) && !c[0].text.includes(M.BUMBLEBEE_INSTALL))
  c = card("update-sources", { sources: [sig], checks: [check(), older] })
  assert.equal(c[0].text, "/usr/bin/pkexec /usr/bin/bash -c\n" + M.rootUpdatesScript(true, true))
  assert.ok(c[0].text.includes(M.BUMBLEBEE_INSTALL))
  c = card("full-scan", { checks: [check(), older] })
  assert.equal(c.length, 2)
  assert.equal(c[0].text, "/usr/bin/pkexec /usr/bin/bash -c\n" + M.rootUpdatesScript(false, true))
  assert.equal(c[1].text, "/usr/bin/pkexec /usr/bin/bash -c\n" + M.NO_PASSWORD_STEP)
  assert.deepEqual(card("full-scan", { tools: {} }), [])                                 // no pkexec: no root step
  assert.deepEqual(card("daily-check", {}), [])
  assert.deepEqual(card("weekly-check", {}), [])
  // Clean all: the root half, in full.
  const care = parse(report({ checks: [check({ id: "journal", category: "care", status: "info", weight: 0,
    fix: { kind: "terminal", action: "clean-journal", label: "Keep two weeks" } })] }))
  const clean = M.confirmation("clean-all", "care", care, "/home/marc").commands
  assert.equal(clean.length, 1)
  assert.equal(clean[0].text, M.actionPlan("clean-system", TOOLS, "/home/marc")[0].argv.slice(0, -1).join(" ")
    + "\n" + M.actionPlan("clean-system", TOOLS, "/home/marc")[0].argv[5])
})
