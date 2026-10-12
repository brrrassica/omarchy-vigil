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
  "omarchy-setup-security-usb-authorization": "/usr/bin",
  "omarchy-setup-security-thunderbolt-authorization": "/usr/bin",
  "omarchy-setup-security-fido2": "/usr/bin",
  "omarchy-sudo-passwordless": "/usr/bin",
  "omarchy-remove-security-sudoless-docker": "/usr/bin",
  "omarchy-update": "/usr/bin",
  "omarchy-pkg-add": "/usr/share/omarchy/bin",
  "omarchy-update-orphan-pkgs": "/usr/bin",
  "omarchy-toggle-idle": "/usr/bin"
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
  assert.equal(parse(report({ checks: Array.from({ length: 81 }, (_, i) => check({ id: "c" + i })) })), null)
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
  assert.match(M.terminalScript("install-lynis", TOOLS), /\/usr\/share\/omarchy\/bin\/omarchy-pkg-add lynis/)
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

import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync } from "node:fs"
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
  assert.equal(parse(report({ checks: [check({ status: "fail", dismissible: true, dismissed: true })] })), null)
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
