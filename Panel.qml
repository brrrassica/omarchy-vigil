import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Vigil: a lighthouse in the bar and a panel with five tabs.
//
// All the checking is done by bin/vigil, run as an argv array with a cleared
// environment. Its stdout is read in raw chunks with a hard size limit and
// validated by Model.parseReport before anything is shown. Nothing here
// builds a shell string from data: helper actions are fixed ids, and every
// other action is a constant script from Model.js, shown in full on the
// confirmation card before it runs.
Panel {
  id: root
  moduleName: "keasbeexd.vigil"
  ipcTarget: "keasbeexd.vigil"
  manageIpc: false

  readonly property int maxReportChars: 512 * 1024
  readonly property int maxFixChars: 4096
  readonly property string helperPath: localPath(Qt.resolvedUrl("bin/vigil"))
  readonly property var helperEnv: ({
    "HOME": Quickshell.env("HOME") || "/",
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8"
  })

  // Actions get only what their scripts and Omarchy's tools need: your home,
  // a fixed PATH (with Omarchy's commands), Omarchy's location, and the
  // session variables its shell and password dialog use.
  readonly property var actionEnv: ({
    "HOME": Quickshell.env("HOME") || "/",
    "PATH": "/usr/share/omarchy/bin:/usr/bin:/bin",
    "OMARCHY_PATH": Quickshell.env("OMARCHY_PATH") || "/usr/share/omarchy",
    "XDG_RUNTIME_DIR": Quickshell.env("XDG_RUNTIME_DIR") || "",
    "WAYLAND_DISPLAY": Quickshell.env("WAYLAND_DISPLAY") || "",
    "DBUS_SESSION_BUS_ADDRESS": Quickshell.env("DBUS_SESSION_BUS_ADDRESS") || "",
    "LANG": "C.UTF-8"
  })

  readonly property int refreshMinutes: {
    var n = Number(setting("refreshMinutes", 30))
    return isFinite(n) ? Math.max(5, Math.min(1440, Math.round(n))) : 30
  }
  readonly property bool notifyOnNew: setting("notifyOnNew", true) === true
  // Weekly refresh of the maintained sources (arch-audit, OSV, the AUR).
  readonly property bool autoUpdate: setting("autoUpdate", true) === true
  property var actionSteps: []
  property int actionIndex: 0
  property string actionOutput: ""
  property string actionTitle: ""
  property var actionResult: null          // { title, verdict, ok, output } after an action ran
  property string feedBuffer: ""
  property bool feedOverflow: false
  property string feedResult: ""           // the last non-progress line: the result
  property var scanProgress: null          // the latest progress line, while a run is going
  property bool feedForced: false
  property bool feedFull: false
  property string feedMode: ""
  // One bar per monitor means one copy of this widget per monitor. Only the
  // first screen's copy schedules audits, records findings and notifies.
  readonly property bool isPrimary: root.QsWindow.window !== null
    && root.QsWindow.window.screen === Quickshell.screens[0]

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  // Every colour comes from the Omarchy theme: text, urgent (to fix), accent
  // (to improve) and muted (secondary text, nothing to do).
  // Secondary text (the key hints, times, descriptions): the theme's text
  // colour, darkened, as mouse-ctrl does. The theme's own "muted" colour is
  // close to the background in some themes, which hid this text.
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color warnColor: Commons.Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  property var report: null
  property string auditBuffer: ""
  property bool auditOverflow: false
  property string fixBuffer: ""
  property bool fixOverflow: false
  property string fixAction: ""
  property string statusMessage: ""
  property bool updatePending: false
  property real lastAutoRun: 0
  property bool statusIsError: false

  property string tab: "overview"
  readonly property var tabs: ["overview", "harden", "detect", "supply", "privacy", "care"]
  property int rowIndex: 0
  property bool cursorActive: false
  property string expandedId: ""
  property string pendingKind: ""
  property string pendingAction: ""
  readonly property string homeDir: Quickshell.env("HOME") || ""
  readonly property var pending: pendingAction === "" ? null
    : Model.confirmation(pendingKind, pendingAction, report, homeDir)
  readonly property var cleanPlan: Model.cleanAllPlan(report)

  readonly property var visibleChecks: tab === "overview" ? [] : Model.checksFor(report, tab)
  readonly property bool busy: auditProc.running || fixProc.running || actionProc.running
  // A scan or update this copy did not start (another monitor's, or one left
  // running when the shell restarted). The helper allows one at a time.
  property var otherRun: null
  readonly property bool runElsewhere: !feedProc.running && otherRun !== null
  readonly property var runProgress: feedProc.running ? scanProgress : otherRun
  property string actionId: ""
  property int actionStageNow: -1
  readonly property var actionNow: actionProc.running
    ? Model.actionProgress(actionId, actionStageNow, actionIndex, actionSteps) : null

  function localPath(url) {
    var value = String(url)
    return value.indexOf("file://") === 0 ? decodeURIComponent(value.substring(7)) : value
  }

  function setStatus(text, isError) {
    statusMessage = Model.plain(text, 240)
    statusIsError = isError === true
  }

  // ---- audit

  function runAudit() {
    if (auditProc.running) return
    auditBuffer = ""
    auditOverflow = false
    auditProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath, "audit"]
      .concat(root.isPrimary ? [] : ["--peek"])
    auditProc.running = true
    auditDeadline.restart()
  }

  function finishAudit(code) {
    auditDeadline.stop()
    var text = auditBuffer
    auditBuffer = ""
    if (auditOverflow) { setStatus("The check produced too much output and was stopped.", true); return }
    if (code !== 0) { setStatus("The check did not finish (exit " + code + ").", true); return }
    var parsed = Model.parseReport(text.trim())
    // After an update the helper on disk is new but this panel is the one the
    // shell loaded at start; only a shell restart loads the new panel.
    var helperVersion = Model.reportVersion(text.trim())
    updatePending = helperVersion !== "" && helperVersion !== Model.VERSION
    if (!parsed) {
      if (updatePending) setStatus("Vigil was updated to " + helperVersion + ". Restart the shell to load the new panel.", true)
      else setStatus("The check returned something Vigil could not read (" + Model.reportProblem(text.trim()) + ").", true)
      return
    }
    report = Model.withSettings(parsed, root.autoUpdate)
    otherRun = feedProc.running ? null : parsed.running
    if (statusIsError) setStatus("", false)
    if (updatePending) setStatus("Vigil was updated to " + helperVersion + ". Restart the shell to load the new panel.", false)
    if (rowIndex >= visibleChecks.length) rowIndex = Math.max(0, visibleChecks.length - 1)
    if (root.isPrimary && root.notifyOnNew && parsed.fresh.length > 0) notifyNew(parsed.fresh.length)
    // The automatic run starts at most every six hours, whatever happens to it,
    // so a run that keeps failing can never restart in a loop.
    if (root.isPrimary && root.autoUpdate && parsed.feedsDue && parsed.running === null
        && Date.now() - lastAutoRun > 6 * 3600000) {
      lastAutoRun = Date.now()
      refreshFeeds("")
    }
  }

  // Runs `bin/vigil refresh-feeds` in the background. With no mode (the
  // background run) the helper runs only what is due and retries failures the
  // next day. The buttons: "sources" (Run update check), "daily" (Run daily
  // check), "weekly" (Run weekly check), "full" (Run all); "scan" is the
  // virus scan of the home folder alone (its row's Scan now button).
  readonly property var feedFlags: ({ sources: "--sources", daily: "--daily", weekly: "--weekly", full: "--full",
                                      scan: "--scan" })
  readonly property var feedTitles: ({ sources: "Run update check", daily: "Run daily check",
                                       weekly: "Run weekly check", full: "Run all", scan: "Virus scan" })
  function refreshFeeds(mode) {
    if (feedProc.running || runElsewhere) return
    feedBuffer = ""
    feedResult = ""
    scanProgress = null
    feedOverflow = false
    feedForced = feedFlags.hasOwnProperty(mode)
    feedFull = mode === "full" || mode === "weekly"
    feedMode = mode
    feedProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath, "refresh-feeds"]
      .concat(feedForced ? [feedFlags[mode]] : [])
    feedProc.running = true
    // The update check takes minutes; anything that scans files can take hours.
    feedDeadline.interval = mode === "sources" ? 3600000 : 4 * 3600000
    feedDeadline.restart()
    if (mode === "sources") setStatus("Update check started. Omarchy may ask for your password first.", false)
    else if (mode === "full") setStatus("Run all started. Omarchy may ask for your password first; after that you can close this panel.", false)
    else if (mode === "daily") setStatus("Daily check started.", false)
    else if (mode === "weekly") setStatus("Weekly check started. You can close this panel; you get a notification when it is done.", false)
    else if (mode === "scan") setStatus("Virus scan started. It runs in the background.", false)
  }

  // Every run button asks first, on the usual card, which lists what it runs.
  function requestRun(kind) {
    if (!report || busy || feedProc.running || runElsewhere) return
    pendingKind = kind
    pendingAction = "all"
  }
  function requestUpdate() { requestRun("update-sources") }
  function requestFullScan() { requestRun("full-scan") }

  function requestInstallHelpers() {
    if (!report || busy || feedProc.running || runElsewhere) return
    pendingKind = "terminal"
    pendingAction = "install-helpers"
  }


  function notifyNew(count) {
    var n = Math.max(1, Math.min(99, Math.round(Number(count) || 1)))
    Quickshell.execDetached([
      "/usr/bin/notify-send", "--app-name=Vigil", "--",
      "Vigil",
      n + (n === 1 ? " new security finding." : " new security findings.") + " Open the lighthouse in the bar for details."
    ])
  }

  // ---- actions

  function requestFix(check) {
    if (!check || !report || busy) return
    if (!Model.canRun(check.fix, report.tools, report.apps)) return
    if (check.fix.kind === "helper" && check.fix.action === "virus-scan-now") {
      // A scan of the whole home folder can take a long time: run it like the
      // weekly scan, with progress, rather than as a quick helper action.
      refreshFeeds("scan")
      return
    }
    if (check.fix.kind === "app" || check.fix.kind === "docs") {
      // Opening an app you installed or a guide in the browser changes
      // nothing, so it needs no confirmation.
      var argv = Model.appCommand(check.fix.action, report.apps)
      if (check.fix.kind === "docs") argv = Model.docsCommand(check.fix.action, report.tools)
      if (argv.length > 0) { Quickshell.execDetached(argv); root.close() }
      return
    }
    pendingKind = check.fix.kind
    pendingAction = check.fix.action
  }

  // Clean all asks once, on the same card as every other action.
  function requestCleanAll() {
    if (!report || busy || cleanPlan.items.length === 0) return
    pendingKind = "clean-all"
    pendingAction = "care"
  }

  function cancelPending() {
    pendingKind = ""
    pendingAction = ""
  }

  function confirmPending() {
    var kind = pendingKind
    var action = pendingAction
    cancelPending()
    if (!report) return
    if (kind === "ignore") {
      if (Model.detectionItem(report, action)) runHelper(["ignore", action])
      return
    }
    if (kind === "trash") {
      var left = Model.leftoverItem(report, action)
      if (left && !left.kept) runHelper(["trash", action])
      return
    }
    if (kind === "trash-all") {
      // Exactly the items the card listed: every leftover not kept.
      var ids = Model.leftoverTrashIds(report)
      if (ids.length > 0) runHelper(["trash"].concat(ids))
      return
    }
    if (kind === "update-sources") {
      refreshFeeds("sources")
      return
    }
    if (kind === "full-scan") {
      // No terminal: the password steps use Omarchy's own password dialog,
      // so the panel stays open and shows the progress.
      refreshFeeds("full")
      return
    }
    if (kind === "daily-check" || kind === "weekly-check") {
      refreshFeeds(kind === "daily-check" ? "daily" : "weekly")
      return
    }
    if (kind === "clean-all") {
      var plan = Model.cleanAllPlan(report)
      if (plan.system) startAction("clean-system")
      if (plan.user) runHelper(["fix", "clean-user"])
      return
    }
    if (kind === "helper") {
      if (!Model.isHelperAction(action)) return
      runHelper(["fix", action])
    } else if (kind === "terminal") {
      if (Model.runMode(action) !== "terminal") { startAction(action); return }
      // Only tools that ask you questions as they go still use a terminal.
      var launcher = Model.launcherPath(report.tools)
      var script = Model.terminalScript(action, report.tools)
      if (launcher === "" || script === "") { setStatus("This action is not available on this system.", true); return }
      Quickshell.execDetached([launcher, script])
      setStatus("Opened in a terminal. Vigil checks again when you reopen this panel.", false)
      root.close()
    }
  }

  // Runs an action's steps in the panel, one after the other: root steps
  // through pkexec (Omarchy's password dialog), the rest as you. What they
  // print is shown on the result card afterwards.
  function startAction(id) {
    if (actionProc.running) return
    var steps = Model.actionPlan(id, report.tools, root.homeDir)
    if (steps.length === 0) { setStatus("This action is not available on this system.", true); return }
    var a = Model.terminalAction(id)
    actionSteps = steps
    actionIndex = 0
    actionOutput = ""
    actionTitle = a ? a.title : ""
    actionId = id
    actionStageNow = -1
    actionResult = null
    actionProc.command = steps[0].argv
    actionProc.running = true
    actionDeadline.restart()
    setStatus("", false)
  }

  function finishAction(code) {
    actionDeadline.stop()
    var cancelled = actionSteps[actionIndex] && actionSteps[actionIndex].asRoot && (code === 126 || code === 127)
    if (code === 0 && actionIndex + 1 < actionSteps.length) {
      actionIndex += 1
      actionProc.command = actionSteps[actionIndex].argv
      actionProc.running = true
      actionDeadline.restart()
      return
    }
    actionResult = {
      title: actionTitle,
      verdict: code === 0 ? "Done." : (cancelled ? "Cancelled: no password was given, so nothing changed."
                                                  : "Did not finish. What it printed is below."),
      ok: code === 0,
      output: Model.plain(Model.actionOutputText(actionOutput), 6000)
    }
    setStatus("", false)
    runAudit()
  }

  // Runs bin/vigil with a fixed verb and ids the panel already validated:
  // `fix <helper action>`, `dismiss|undismiss <check id>`, `ignore|unignore <detection id>`,
  // `keep|unkeep <leftover id>`, `trash <leftover id>...`. Ids are hashes the
  // helper made; no file name ever reaches the command line.
  function runHelper(args) {
    if (fixProc.running || args.length < 2) return
    if (["fix", "dismiss", "undismiss", "ignore", "unignore", "keep", "unkeep", "trash"].indexOf(args[0]) === -1) return
    var hashed = ["ignore", "unignore", "keep", "unkeep", "trash"].indexOf(args[0]) !== -1
    if (args.length !== 2 && (args[0] !== "trash" || args.length > 151)) return
    for (var i = 1; i < args.length; i++) {
      if (!/^[a-z0-9-]{1,40}$/.test(args[i])) return
      if (hashed && !/^[0-9a-f]{16}$/.test(args[i])) return
      if (args.indexOf(args[i]) !== i) return
    }
    fixBuffer = ""
    fixOverflow = false
    fixAction = args[1]
    fixProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath].concat(args)
    fixProc.running = true
    fixDeadline.restart()
    setStatus("Working…", false)
  }

  // Marking a warning as reviewed changes no system setting and is undone
  // with one click, so it does not ask first.
  function setReviewed(check, on) {
    if (!check || busy) return
    if (on && (!check.dismissible || check.dismissed)) return
    if (!on && !check.dismissed) return
    runHelper([on ? "dismiss" : "undismiss", check.id])
  }

  // Mark one virus detection as a false positive: asks first, on the usual card.
  function requestIgnore(item) {
    if (!report || busy || !item || item.id === "" || item.ignored) return
    pendingKind = "ignore"
    pendingAction = item.id
  }

  function requestUnignore(item) {
    if (!report || busy || !item || item.id === "" || !item.ignored) return
    runHelper(["unignore", item.id])
  }

  // Leftovers of apps that are gone: Move to trash asks first; Keep and Stop
  // keeping only change Vigil's own notes, so they do not.
  function requestTrash(item) {
    if (!report || busy || !item || item.kind !== "leftover" || item.kept) return
    pendingKind = "trash"
    pendingAction = item.id
  }

  function requestTrashAll() {
    if (!report || busy || Model.leftoverTrashIds(report).length === 0) return
    pendingKind = "trash-all"
    pendingAction = "leftovers"
  }

  function setKept(item, on) {
    if (!report || busy || !item || item.kind !== "leftover" || item.kept === on) return
    runHelper([on ? "keep" : "unkeep", item.id])
  }

  function requestUndo(check) {
    if (!check || !report || busy || check.undo.action === "") return
    if (!Model.canRun({ kind: "terminal", action: check.undo.action }, report.tools, report.apps)) return
    pendingKind = "terminal"
    pendingAction = check.undo.action
  }

  function finishFix(code) {
    fixDeadline.stop()
    var text = fixBuffer
    fixBuffer = ""
    var parsed = (!fixOverflow && code === 0) ? Model.parseFixResult(text.trim()) : null
    if (!parsed) setStatus("The action did not finish.", true)
    else setStatus(parsed.message, !parsed.ok)
    runAudit()
  }

  // ---- navigation

  function selectTab(name) {
    if (tabs.indexOf(name) === -1) return
    tab = name
    rowIndex = 0
    expandedId = ""
    cancelPending()
    if (panelFlick) panelFlick.contentY = 0
  }

  function moveTab(delta) {
    var i = tabs.indexOf(tab)
    selectTab(tabs[(i + delta + tabs.length) % tabs.length])
  }

  function moveRow(delta) {
    if (visibleChecks.length === 0) return
    rowIndex = Math.max(0, Math.min(visibleChecks.length - 1, rowIndex + delta))
    Qt.callLater(scrollRowIntoView)
  }

  function toggleExpanded(check) {
    if (!check) return
    expandedId = expandedId === check.id ? "" : check.id
  }

  function selectedCheck() {
    if (rowIndex < 0 || rowIndex >= visibleChecks.length) return null
    return visibleChecks[rowIndex]
  }

  function scrollRowIntoView() {
    var item = rowsRepeater.itemAt(rowIndex)
    if (!item || !panelFlick) return
    var y = item.mapToItem(column, 0, 0).y
    if (y < panelFlick.contentY) panelFlick.contentY = y
    else if (y + item.height > panelFlick.contentY + panelFlick.height)
      panelFlick.contentY = Math.min(panelFlick.contentHeight - panelFlick.height, y + item.height - panelFlick.height)
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    cancelPending()
    if (!fixProc.running) setStatus("", false)
    if (panelFlick) panelFlick.contentY = 0
    runAudit()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  Component.onDestruction: {
    if (auditProc.running) auditProc.signal(15)
    if (fixProc.running) fixProc.signal(15)
    if (feedProc.running) feedProc.signal(15)
  }

  // ---- processes

  Process {
    id: auditProc
    clearEnvironment: true
    environment: root.helperEnv
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) {
        if (root.auditOverflow) return
        if (root.auditBuffer.length + data.length > root.maxReportChars) {
          root.auditOverflow = true
          root.auditBuffer = ""
          auditProc.signal(15)
          auditKill.restart()
          return
        }
        root.auditBuffer += data
      }
    }
    onExited: function(exitCode, exitStatus) {
      auditKill.stop()
      root.finishAudit(exitCode)
    }
  }

  // Stop: `vigil stop` stops whichever scan or update holds the lock, this
  // copy's own or one left from before a shell restart.
  property bool stopRequested: false
  function stopRun() {
    if (stopProc.running || stopRequested) return
    if (feedProc.running) {
      // This copy's own run: the helper stops its current step on TERM,
      // keeps what finished and reports on the result card.
      stopRequested = true
      feedProc.signal(15)
      feedKill.restart()
      return
    }
    if (!runElsewhere) return
    stopProc.buffer = ""
    stopProc.running = true
  }

  Process {
    id: stopProc
    clearEnvironment: true
    environment: root.helperEnv
    command: ["/usr/bin/python3", "-I", "-S", root.helperPath, "stop"]
    property string buffer: ""
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) { stopProc.buffer = (stopProc.buffer + data).slice(-4096) }
    }
    onExited: function(exitCode, exitStatus) {
      var r = exitCode === 0 ? Model.parseFixResult(stopProc.buffer.trim()) : null
      stopProc.buffer = ""
      // This copy's own run reports on its result card when it exits.
      if (!r || !r.ok) root.setStatus(r ? r.message : "Could not stop it.", true)
      else root.setStatus(r.message, false)
      root.otherRun = null
      root.runAudit()
    }
  }

  // Follows a run this copy did not start, cheaply, until it ends; then the
  // full check shows its results.
  Process {
    id: runningProc
    clearEnvironment: true
    environment: root.helperEnv
    command: ["/usr/bin/python3", "-I", "-S", root.helperPath, "running"]
    property string buffer: ""
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) { runningProc.buffer = (runningProc.buffer + data).slice(-4096) }
    }
    onExited: function(exitCode, exitStatus) {
      var r = exitCode === 0 ? Model.parseRunning(runningProc.buffer.trim()) : null
      runningProc.buffer = ""
      if (!r || feedProc.running) return
      if (r.running === null) { root.otherRun = null; root.runAudit() }
      else {
        if (root.otherRun && r.running.step !== root.otherRun.step) root.runAudit()
        root.otherRun = r.running
      }
    }
  }
  Timer {
    interval: 4000
    repeat: true
    running: root.runElsewhere
    onTriggered: if (!runningProc.running) runningProc.running = true
  }

  // Omarchy's own shell restart, after Vigil was updated on disk.
  Process {
    id: restartProc
    clearEnvironment: true
    environment: root.actionEnv
    command: ["/usr/bin/bash", "-c", "omarchy-restart-shell"]
  }

  Process {
    id: actionProc
    clearEnvironment: true
    environment: root.actionEnv
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) {
        // Keep the last 8 KiB of what the action printed, and how far it got.
        root.actionOutput = (root.actionOutput + data).slice(-8192)
        root.actionStageNow = Math.max(root.actionStageNow, Model.actionStage(root.actionOutput))
      }
    }
    onExited: function(exitCode, exitStatus) { root.finishAction(exitCode) }
  }
  Timer { id: actionDeadline; interval: 1800000; onTriggered: if (actionProc.running) actionProc.signal(15) }

  Process {
    id: fixProc
    clearEnvironment: true
    environment: root.helperEnv
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) {
        if (root.fixOverflow) return
        if (root.fixBuffer.length + data.length > root.maxFixChars) {
          root.fixOverflow = true
          root.fixBuffer = ""
          fixProc.signal(15)
          fixKill.restart()
          return
        }
        root.fixBuffer += data
      }
    }
    onExited: function(exitCode, exitStatus) {
      fixKill.stop()
      root.finishFix(exitCode)
    }
  }

  Process {
    id: feedProc
    clearEnvironment: true
    environment: root.helperEnv
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) {
        if (root.feedOverflow) return
        // Complete lines are handled as they arrive, so only a partial line is
        // ever held; the cap is on that, and on the result line.
        var text = root.feedBuffer + data
        var cut = text.lastIndexOf("\n")
        root.feedBuffer = cut === -1 ? text : text.substring(cut + 1)
        if (root.feedBuffer.length > root.maxFixChars) {
          root.feedOverflow = true
          root.feedBuffer = ""
          feedProc.signal(15)
          feedKill.restart()
          return
        }
        if (cut === -1) return
        var lines = text.substring(0, cut).split("\n")
        for (var i = 0; i < lines.length; i++) {
          if (lines[i] === "") continue
          var p = Model.parseProgress(lines[i])
          if (p) {
            // A step finished: re-read, so its Last run line updates now,
            // not after the (long) virus scan at the end.
            if (root.scanProgress && p.step !== root.scanProgress.step) root.runAudit()
            root.scanProgress = p
          }
          else if (lines[i].length <= root.maxFixChars) root.feedResult = lines[i]
        }
      }
    }
    onExited: function(exitCode, exitStatus) {
      feedKill.stop()
      feedDeadline.stop()
      root.stopRequested = false
      var parsed = (!root.feedOverflow && exitCode === 0)
        ? Model.parseFixResult((root.feedResult !== "" ? root.feedResult : root.feedBuffer).trim()) : null
      root.feedBuffer = ""
      root.feedResult = ""
      root.scanProgress = null
      // Only the buttons report back, on the result card, which stays until
      // you close it; the weekly background run stays quiet.
      if (root.feedForced) {
        root.setStatus("", false)
        root.actionResult = {
          title: root.feedTitles[root.feedMode] || "Vigil",
          verdict: parsed ? parsed.message : "It did not finish.",
          ok: parsed !== null && parsed.ok,
          output: ""
        }
      }
      // The long runs (Run all, Run weekly check) also send a notification.
      if (root.feedFull) {
        var name = root.feedTitles[root.feedMode]
        Quickshell.execDetached(["/usr/bin/notify-send", "--app-name=Vigil", "--", "Vigil",
          parsed && parsed.stopped ? name + " was stopped."
            : (parsed ? name + " finished. Open the lighthouse in the bar for the results." : name + " did not finish.")])
      }
      root.feedForced = false
      root.feedFull = false
      root.runAudit()
    }
  }

  // The helper bounds its own children; these are the outer backstops.
  Timer { id: auditDeadline; interval: 90000; onTriggered: if (auditProc.running) { auditProc.signal(15); auditKill.restart() } }
  Timer { id: auditKill; interval: 2000; onTriggered: if (auditProc.running) auditProc.signal(9) }
  Timer { id: fixDeadline; interval: 120000; onTriggered: if (fixProc.running) { fixProc.signal(15); fixKill.restart() } }
  Timer { id: fixKill; interval: 2000; onTriggered: if (fixProc.running) fixProc.signal(9) }
  Timer { id: feedDeadline; interval: 1200000; onTriggered: if (feedProc.running) { feedProc.signal(15); feedKill.restart() } }
  // Time for the helper to stop its current program and save what finished.
  Timer { id: feedKill; interval: 15000; onTriggered: if (feedProc.running) feedProc.signal(9) }

  // First check shortly after login, then every refreshMinutes on the
  // primary monitor's copy. Secondary copies check when their panel opens.
  Timer {
    id: startupAudit
    interval: 8000
    running: true
    onTriggered: root.runAudit()
  }
  Timer {
    interval: root.refreshMinutes * 60000
    running: root.isPrimary
    repeat: true
    onTriggered: root.runAudit()
  }

  IpcHandler {
    enabled: root.isPrimary
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { root.runAudit(); return "ok" }
  }

  // ---- bar button

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    // A lighthouse: it keeps watch and warns. Its beams show while a scan or
    // update runs (Nerd Font md-lighthouse_on / md-lighthouse).
    text: feedProc.running || root.runElsewhere ? "󰨀" : "󰧿"
    tooltipText: Model.tooltip(root.report, auditProc.running)
    dimmed: root.report === null
    active: root.report !== null && root.report.level !== "ok"
    activeColor: root.report !== null && root.report.level === "fail" ? root.urgent : root.warnColor
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) root.runAudit()
      else if (buttonCode === Qt.LeftButton) root.toggle()
    }
  }

  // ---- panel

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    // 440 for the content plus the 22-unit scroll bar lane.
    contentWidth: panel.fittedContentWidth(Style.space(462))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (root.pending) return
        if (dx !== 0) { root.moveTab(dx > 0 ? 1 : -1); return }
        if (!root.cursorActive) { root.cursorActive = true; return }
        root.moveRow(dy > 0 ? 1 : -1)
      }
      onActivateRequested: {
        if (root.pending) root.confirmPending()
        else if (root.cursorActive) root.toggleExpanded(root.selectedCheck())
      }
      onCloseRequested: {
        if (root.pending) root.cancelPending()
        else root.close()
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R" || t === "s" || t === "S") root.requestFullScan()
        else if (t === "f" || t === "F") root.requestFix(root.selectedCheck())
        else if (t === "u" || t === "U") root.requestUpdate()
        else if ((t === "c" || t === "C") && root.tab === "care") root.requestCleanAll()
        else if (t === "d" || t === "D") {
          var sel = root.selectedCheck()
          if (sel) root.setReviewed(sel, !sel.dismissed)
        }
        else if (t >= "1" && t <= "6") root.selectTab(root.tabs[Number(t) - 1])
      }

      // The content stops 22 units short of the right edge, so the scroll bar
      // sits in its own lane and never covers a button or text. The lane stays
      // when nothing scrolls, so the content width never jumps.
      Flickable {
        id: panelFlick
        anchors.fill: parent
        anchors.rightMargin: Style.space(22)
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        // A thin bar with square ends in a faint shade of the theme's text
        // colour; brighter on hover and while dragging, gone when all fits.
        ScrollBar.vertical: ScrollBar {
          id: vbar
          parent: panelFlick.parent
          anchors.top: parent.top
          anchors.right: parent.right
          anchors.bottom: parent.bottom
          width: Style.space(3)
          padding: 0
          policy: ScrollBar.AlwaysOn
          visible: panelFlick.contentHeight > panelFlick.height
          background: Item {}
          contentItem: Rectangle {
            implicitWidth: Style.space(3)
            radius: 0
            color: root.foreground
            opacity: vbar.pressed ? 0.6 : (vbar.hovered ? 0.45 : 0.25)
          }
        }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          PanelHero {
            width: parent.width
            title: "Vigil"
            meta: Model.plain(Model.heroMeta(root.report, root.tab, auditProc.running, new Date()), 80)
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          // The tabs, each with what matters most in it right underneath.
          // Care stands apart, past a divider: it is upkeep, not security,
          // and never part of the score or of the scheduled checks.
          Row {
            id: tabStrip
            width: parent.width
            spacing: Style.spacing.md
            readonly property real dividerWidth: Style.space(8)
            // Each tab as wide as its label, as in Omarchy's ButtonGroup, and
            // the room left over shared out evenly.
            readonly property real spare: Math.max(0, Math.floor((width - spacing * 6 - dividerWidth
              - tabOverview.naturalWidth - tabHarden.naturalWidth - tabDetect.naturalWidth
              - tabSupply.naturalWidth - tabPrivacy.naturalWidth - tabCare.naturalWidth) / 6))
            TabCell { id: tabOverview; tab: "overview"; width: naturalWidth + tabStrip.spare }
            TabCell { id: tabHarden; tab: "harden"; width: naturalWidth + tabStrip.spare }
            TabCell { id: tabDetect; tab: "detect"; width: naturalWidth + tabStrip.spare }
            TabCell { id: tabSupply; tab: "supply"; width: naturalWidth + tabStrip.spare }
            TabCell { id: tabPrivacy; tab: "privacy"; width: naturalWidth + tabStrip.spare }
            Item {
              width: tabStrip.dividerWidth
              height: tabOverview.buttonHeight
              Rectangle {
                anchors.centerIn: parent
                width: 1
                height: parent.height * 0.7
                color: root.dim
              }
            }
            TabCell { id: tabCare; tab: "care"; width: naturalWidth + tabStrip.spare }
          }

          // Confirmation card: every action is described before it runs.
          CursorSurface {
            visible: root.pending !== null
            width: parent.width
            hasCursor: true
            foreground: root.foreground
            implicitHeight: confirmColumn.implicitHeight + Style.space(20)

            Column {
              id: confirmColumn
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.pending ? root.pending.title : ""
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                wrapMode: Text.WordWrap
              }
              Repeater {
                model: root.pending ? root.pending.lines : []
                delegate: Text {
                  required property var modelData
                  textFormat: Text.PlainText
                  width: confirmColumn.width
                  text: String(modelData)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WordWrap
                }
              }
              Row {
                spacing: Style.space(8)
                Button {
                  text: "Run"
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  bordered: true
                  onClicked: root.confirmPending()
                }
                Button {
                  text: "Cancel"
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.cancelPending()
                }
              }
              // Exactly what Run starts, every root step in full: the program
              // with its options, then the script as it is passed. Constants
              // from Model.js, so nothing here is stripped or shortened.
              Column {
                visible: root.pending !== null && root.pending.commands.length > 0
                width: parent.width
                topPadding: Style.space(6)
                spacing: Style.space(4)
                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: "EXACT COMMANDS"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1
                }
                Repeater {
                  model: root.pending ? root.pending.commands : []
                  delegate: Column {
                    required property var modelData
                    width: confirmColumn.width
                    spacing: Style.space(2)
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: String(modelData.who)
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                    }
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: String(modelData.text)
                      color: root.dim
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WrapAnywhere
                    }
                  }
                }
              }
            }
          }

          // What the last action did, in place of a terminal.
          CursorSurface {
            visible: root.actionResult !== null
            width: parent.width
            hasCursor: true
            foreground: root.foreground
            implicitHeight: resultColumn.implicitHeight + Style.space(20)
            Column {
              id: resultColumn
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(6)
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.actionResult ? root.actionResult.title : ""
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                wrapMode: Text.WordWrap
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.actionResult ? root.actionResult.verdict : ""
                color: root.actionResult && !root.actionResult.ok ? root.urgent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.italic: true
                wrapMode: Text.WordWrap
              }
              Text {
                textFormat: Text.PlainText
                visible: root.actionResult !== null && root.actionResult.output !== ""
                width: parent.width
                text: root.actionResult ? root.actionResult.output : ""
                color: root.dim
                font.family: "monospace"
                font.pixelSize: Style.font.caption
                wrapMode: Text.WrapAnywhere
              }
              Button {
                text: "Close"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.actionResult = null
              }
            }
          }

          // While a fix, Clean all or an install runs: what it is doing.
          Column {
            visible: root.actionNow !== null
            width: parent.width
            spacing: Style.space(4)
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.actionTitle
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              font.bold: true
              wrapMode: Text.WordWrap
            }
            Rectangle {
              width: parent.width
              height: Style.space(6)
              radius: height / 2
              color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
              Rectangle {
                width: parent.width * (root.actionNow ? Math.max(0.02, Math.min(1, root.actionNow.fraction)) : 0.02)
                height: parent.height
                radius: parent.radius
                color: root.foreground
              }
            }
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.actionNow ? root.actionNow.text : ""
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          Button {
            visible: root.updatePending
            text: restartProc.running ? "Restarting\u2026" : "Restart shell"
            tooltipText: "Loads the updated Vigil. The bar and panels come back after a moment"
            foreground: root.foreground
            fontFamily: root.fontFamily
            bordered: true
            enabled: !restartProc.running
            onClicked: restartProc.running = true
          }

          Text {
            textFormat: Text.PlainText
            visible: root.statusMessage !== ""
            width: parent.width
            text: root.statusMessage
            color: root.statusIsError ? root.urgent : root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.italic: true
            wrapMode: Text.WordWrap
          }

          // Overview: the score, the run buttons with when each next runs, a
          // word on Care, then when everything last ran. Each pillar's counts
          // sit under its tab at the top.
          Column {
            visible: root.tab === "overview"
            width: parent.width
            spacing: Style.space(8)

            Row {
              spacing: Style.space(6)
              Text {
                id: scoreText
                textFormat: Text.PlainText
                text: root.report ? String(root.report.score) : "\u2013"
                color: root.report && root.report.level === "fail" ? root.urgent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.displayLarge
                font.bold: true
              }
              Text {
                textFormat: Text.PlainText
                anchors.baseline: scoreText.baseline
                text: "/ 100"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
              }
            }
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.report ? Model.levelText(root.report) : "Not checked yet"
              color: root.report && root.report.level === "fail" ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
              wrapMode: Text.WordWrap
            }

            // When tools Vigil works with are missing, installing them comes first.
            Button {
              visible: Model.missingLabel(root.report) !== ""
              text: actionProc.running && root.actionId === "install-helpers" ? "Installing\u2026"
                                                                                : Model.missingLabel(root.report)
              tooltipText: "Install everything Vigil works with that is missing, in one go"
              foreground: root.urgent
              fontFamily: root.fontFamily
              bordered: true
              enabled: !root.busy && !feedProc.running && !root.runElsewhere && root.pending === null
              onClicked: root.requestInstallHelpers()
            }

            // One button per schedule, each with when it next runs by itself
            // right under it, then all three at once.
            SectionHeading { visible: root.report !== null; text: "RUN NOW" }
            Row {
              id: runStrip
              visible: root.report !== null
              width: parent.width
              spacing: Style.spacing.md
              readonly property var captions: Model.runCaptions(root.report, root.autoUpdate, new Date(), root.refreshMinutes)
              readonly property real spare: Math.max(0, Math.floor((width - spacing * 3 - runDaily.naturalWidth
                - runWeekly.naturalWidth - runUpdate.naturalWidth - runAll.naturalWidth) / 4))
              RunCell {
                id: runDaily; kind: "daily-check"; mode: "daily"; label: "Daily check"
                caption: runStrip.captions.daily; width: naturalWidth + runStrip.spare
                tip: "Now: ClamAV scan of ~/Downloads, System update check, Flatpak update check, Bumblebee scan, settings checks"
              }
              RunCell {
                id: runWeekly; kind: "weekly-check"; mode: "weekly"; label: "Weekly check"
                caption: runStrip.captions.weekly; width: naturalWidth + runStrip.spare
                tip: "Now: Firmware check and ClamAV scan of ~ (your whole home folder)"
              }
              RunCell {
                id: runUpdate; kind: "update-sources"; mode: "sources"; label: "Update check"
                caption: runStrip.captions.update; width: naturalWidth + runStrip.spare
                tip: "Now: ClamAV signatures and every list Vigil checks against. No scan"
              }
              RunCell {
                id: runAll; kind: "full-scan"; mode: "full"; label: "Run all"; primary: true
                caption: runStrip.captions.all; width: naturalWidth + runStrip.spare
                tip: "Now: the update, daily and weekly checks, plus the password check"
              }
            }
            // While an update or scan runs: what it is doing, and how far along.
            Column {
              visible: feedProc.running || root.runElsewhere
              width: parent.width
              spacing: Style.space(4)
              Rectangle {
                width: parent.width
                height: Style.space(6)
                radius: height / 2
                color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
                Rectangle {
                  width: parent.width * (root.runProgress ? Math.max(0.02, root.runProgress.fraction) : 0.02)
                  height: parent.height
                  radius: parent.radius
                  color: root.foreground
                }
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: (root.runElsewhere ? "Already running. " : "")
                      + (root.runProgress ? Model.progressText(root.runProgress) : "Starting\u2026")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
              Button {
                text: stopProc.running || root.stopRequested ? "Stopping\u2026" : "Stop"
                tooltipText: "Stop this scan or update. What already finished is kept; the rest runs next time"
                foreground: root.foreground
                fontFamily: root.fontFamily
                bordered: true
                enabled: !stopProc.running && !root.stopRequested
                onClicked: root.stopRun()
              }
            }
            Repeater {
              model: Model.scheduleNotes(root.report, root.autoUpdate)
              delegate: Text {
                required property var modelData
                textFormat: Text.PlainText
                width: column.width
                text: String(modelData)
                color: String(modelData).indexOf("could not") !== -1 ? root.urgent : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }

            // The run buttons above never clean: Care is the user's call.
            Text {
              textFormat: Text.PlainText
              visible: root.report !== null
              width: parent.width
              topPadding: Style.space(4)
              text: Model.CARE_NOTE
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            // When every check and scan last ran, and when each source last updated.
            SectionHeading { visible: root.report !== null; text: "LAST RUN" }
            Repeater {
              model: root.report ? Model.lastRunRows(root.report, new Date()) : []
              delegate: Item {
                required property var modelData
                width: column.width
                implicitHeight: Math.max(runLabel.implicitHeight, runValue.implicitHeight)
                Text {
                  id: runLabel
                  textFormat: Text.PlainText
                  anchors.left: parent.left
                  width: parent.width * 0.5
                  text: modelData.label
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: modelData.heading === true
                  wrapMode: Text.WordWrap
                }
                Text {
                  id: runValue
                  textFormat: Text.PlainText
                  anchors.right: parent.right
                  width: parent.width * 0.5
                  horizontalAlignment: Text.AlignRight
                  text: modelData.value
                  color: modelData.problem ? root.urgent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: modelData.problem === true
                  wrapMode: Text.WordWrap
                }
              }
            }
          }

          // Each pillar opens with its question in bold, then what it covers.
          Column {
            visible: root.tab !== "overview" && root.report !== null
            width: parent.width
            spacing: Style.space(2)
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: Model.tabIntro(root.tab).question
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
              wrapMode: Text.WordWrap
            }
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: Model.tabIntro(root.tab).text
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Text {
              textFormat: Text.PlainText
              visible: root.tab === "care"
              width: parent.width
              topPadding: Style.space(2)
              text: Model.CARE_TAB_NOTE
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
            Item {
              visible: root.tab === "care" && root.cleanPlan.items.length > 0
              width: parent.width
              implicitHeight: cleanAllButton.implicitHeight + Style.space(8)
              Button {
                id: cleanAllButton
                anchors.bottom: parent.bottom
                text: "Clean all"
                foreground: root.foreground
                fontFamily: root.fontFamily
                bordered: true
                enabled: !root.busy && root.pending === null
                onClicked: root.requestCleanAll()
              }
            }
          }

          Repeater {
            id: rowsRepeater
            model: root.visibleChecks
            // A row, and at the start of each group a heading: which check
            // brings the rows in (settings, daily, weekly, update), and on the
            // Care tab what Clean all covers and what it leaves alone.
            delegate: Column {
              id: rowSlot
              required property var modelData
              required property int index
              readonly property string heading: Model.rowHeading(root.visibleChecks, index)
              readonly property string headingNote: Model.rowHeadingNote(root.visibleChecks, index)
              width: column.width
              spacing: Style.space(2)
              SectionHeading { visible: rowSlot.heading !== ""; text: rowSlot.heading }
              Text {
                textFormat: Text.PlainText
                visible: rowSlot.headingNote !== ""
                width: parent.width
                bottomPadding: Style.space(4)
                text: rowSlot.headingNote
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
              CheckRow {
                width: parent.width
                check: rowSlot.modelData
                selected: root.cursorActive && root.rowIndex === rowSlot.index
                expanded: root.expandedId === rowSlot.modelData.id
                onClicked: { root.rowIndex = rowSlot.index; root.toggleExpanded(rowSlot.modelData) }
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: Model.keyHints(root.tab, root.report ? root.report.version : "")
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
        }
      }
    }
  }

  // ---- components

  // Omarchy's own small bold section label, with a little air above it.
  component SectionHeading: Item {
    property alias text: heading.text
    width: parent ? parent.width : 0
    implicitHeight: heading.implicitHeight + Style.space(6)
    PanelSectionHeader {
      id: heading
      anchors.bottom: parent.bottom
      foreground: root.foreground
      fontFamily: root.fontFamily
      font.letterSpacing: 1
    }
  }

  // One tab: Omarchy's own bordered button, as in its ButtonGroup, with the
  // pillar's most important count under it. The tooltip has every count.
  component TabCell: Column {
    id: cell
    property string tab: ""
    readonly property var caption: Model.tabCaption(root.report, tab)
    readonly property alias buttonHeight: tabButton.height
    readonly property real naturalWidth: tabButton.implicitWidth
    readonly property color tone: caption.tone === "urgent" ? root.urgent
      : (caption.tone === "warn" ? root.warnColor : root.dim)
    spacing: Style.space(2)
    Button {
      id: tabButton
      width: cell.width
      text: Model.categoryLabel(cell.tab)
      tooltipText: Model.plain(Model.tabCounts(root.report, cell.tab), 120)
      selected: root.tab === cell.tab
      bordered: true
      foreground: root.foreground
      background: Commons.Color.background
      fontFamily: root.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: root.selectTab(cell.tab)
    }
    Text {
      textFormat: Text.PlainText
      width: cell.width
      horizontalAlignment: Text.AlignHCenter
      // A space before the first check, so the strip does not grow when it lands.
      text: cell.caption.count !== "" ? cell.caption.count : " "
      color: cell.tone
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      font.bold: cell.caption.tone !== "dim"
    }
    Text {
      textFormat: Text.PlainText
      width: cell.width
      horizontalAlignment: Text.AlignHCenter
      text: cell.caption.label !== "" ? cell.caption.label : " "
      color: cell.tone
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }
  }

  // One run button with when it next runs by itself under it.
  component RunCell: Column {
    id: runCell
    property string kind: ""
    property string mode: ""
    property string label: ""
    property string caption: ""
    property string tip: ""
    property bool primary: false
    readonly property real naturalWidth: runButton.implicitWidth
    spacing: Style.space(2)
    Button {
      id: runButton
      width: runCell.width
      text: feedProc.running && root.feedMode === runCell.mode ? "Running\u2026" : runCell.label
      tooltipText: runCell.tip
      foreground: root.foreground
      fontFamily: root.fontFamily
      bordered: runCell.primary
      enabled: !feedProc.running && !root.runElsewhere && !root.busy && root.pending === null
      onClicked: root.requestRun(runCell.kind)
    }
    Text {
      textFormat: Text.PlainText
      width: runCell.width
      horizontalAlignment: Text.AlignHCenter
      text: runCell.caption !== "" ? runCell.caption : " "
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }
  }

  component CheckRow: CursorSurface {
    id: row
    property var check: null
    property bool selected: false
    property bool expanded: false
    readonly property bool unresolved: check !== null && check.status !== "pass" && check.status !== "na"
    readonly property bool runnable: unresolved && root.report !== null && Model.canRun(check.fix, root.report.tools, root.report.apps)
    readonly property string howTo: Model.howTo(check)
    readonly property bool undoable: check !== null && root.report !== null && check.undo.action !== ""
      && Model.canRun({ kind: "terminal", action: check.undo.action }, root.report.tools, root.report.apps)
    readonly property bool reviewable: check !== null && (check.dismissible || check.dismissed)
    readonly property bool trashable: check !== null && check.items.some(function(it) {
      return it.kind === "leftover" && !it.kept })
    signal clicked()

    hasCursor: selected
    foreground: root.foreground
    implicitHeight: rowColumn.implicitHeight + Style.spacing.rowPaddingX
    // Dimmed means nothing to do: passing, not applicable, or marked as reviewed.
    opacity: check !== null && (check.dismissed || check.status === "pass" || check.status === "na") ? 0.55 : 1

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: row.clicked()
    }

    Text {
      id: glyph
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.top: parent.top
      anchors.leftMargin: Style.space(10)
      anchors.topMargin: Style.spacing.rowPaddingX / 2
      width: Style.space(16)
      text: row.check ? Model.statusGlyph(row.check.status) : ""
      color: !row.check ? root.dim
        : row.check.status === "fail" ? root.urgent
        : row.check.status === "warn" ? root.warnColor
        : row.check.status === "pass" ? root.foreground : root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      font.bold: true
    }

    Column {
      id: rowColumn
      anchors.left: glyph.right
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(6)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(3)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: row.check ? row.check.title : ""
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
        elide: Text.ElideRight
      }
      Text {
        textFormat: Text.PlainText
        visible: row.check !== null && row.check.dismissed
        width: parent.width
        text: row.check && row.check.dismissed
          ? "Reviewed" + (row.check.dismissedAt !== "" ? " on " + Model.shortDate(row.check.dismissedAt) : "") : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.italic: true
      }
      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: row.check ? row.check.summary : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.check !== null && row.check.why !== ""
        width: parent.width
        topPadding: Style.space(6)
        text: "WHY IT MATTERS"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.check !== null && row.check.why !== ""
        width: parent.width
        lineHeight: 1.15
        text: row.check ? row.check.why : ""
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.howTo !== ""
        width: parent.width
        topPadding: Style.space(6)
        text: "HOW TO FIX"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.howTo !== ""
        width: parent.width
        lineHeight: 1.15
        text: row.howTo
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.check !== null && (row.check.detail !== "" || row.check.items.length > 0)
        width: parent.width
        topPadding: Style.space(6)
        text: "DETAILS"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.check !== null && row.check.detail !== "" && row.check.items.length === 0
        width: parent.width
        text: row.check ? row.check.detail : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WrapAnywhere
      }
      // One line per item. A detection has False positive (or Not a false
      // positive); a leftover has Move to trash and Keep (or Stop keeping).
      Repeater {
        model: row.expanded && row.check !== null ? row.check.items : []
        delegate: Row {
          id: itemRow
          required property var modelData
          readonly property bool leftover: modelData.kind === "leftover"
          readonly property bool quiet: modelData.ignored || modelData.kept
          width: parent ? parent.width : 0
          spacing: Style.space(8)
          Text {
            textFormat: Text.PlainText
            width: itemRow.width - itemButtons.width - itemRow.spacing
            anchors.verticalCenter: parent.verticalCenter
            text: itemRow.modelData.text + (itemRow.modelData.ignored ? "  (false positive)"
                                            : itemRow.modelData.kept ? "  (kept)" : "")
            color: root.dim
            opacity: itemRow.quiet ? 0.6 : 1
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WrapAnywhere
          }
          Row {
            id: itemButtons
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(6)
            Button {
              visible: itemRow.leftover && !itemRow.modelData.kept
              text: "Move to trash"
              tooltipText: "Asks first. You can restore it from the trash in your file manager"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !root.busy && root.pending === null
              onClicked: root.requestTrash(itemRow.modelData)
            }
            Button {
              visible: itemRow.leftover
              text: itemRow.modelData.kept ? "Stop keeping" : "Keep"
              tooltipText: itemRow.modelData.kept ? "Count it again, so you can move it to the trash"
                                                  : "Leave it where it is; Vigil stops counting it"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !root.busy && root.pending === null
              onClicked: root.setKept(itemRow.modelData, !itemRow.modelData.kept)
            }
            Button {
              visible: !itemRow.leftover && itemRow.modelData.id !== ""
              text: itemRow.modelData.ignored ? "Not a false positive" : "False positive"
              tooltipText: itemRow.modelData.ignored ? "Count this detection again"
                                                     : "The file is safe and ClamAV is wrong. Only if you are sure; it comes back if the file changes"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !root.busy && root.pending === null
              onClicked: itemRow.modelData.ignored ? root.requestUnignore(itemRow.modelData)
                                                   : root.requestIgnore(itemRow.modelData)
            }
          }
        }
      }
      Flow {
        visible: row.expanded && (row.runnable || row.undoable || row.reviewable || row.trashable)
        width: parent.width
        spacing: Style.space(8)
        Button {
          visible: row.trashable
          text: "Move all to trash"
          tooltipText: "Asks first, listing each item. Items you keep stay where they are"
          foreground: root.foreground
          fontFamily: root.fontFamily
          enabled: !root.busy && root.pending === null
          onClicked: root.requestTrashAll()
        }
        Button {
          visible: row.runnable && !(row.check !== null && row.check.dismissed)
          text: row.check ? row.check.fix.label : ""
          foreground: root.foreground
          fontFamily: root.fontFamily
          bordered: true
          onClicked: root.requestFix(row.check)
        }
        Button {
          visible: row.undoable
          text: row.check ? row.check.undo.label : ""
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.requestUndo(row.check)
        }
        Button {
          visible: row.reviewable
          text: row.check !== null && row.check.dismissed ? "Show again" : "Mark as reviewed"
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.setReviewed(row.check, !row.check.dismissed)
        }
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && row.unresolved && !row.runnable && row.check.fix.kind !== "none"
        width: parent.width
        text: "This needs a command that was not found on this system."
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
      }
    }
  }
}
