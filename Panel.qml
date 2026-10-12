import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Vigil: a shield in the bar and a panel with five tabs.
//
// All the checking is done by bin/vigil, run as an argv array with a cleared
// environment. Its stdout is read in raw chunks with a hard size limit and
// validated by Model.parseReport before anything is shown. Nothing here
// builds a shell string from data: helper actions are fixed ids, and
// terminal actions are constant scripts in Model.js shown to you, in a
// visible terminal, before they run.
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
  // One bar per monitor means one copy of this widget per monitor. Only the
  // first screen's copy schedules audits, records findings and notifies.
  readonly property bool isPrimary: root.QsWindow.window !== null
    && root.QsWindow.window.screen === Quickshell.screens[0]

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  // Every colour comes from the Omarchy theme: text, urgent (to fix), accent
  // (to improve) and muted (secondary text, nothing to do).
  readonly property color dim: Commons.Color.muted
  readonly property color warnColor: Commons.Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  property var report: null
  property string auditBuffer: ""
  property bool auditOverflow: false
  property string fixBuffer: ""
  property bool fixOverflow: false
  property string fixAction: ""
  property string statusMessage: ""
  property bool statusIsError: false

  property string tab: "overview"
  readonly property var tabs: ["overview", "harden", "detect", "supply", "privacy", "care"]
  property int rowIndex: 0
  property bool cursorActive: false
  property string expandedId: ""
  property string pendingKind: ""
  property string pendingAction: ""
  readonly property var pending: pendingAction === "" ? null : Model.confirmation(pendingKind, pendingAction, report)
  readonly property var cleanPlan: Model.cleanAllPlan(report)

  readonly property var visibleChecks: tab === "overview" ? [] : Model.checksFor(report, tab)
  readonly property bool busy: auditProc.running || fixProc.running || actionProc.running

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
    if (!parsed) { setStatus("The check returned something Vigil could not read.", true); return }
    report = parsed
    if (statusIsError) setStatus("", false)
    if (rowIndex >= visibleChecks.length) rowIndex = Math.max(0, visibleChecks.length - 1)
    if (root.isPrimary && root.notifyOnNew && parsed.fresh.length > 0) notifyNew(parsed.fresh.length)
    if (root.isPrimary && root.autoUpdate && parsed.feedsDue) refreshFeeds("")
  }

  // Runs `bin/vigil refresh-feeds` in the background. With no mode (the
  // weekly run) the helper refreshes only what is due and retries failures the
  // next day; "sources" (Update sources) refreshes every database and list;
  // "full" (Full scan) also scans Downloads for viruses.
  function refreshFeeds(mode) {
    if (feedProc.running) return
    feedBuffer = ""
    feedResult = ""
    scanProgress = null
    feedOverflow = false
    feedForced = mode === "sources" || mode === "full" || mode === "scan"
    feedFull = mode === "full"
    feedProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath, "refresh-feeds"]
      .concat(mode === "sources" ? ["--sources"] : (mode === "full" ? ["--full"] : (mode === "scan" ? ["--scan"] : [])))
    feedProc.running = true
    // Anything but Update sources may scan the whole home folder, which can take a long time.
    feedDeadline.interval = mode === "sources" ? 1200000 : 4 * 3600000
    feedDeadline.restart()
    if (mode === "sources") setStatus("Updating sources\u2026 Omarchy may ask for your password first.", false)
    else if (mode === "full") setStatus("Full scan started. You can close this panel; you get a notification when it is done.", false)
    else if (mode === "scan") setStatus("Virus scan started. It runs in the background.", false)
  }

  // Full scan: the background part (sources and the virus scan) plus the
  // checks that need a password, in one terminal. Asks first on the usual card.
  // Update sources asks first too: it may ask for your password (ClamAV's
  // signatures live in a system folder), so it explains itself on the card.
  function requestUpdate() {
    if (!report || busy || feedProc.running) return
    pendingKind = "update-sources"
    pendingAction = "all"
  }

  function requestFullScan() {
    if (!report || busy || feedProc.running) return
    pendingKind = "full-scan"
    pendingAction = "all"
  }

  function notifyNew(count) {
    var n = Math.max(1, Math.min(99, Math.round(Number(count) || 1)))
    Quickshell.execDetached([
      "/usr/bin/notify-send", "--app-name=Vigil", "--",
      "Vigil",
      n + (n === 1 ? " new security finding." : " new security findings.") + " Open the shield in the bar for details."
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
    if (kind === "update-sources") {
      refreshFeeds("sources")
      return
    }
    if (kind === "full-scan") {
      // No terminal: the password step uses Omarchy's own password dialog,
      // so the panel stays open and shows the progress.
      refreshFeeds("full")
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
    var steps = Model.actionPlan(id, report.tools, Quickshell.env("HOME") || "")
    if (steps.length === 0) { setStatus("This action is not available on this system.", true); return }
    var a = Model.terminalAction(id)
    actionSteps = steps
    actionIndex = 0
    actionOutput = ""
    actionTitle = a ? a.title : ""
    actionResult = null
    actionProc.command = steps[0].argv
    actionProc.running = true
    actionDeadline.restart()
    setStatus(steps[0].asRoot ? "Waiting for your password\u2026" : "Working\u2026", false)
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
      output: Model.plain(actionOutput, 6000)
    }
    setStatus("", false)
    runAudit()
  }

  // Runs bin/vigil with one of three fixed verbs and an id the panel already
  // validated: `fix <helper action>`, `dismiss <check id>`, `undismiss <check id>`.
  function runHelper(args) {
    if (fixProc.running || args.length !== 2) return
    if (["fix", "dismiss", "undismiss"].indexOf(args[0]) === -1 || !/^[a-z0-9-]{1,40}$/.test(args[1])) return
    fixBuffer = ""
    fixOverflow = false
    fixAction = args[1]
    fixProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath, args[0], args[1]]
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

  Process {
    id: actionProc
    clearEnvironment: true
    environment: root.actionEnv
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) {
        // Keep the last 8 KiB of what the action printed.
        root.actionOutput = (root.actionOutput + data).slice(-8192)
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
          if (p) root.scanProgress = p
          else if (lines[i].length <= root.maxFixChars) root.feedResult = lines[i]
        }
      }
    }
    onExited: function(exitCode, exitStatus) {
      feedKill.stop()
      feedDeadline.stop()
      var parsed = (!root.feedOverflow && exitCode === 0)
        ? Model.parseFixResult((root.feedResult !== "" ? root.feedResult : root.feedBuffer).trim()) : null
      root.feedBuffer = ""
      root.feedResult = ""
      root.scanProgress = null
      // Only the button reports back; the weekly background run stays quiet.
      if (root.feedForced) {
        if (!parsed) root.setStatus("The update did not finish.", true)
        else root.setStatus(parsed.message, !parsed.ok)
      }
      if (root.feedFull)
        Quickshell.execDetached(["/usr/bin/notify-send", "--app-name=Vigil", "--", "Vigil",
          parsed ? "Full scan finished. Open the shield in the bar for the results." : "The Full scan did not finish."])
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
  Timer { id: feedKill; interval: 2000; onTriggered: if (feedProc.running) feedProc.signal(9) }

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
    text: "󰒃"
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
    contentWidth: panel.fittedContentWidth(Style.space(440))
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

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar {
          id: vbar
          policy: ScrollBar.AsNeeded
          width: Style.space(6)
          background: Item {}
          contentItem: Rectangle {
            implicitWidth: Style.space(4)
            radius: width / 2
            color: root.foreground
            opacity: vbar.pressed ? 0.55 : (vbar.hovered ? 0.4 : 0.25)
          }
        }

        Column {
          id: column
          // A fixed gutter for the scroll bar, so it never sits on top of text
          // (and the layout does not reflow when the bar appears).
          width: panelFlick.width - Style.space(12)
          spacing: Style.space(12)

          PanelHero {
            width: parent.width
            title: "Vigil"
            meta: Model.plain(root.report
              ? Model.levelText(root.report) + " · " + root.report.score + "/100"
              : (auditProc.running ? "Checking…" : "Not checked yet"), 80)
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          ButtonGroup {
            width: parent.width
            options: [
              { value: "overview", label: "Overview" },
              { value: "harden", label: "Harden" },
              { value: "detect", label: "Detect" },
              { value: "supply", label: "Supply" },
              { value: "privacy", label: "Privacy" },
              { value: "care", label: "Care" }
            ]
            value: root.tab
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            focusable: false
            onChanged: function(v) { root.selectTab(v) }
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

          // Overview: the score, the two buttons, then each pillar with its counts.
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

            Flow {
              width: parent.width
              topPadding: Style.space(6)
              spacing: Style.space(8)
              Button {
                text: feedProc.running && root.feedFull ? "Scanning\u2026" : "Full scan"
                tooltipText: "Run every check and scan Vigil has, including a virus scan of your home folder"
                foreground: root.foreground
                fontFamily: root.fontFamily
                bordered: true
                enabled: !feedProc.running && !root.busy && root.pending === null
                onClicked: root.requestFullScan()
              }
              Button {
                text: feedProc.running && !root.feedFull ? "Updating\u2026" : "Update sources"
                tooltipText: "Download the latest virus signatures and lists Vigil checks against. No scan"
                foreground: root.foreground
                fontFamily: root.fontFamily
                enabled: !feedProc.running && !root.busy && root.pending === null
                onClicked: root.requestUpdate()
              }
            }
            // While an update or scan runs: what it is doing, and how far along.
            Column {
              visible: feedProc.running
              width: parent.width
              spacing: Style.space(4)
              Rectangle {
                width: parent.width
                height: Style.space(6)
                radius: height / 2
                color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
                Rectangle {
                  width: parent.width * (root.scanProgress ? Math.max(0.02, root.scanProgress.fraction) : 0.02)
                  height: parent.height
                  radius: parent.radius
                  color: root.foreground
                }
              }
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.scanProgress ? Model.progressText(root.scanProgress) : "Starting\u2026"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }
            Repeater {
              model: Model.scheduleLines(root.report, root.autoUpdate, new Date())
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

            SectionHeading { visible: root.report !== null; text: "PILLARS" }
            Repeater {
              model: root.report ? ["harden", "detect", "supply", "privacy", "care"] : []
              delegate: CategoryRow {
                required property var modelData
                width: column.width
                category: String(modelData)
              }
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
            delegate: CheckRow {
              required property var modelData
              required property int index
              width: column.width
              check: modelData
              selected: root.cursorActive && root.rowIndex === index
              expanded: root.expandedId === modelData.id
              onClicked: { root.rowIndex = index; root.toggleExpanded(modelData) }
            }
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: "R check again · ← → tabs · Enter details · F fix · D reviewed · U update all · Vigil " + (root.report ? root.report.version : "")
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

  component CategoryRow: CursorSurface {
    id: catRow
    property string category: ""
    readonly property int fails: Model.countBy(root.report, category, "fail")
    readonly property int warns: Model.countBy(root.report, category, "warn")
    readonly property int notes: Model.countBy(root.report, category, "info")
    foreground: root.foreground
    implicitHeight: catText.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.selectTab(catRow.category)
    }
    Text {
      id: catText
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      text: Model.categoryLabel(catRow.category)
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      font.bold: true
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.rightMargin: Style.space(10)
      text: Model.pillarCounts(catRow.fails, catRow.warns, catRow.notes)
      color: catRow.fails ? root.urgent : (catRow.warns ? root.warnColor : root.dim)
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      font.bold: catRow.fails > 0
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
        visible: row.expanded && row.check !== null && row.check.detail !== ""
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
        visible: row.expanded && row.check !== null && row.check.detail !== ""
        width: parent.width
        text: row.check ? row.check.detail : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WrapAnywhere
      }
      Flow {
        visible: row.expanded && (row.runnable || row.undoable || row.reviewable)
        width: parent.width
        spacing: Style.space(8)
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
