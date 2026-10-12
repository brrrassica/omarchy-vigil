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

  readonly property int refreshMinutes: {
    var n = Number(setting("refreshMinutes", 30))
    return isFinite(n) ? Math.max(5, Math.min(1440, Math.round(n))) : 30
  }
  readonly property bool notifyOnNew: setting("notifyOnNew", true) === true
  // One bar per monitor means one copy of this widget per monitor. Only the
  // first screen's copy schedules audits, records findings and notifies.
  readonly property bool isPrimary: root.QsWindow.window !== null
    && root.QsWindow.window.screen === Quickshell.screens[0]

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color warnColor: Qt.tint(foreground, Qt.rgba(urgent.r, urgent.g, urgent.b, 0.55))
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
  readonly property var pending: pendingAction === "" ? null : Model.confirmation(pendingKind, pendingAction)

  readonly property var visibleChecks: tab === "overview"
    ? Model.topFindings(report, 6)
    : Model.checksFor(report, tab)
  readonly property bool busy: auditProc.running || fixProc.running

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
    if (check.fix.kind === "app") {
      // Opening an app you installed changes nothing, so it needs no confirmation.
      var argv = Model.appCommand(check.fix.action, report.apps)
      if (argv.length > 0) { Quickshell.execDetached(argv); root.close() }
      return
    }
    pendingKind = check.fix.kind
    pendingAction = check.fix.action
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
    if (kind === "helper") {
      if (!Model.isHelperAction(action) || fixProc.running) return
      fixBuffer = ""
      fixOverflow = false
      fixAction = action
      fixProc.command = ["/usr/bin/python3", "-I", "-S", root.helperPath, "fix", action]
      fixProc.running = true
      fixDeadline.restart()
      setStatus("Working…", false)
    } else if (kind === "terminal") {
      var launcher = Model.launcherPath(report.tools)
      var script = Model.terminalScript(action, report.tools)
      if (launcher === "" || script === "") { setStatus("This action is not available on this system.", true); return }
      Quickshell.execDetached([launcher, script])
      setStatus("Opened in a terminal. Vigil checks again when you reopen this panel.", false)
      root.close()
    }
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

  // The helper bounds its own children; these are the outer backstops.
  Timer { id: auditDeadline; interval: 90000; onTriggered: if (auditProc.running) { auditProc.signal(15); auditKill.restart() } }
  Timer { id: auditKill; interval: 2000; onTriggered: if (auditProc.running) auditProc.signal(9) }
  Timer { id: fixDeadline; interval: 120000; onTriggered: if (fixProc.running) { fixProc.signal(15); fixKill.restart() } }
  Timer { id: fixKill; interval: 2000; onTriggered: if (fixProc.running) fixProc.signal(9) }

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

  ShellIpc {
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
        if (t === "r" || t === "R") root.runAudit()
        else if (t === "f" || t === "F") root.requestFix(root.selectedCheck())
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
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
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

          Text {
            textFormat: Text.PlainText
            visible: root.statusMessage !== ""
            width: parent.width
            text: root.statusMessage
            color: root.statusIsError ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // Overview summary
          Column {
            visible: root.tab === "overview"
            width: parent.width
            spacing: Style.space(6)

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.report ? String(root.report.score) : "–"
              color: root.report && root.report.level === "fail" ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.displayLarge
            }
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.report
                ? "Security score out of 100. Checked " + root.report.generatedAt.replace("T", " ").substring(0, 16) + "."
                : "Vigil reads your settings locally. Nothing leaves this computer."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Repeater {
              model: root.report ? ["harden", "detect", "supply", "privacy", "care"] : []
              delegate: CategoryRow {
                required property var modelData
                width: column.width
                category: String(modelData)
              }
            }
            PanelSeparator { width: parent.width; foreground: root.foreground }
            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.visibleChecks.length > 0 ? "Fix these first" : (root.report ? "Nothing urgent. The other tabs list optional extras." : "")
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: root.tab !== "overview" && root.report !== null
            width: parent.width
            text: root.tab === "harden" ? "Can someone get in? Settings that make this machine harder to break into."
              : root.tab === "detect" ? "Is something bad already here? Signs of malware, virus scanning with ClamUI, and rootkit checks."
              : root.tab === "supply" ? "Can you trust what you installed? Packages, known vulnerabilities, known-compromised components and plugins."
              : root.tab === "privacy" ? "What does this machine tell the networks it joins?"
              : "Is the system tidy? Space you can reclaim and traces you can clear."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
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
            text: "R check again · ← → tabs · Enter details · F fix · Vigil " + (root.report ? root.report.version : "")
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

  component CategoryRow: CursorSurface {
    id: catRow
    property string category: ""
    readonly property int fails: Model.countBy(root.report, category, "fail")
    readonly property int warns: Model.countBy(root.report, category, "warn")
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
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      text: Model.categoryLabel(catRow.category) + "   "
        + (catRow.fails + catRow.warns === 0 ? "✓ all good"
           : (catRow.fails ? catRow.fails + " to fix" : "") + (catRow.fails && catRow.warns ? ", " : "")
             + (catRow.warns ? catRow.warns + " to improve" : ""))
      color: catRow.fails ? root.urgent : root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      elide: Text.ElideRight
    }
  }

  component CheckRow: CursorSurface {
    id: row
    property var check: null
    property bool selected: false
    property bool expanded: false
    readonly property bool runnable: check !== null && root.report !== null && Model.canRun(check.fix, root.report.tools, root.report.apps)
    signal clicked()

    hasCursor: selected
    foreground: root.foreground
    implicitHeight: rowColumn.implicitHeight + Style.spacing.rowPaddingX

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
        elide: Text.ElideRight
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
        text: row.check ? row.check.why : ""
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
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
      Button {
        visible: row.expanded && row.runnable
        text: row.check ? row.check.fix.label : ""
        foreground: root.foreground
        fontFamily: root.fontFamily
        bordered: true
        onClicked: root.requestFix(row.check)
      }
      Text {
        textFormat: Text.PlainText
        visible: row.expanded && !row.runnable && row.check !== null && row.check.fix.kind !== "none"
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
