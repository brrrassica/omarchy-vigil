"""Mechanical checks for the Omarchy plugin marketplace review rules.

These encode the findings reviewers raise most often, so a regression fails
here instead of in a review round. Run with the rest: python3 -m pytest tests
"""
import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((REPO / "manifest.json").read_text())
PLUGIN_ID = MANIFEST["id"]


def shipped_files():
    """Files `omarchy plugin add` would install (the git tree), minus .git."""
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, text=True, check=True).stdout.split()
    return [REPO / p for p in out if (REPO / p).is_file()]


def qml_files():
    return sorted(REPO.glob("*.qml")) + sorted(REPO.glob("**/*.qml"))


def test_every_text_sink_is_plain_text():
    missing = []
    for f in set(qml_files()):
        src = f.read_text()
        for m in re.finditer(r"\b(Text|Label|TextEdit|TextInput|StyledText)\s*\{", src):
            i, depth = m.end(), 1
            while i < len(src) and depth:
                depth += (src[i] == "{") - (src[i] == "}")
                i += 1
            if "textFormat: Text.PlainText" not in src[m.end():i]:
                missing.append("%s:%d" % (f.name, src[:m.start()].count("\n") + 1))
    assert missing == []


def test_no_unbounded_collectors_or_shell_strings_in_qml():
    for f in set(qml_files()):
        src = f.read_text()
        assert "StdioCollector" not in src, f
        assert "FileView" not in src, f
        assert not re.search(r'"(ba)?sh",\s*"-l?c"', src), f
        assert "bar.run(" not in src and "Util.execDetached" not in src, f
        for m in re.finditer(r"execDetached\(", src):
            rest = src[m.end():m.end() + 6]
            # Either a literal argv array, or `argv` built by Model.appCommand / Model.docsCommand,
            # each from a fixed table.
            assert rest.startswith("[") or (rest.startswith("argv)") and "var argv = Model.appCommand(" in src), \
                "%s: execDetached must take an argv array" % f.name


def test_process_commands_are_absolute():
    src = (REPO / "Panel.qml").read_text()
    for m in re.finditer(r"\.command = \[\s*\"([^\"]+)\"", src):
        assert m.group(1).startswith("/usr/bin/"), m.group(1)
    for m in re.finditer(r"execDetached\(\[\s*\"([^\"]+)\"", src):
        assert m.group(1).startswith("/usr/bin/"), m.group(1)
    assert src.count("clearEnvironment: true") == src.count("Process {")


def test_ids_agree():
    src = (REPO / "Panel.qml").read_text()
    assert 'moduleName: "%s"' % PLUGIN_ID in src
    assert 'ipcTarget: "%s"' % PLUGIN_ID in src
    for kind, entry in MANIFEST["entryPoints"].items():
        assert (REPO / entry).is_file(), entry
    assert MANIFEST["schemaVersion"] == 1
    assert not PLUGIN_ID.startswith("omarchy.")


def test_versions_agree():
    helper = (REPO / "bin" / "vigil").read_text()
    assert 'VERSION = "%s"' % MANIFEST["version"] in helper


def test_ipc_methods_take_no_parameters():
    src = (REPO / "Panel.qml").read_text()
    block = src[src.index("IpcHandler {"):]
    block = block[:block.index("\n  }\n")]
    for m in re.finditer(r"function (\w+)\(([^)]*)\)", block):
        assert m.group(2).strip() == "", m.group(0)


def test_tree_hygiene():
    banned = re.compile(r"(^|/)(AGENTS\.md|CLAUDE\.md|SKILL\.md|\.claude|\.codex|\.agents|\.gemini|__pycache__)(/|$)|\.pyc$")
    for f in shipped_files():
        rel = str(f.relative_to(REPO))
        assert not banned.search(rel), rel
        assert f.stat().st_size <= 512 * 1024 or rel == "preview.png", rel
        data = f.read_bytes()
        if f.suffix not in (".png", ".jpg", ".webp"):
            assert b"\x00" not in data, rel
        assert not data.startswith(b"\x7fELF"), rel
        if re.search(r"install|setup|uninstall", f.name, re.I):
            assert f.suffix not in (".png", ".jpg", ".gif", ".webp"), rel


def test_no_shared_tmp_or_shell_in_python():
    src = (REPO / "bin" / "vigil").read_text()
    # Actual calls and imports; the words themselves appear in the patterns
    # Vigil uses to detect them in other plugins.
    for bad in ("shell=True", "os.system(", "capture_output", "communicate(", "/tmp/", "urlopen(",
                "import requests", "import urllib", "import socket", "import http", "from urllib"):
        assert bad not in src, bad
    assert src.startswith("#!/usr/bin/python3 -I -S\n")


def test_helper_network_is_bounded_and_fixed():
    """The helper's only direct network use is two curl calls to fixed
    addresses (the AUR and Perplexity's Bumblebee catalogs), each with curl
    -q first, HTTPS only (also on redirects), a time and size limit, and no
    blind redirect following."""
    src = (REPO / "bin" / "vigil").read_text()
    calls = re.findall(r'run\(\[\s*"(/usr/bin/(?:curl|wget)[^"]*)"(.*?)\]', src, re.S)
    assert len(calls) == 2 and all(c[0] == "/usr/bin/curl" for c in calls)
    targets = []
    for _, args in calls:
        assert args.lstrip(", ").startswith('"-q"')
        for flag in ('"--proto", "=https"', '"--proto-redir", "=https"', '"--max-time"', '"--max-filesize"'):
            assert flag in args, flag
        assert '"-L"' not in args and "--location" not in args
        targets.append(re.search(r'"--", (\w+)', args).group(1))
    assert sorted(targets) == ["BUMBLEBEE_CATALOG_URL", "url"]
    assert "api.github.com" not in src
    assert src.count("https://aur.archlinux.org/rpc/v5/info?") == 1
    assert re.search(r'^BUMBLEBEE_CATALOG_URL = "https://codeload\.github\.com/perplexityai/bumblebee/tar\.gz/refs/heads/main"$',
                     src, re.M)


def test_readme_keeps_every_section():
    """Every section the README promises is there, once, in order (an edit once dropped six)."""
    heads = re.findall(r"^#{2,3} (.+)$", (REPO / "README.md").read_text(), re.M)
    want = ["Install", "Using it", "When Vigil runs what", "Every finding", "Lists you tick", "Undo", "Settings", "What Vigil checks",
            "Harden", "Detect", "Supply", "Privacy", "Care", "Accounts, history and old services",
            "How actions run", "What it costs your computer", "Where the data comes from", "Privacy",
            "Files Vigil writes", "Removing", "Requirements", "Development", "Credits", "License"]
    assert heads == want


def test_readme_documents_removal_and_files():
    readme = (REPO / "README.md").read_text()
    assert "omarchy plugin remove %s" % PLUGIN_ID in readme
    for path in ("~/.local/state/omarchy-vigil", "90-omarchy-vigil-opt-out", "/etc/sysctl.d/90-omarchy-vigil.conf"):
        assert path in readme, path
    assert (REPO / "LICENSE").is_file()


# Types a third-party plugin can use. qs.Ui exports exactly what its qmldir
# lists (Omarchy quattro, shell/Ui/qmldir); anything else in that folder, such
# as ShellIpc, is internal and fails to load in a plugin ("is not a type").
QS_UI_EXPORTS = {
    "BarIndicator", "BarIconButton", "BarIconContent", "BarWidget", "BackgroundMedia", "BorderOverlay",
    "BorderSurface", "Button", "ButtonGroup", "ConfirmDialog", "CursorSurface", "Dropdown", "IconContentBounds",
    "KeyboardPanel", "MultiSelect", "NumberField", "OpticalGlyph", "OverlayWindow", "Panel", "PanelActionButton",
    "PanelController", "PanelKeyCatcher", "PanelHero", "PanelSectionHeader", "PanelSeparator", "PanelSlider",
    "PanelToolTip", "PluginBarApi", "PointerMoveGate", "ScreenMoveRemap", "PopupCard", "SearchableDropdown",
    "SpeedTestOverlay", "TextField", "Toggle", "ToggleSwitch", "WidgetButton",
}
QT_TYPES = {"Item", "Text", "Column", "Row", "Flow", "Repeater", "Rectangle", "MouseArea", "Timer", "Flickable",
            "Connections", "ScrollBar", "Process", "SplitParser", "IpcHandler"}


def test_only_types_available_to_plugins():
    src = (REPO / "Panel.qml").read_text()
    inline = set(re.findall(r"^\s*component (\w+):", src, re.M))
    used = set(re.findall(r"(?:^|[:\s])([A-Z][A-Za-z0-9]+)\s*\{", src, re.M))
    unknown = used - QS_UI_EXPORTS - QT_TYPES - inline
    assert unknown == set(), unknown
