#!/usr/bin/env python3
"""End-to-end check of the Android core on Linux (run as root on CI).

Plays the Android app: listens on the host socket, starts the core with the
same environment the app sets, answers tun_open with a real TUN descriptor
(as VpnService would) and waits until mihomo reports the VPN up and ByeDPI
running. Usage: e2e.py CORE MIHOMO BYEDPI
"""
import fcntl, json, os, select, shutil, socket, struct, subprocess, sys, tempfile, time

core_bin, mihomo, byedpi = sys.argv[1:4]
name = "lazeyka-e2e-%d" % os.getpid()
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind("\0" + name)
srv.listen(1)
home = tempfile.mkdtemp(prefix="lz-e2e-")
env = dict(os.environ, LAZEYKA_HOST_SOCKET="@" + name, LAZEYKA_HOME=home, LAZEYKA_MIHOMO=mihomo,
           LAZEYKA_BYEDPI=byedpi, LAZEYKA_OSVER="15", LAZEYKA_MODEL="CI", LAZEYKA_DEVICE_ID="ci",
           LAZEYKA_DNS="8.8.8.8", LAZEYKA_AUTOSTART="0")
core = subprocess.Popen([core_bin], env=env)
srv.settimeout(20)
c, _ = srv.accept()
c.setblocking(False)
buf = b""
tun = None
state = {"ready": False, "vpn": False, "dpi": False, "tun_opened": 0}


def send(o, fds=None):
    data = (json.dumps(o, ensure_ascii=False) + "\n").encode()
    c.setblocking(True)
    if fds:
        socket.send_fds(c, [data], fds)
    else:
        c.sendall(data)
    c.setblocking(False)


def open_tun():
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", b"lze2e", 0x0001 | 0x1000))  # TUNSETIFF, IFF_TUN|IFF_NO_PI
    if shutil.which("ip"):  # VpnService would also set the address; mihomo works either way
        subprocess.run(["ip", "addr", "replace", "198.18.0.1/30", "dev", "lze2e"], check=True)
        subprocess.run(["ip", "link", "set", "lze2e", "up"], check=True)
    return fd


def handle(m):
    global tun
    op, mid, args = m.get("op"), m.get("id"), m.get("args") or {}
    print("core:", json.dumps(m, ensure_ascii=False), flush=True)
    if op == "ready":
        state["ready"] = True
        send({"event": "connect"})
    elif op == "status" and not args.get("notify"):
        state["vpn"] = args.get("mode") == "on" and args.get("vpn_on")
        state["dpi"] = bool(args.get("dpi_on"))
    elif op == "tun_open":
        assert args.get("mtu") == 1500 and args.get("address4") == "198.18.0.1/30", args
        assert "ru.rostel" in args.get("bypass_apps", []), args
        if tun is None:
            tun = open_tun()
        state["tun_opened"] += 1
        send({"id": mid, "ok": True}, [tun])
    elif op == "tun_close":
        send({"id": mid, "ok": True})
    elif op == "apps":
        send({"id": mid, "ok": True, "data": []})
    elif mid:
        send({"id": mid, "ok": True})


def pump(until, stop):
    """Serves the core until stop() or the deadline; False if the core went away."""
    global buf
    while time.time() < until:
        if stop():
            return True
        if core.poll() is not None:
            return False
        r, _, _ = select.select([c], [], [], 0.5)
        if r:
            chunk = c.recv(65536)
            if not chunk:
                return False
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    handle(json.loads(line))
    return stop()


def mihomo_has_tun():
    for _ in range(10):
        if _mihomo_has_tun():
            return True
        pump(time.time() + 1, lambda: False)
    return False


def _mihomo_has_tun():
    log = open(os.path.join(home, "data", "logs", "lazeyka.log"), encoding="utf-8").read()
    pids = [l.split("pid ")[1].rstrip(")") for l in log.splitlines() if "mihomo запущен (pid" in l]
    if not pids:
        return False
    fds = os.path.join("/proc", pids[-1], "fd")
    try:
        links = [os.readlink(os.path.join(fds, f)) for f in os.listdir(fds)]
        print("mihomo", pids[-1], "fds:", links, flush=True)
        return "/dev/net/tun" in links
    except OSError:
        return False


ok = pump(time.time() + 120, lambda: state["vpn"] and state["dpi"])
if ok:
    ok = mihomo_has_tun()
    print("mihomo holds the TUN descriptor:", ok)
if ok:
    send({"event": "quit"})
    pump(time.time() + 30, lambda: core.poll() is not None)
    if core.poll() is None:
        print("core did not quit")
        ok = False
if core.poll() is None:
    core.kill()
log = os.path.join(home, "data", "logs", "lazeyka.log")
if os.path.exists(log):
    print("---- lazeyka.log ----")
    print(open(log, encoding="utf-8").read()[-6000:])
print("E2E", "OK" if ok else "FAILED", state)
sys.exit(0 if ok else 1)
