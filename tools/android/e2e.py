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
REACH = os.environ.get("E2E_REACH") == "1"
reach_want = []
if REACH:
    # a subscription whose servers all fail mihomo's check, each for its own
    # reason; the core must tell them apart (internal/app/reach.go)
    import base64, http.server, ssl, threading

    def listener():
        l = socket.socket()
        l.bind(("127.0.0.1", 0))
        l.listen(16)
        return l

    closed = listener()
    closed_port = closed.getsockname()[1]
    closed.close()  # nothing listens: refused
    silent = listener()  # accepts, never answers: TLS times out (DPI-like)
    held = []
    threading.Thread(target=lambda: [held.append(silent.accept()) for _ in iter(int, 1)], daemon=True).start()
    tls_l = listener()  # a TLS server: reachable, the VPN through it fails
    certdir = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days", "1",
                    "-keyout", certdir + "/k.pem", "-out", certdir + "/c.pem"], check=True, capture_output=True)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(certdir + "/c.pem", certdir + "/k.pem")

    def serve_tls():
        while True:
            conn, _ = tls_l.accept()
            try:
                t = sctx.wrap_socket(conn, server_side=True)
                held.append(t)
            except Exception:
                conn.close()

    threading.Thread(target=serve_tls, daemon=True).start()
    uid = "11111111-2222-3333-4444-555555555555"
    pbk = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()  # any valid x25519 key
    links = "\n".join([
        "vless://%s@127.0.0.1:%d?security=reality&sni=www.microsoft.com&pbk=%s&sid=01&type=tcp#Refused" % (uid, closed_port, pbk),
        "vless://%s@127.0.0.1:%d?security=reality&sni=www.microsoft.com&pbk=%s&sid=01&type=tcp#Silent" % (uid, silent.getsockname()[1], pbk),
        "trojan://pw@127.0.0.1:%d?sni=localhost#TLS" % tls_l.getsockname()[1],
        "hysteria2://pw@127.0.0.1:443?sni=x.example#HY",
    ])
    body = base64.b64encode(links.encode())

    class Sub(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    hs = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sub)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    os.makedirs(os.path.join(home, "data"), exist_ok=True)
    with open(os.path.join(home, "data", "settings.json"), "w") as f:
        json.dump({"subscriptions": [{"id": "e2e", "name": "E2E", "url": "http://127.0.0.1:%d/sub" % hs.server_address[1],
                                      "enabled": True, "interval_hours": 24}]}, f)
    reach_want = ["серверы: отвечают 0 из 4",
                  "недоступны из этой сети (адрес заблокирован или сервер выключен) — 1 («Refused» 127.0.0.1:%d)" % closed_port,
                  "подключение есть, TLS обрывается (блокировка протокола) — 1 («Silent»",
                  "доступны напрямую, но VPN через них не работает — 1 («TLS»",
                  "по UDP, напрямую не проверить — 1 («HY»"]
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
    if os.environ.get("E2E_LOOP") == "1":
        # make the probe addresses go into the TUN, as if the app were not
        # excluded from its VPN: the core must notice
        from pyroute2 import IPRoute
        ipr = IPRoute()
        idx = ipr.link_lookup(ifname="lze2e")[0]
        ipr.link("set", index=idx, state="up")
        try:
            ipr.addr("add", index=idx, address="198.18.0.1", mask=30)
        except Exception:
            pass
        for dst in ("192.0.2.77/32", "77.88.8.8/32"):
            try:
                ipr.route("add", dst=dst, oif=idx)
            except Exception as e:
                print("route", dst, e)
    return fd


def handle(m):
    global tun
    op, mid, args = m.get("op"), m.get("id"), m.get("args") or {}
    print("core:", json.dumps(m, ensure_ascii=False), flush=True)
    if op == "ready":
        state["ready"] = True
        state["url"] = args.get("url")
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
        env = open(os.path.join("/proc", pids[-1], "environ"), "rb").read().split(b"\0")
        # Android forbids netlink to apps: mihomo's loop check would break all UDP
        if b"DISABLE_LOOPBACK_DETECTOR=true" not in env:
            print("mihomo runs without DISABLE_LOOPBACK_DETECTOR")
            return False
        return "/dev/net/tun" in links
    except OSError:
        return False


ok = pump(time.time() + 120, lambda: state["vpn"] and state["dpi"])
if ok:
    ok = mihomo_has_tun()
    print("mihomo holds the TUN descriptor:", ok)
if ok and os.environ.get("E2E_LOOP") == "1":
    want = "проверка петли: TCP через VPN Лазейки (петля), UDP через VPN Лазейки (петля), DNS по UDP через VPN Лазейки (петля)"
    pump(time.time() + 15, lambda: want in open(os.path.join(home, "data", "logs", "lazeyka.log"), encoding="utf-8").read())
    ok = want in open(os.path.join(home, "data", "logs", "lazeyka.log"), encoding="utf-8").read()
    print("loop detected:", ok)
if ok and REACH:
    logf = os.path.join(home, "data", "logs", "lazeyka.log")
    has = lambda: all(w in open(logf, encoding="utf-8").read() for w in reach_want)
    pump(time.time() + 90, has)
    ok = has()
    text = open(logf, encoding="utf-8").read()
    print("reach lines:", [l for l in text.splitlines() if "серверы:" in l])
    print("dead servers explained:", ok, [w for w in reach_want if w not in text])
    if ok:
        # the server picker must show the checked servers with the reasons
        # (mihomo lists provider servers only under /providers)
        import http.cookiejar, urllib.request
        jar = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
        op.open(state["url"], timeout=10).read()
        groups = json.loads(op.open(state["url"].split("/?")[0] + "/api/groups", timeout=20).read())["groups"]
        blocked = [g for g in groups if g["name"] == "BLOCKED"][0]
        got = {o["name"]: (o["alive"], o["delay"], o.get("reach")) for o in blocked["options"] if o["kind"] == "sub"}
        print("BLOCKED servers:", got)
        want = {"Refused": (False, 0, "unreachable"), "Silent": (False, 0, "dpi"), "TLS": (False, 0, "open"), "HY": (False, 0, "udp")}
        ok = got == want
        print("picker shows the reasons:", ok)
        if os.environ.get("E2E_HOLD"):  # keep the core up to look at the UI
            open(os.environ["E2E_HOLD"], "w").write(state["url"])
            pump(time.time() + 120, lambda: not os.path.exists(os.environ["E2E_HOLD"]))
if ok:
    send({"event": "quit"})
    # pump stops at the socket's EOF, which comes a moment before the
    # process can be reaped: wait for the process itself
    pump(time.time() + 30, lambda: core.poll() is not None)
    try:
        core.wait(timeout=30)
    except subprocess.TimeoutExpired:
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
