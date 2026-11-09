"""Локальный прогон веток, которые нельзя проверить на живых доменах."""
import importlib.machinery, importlib.util, os, ssl, socket, subprocess, sys, tempfile, threading

sys.dont_write_bytecode = True

exitctl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exitctl")
workdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp()
loader = importlib.machinery.SourceFileLoader("exitctl", exitctl_path)
spec = importlib.util.spec_from_loader("exitctl", loader)
ex = importlib.util.module_from_spec(spec)
loader.exec_module(ex)

key, crt = os.path.join(workdir, "k.pem"), os.path.join(workdir, "c.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                "-out", crt, "-days", "2", "-subj", "/CN=sni-test.example",
                "-addext", "subjectAltName=DNS:sni-test.example"],
               check=True, capture_output=True)


def serve(alpn, max_tls=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(alpn)
    if max_tls:
        ctx.maximum_version = max_tls
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def loop():
        while True:
            c, _ = srv.accept()
            try:
                with ctx.wrap_socket(c, server_side=True) as s:
                    s.settimeout(1)
                    s.recv(4096)
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()
    return port


def run(title, port, https, cert=None):
    print("---", title)
    ex.SNI_PORT = port
    ex.resolve_ipv4 = lambda d: ["8.8.8.8"]  # чтобы пройти проверку публичного адреса
    real = socket.create_connection
    socket.create_connection = lambda addr, timeout=None: real(("127.0.0.1", port), timeout=timeout)
    ex.probe_http = lambda d, ip: https
    if cert:
        orig = ex.probe_tls
        ex.probe_tls = lambda d, ip: {**orig(d, ip), "cert": cert, "cert_error": None}
    rep = ex.sni_check("sni-test.example", "8.8.4.4", 1)
    socket.create_connection = real
    if cert:
        ex.probe_tls = orig
    for c in rep["checks"]:
        print(f'  {c["status"]:<4} {c["id"]}: {c["message"]}')
    print("  verdict =", rep["verdict"])
    return rep["verdict"]


ok200 = ("2", "200", "")
expect = {}
h2 = serve(["h2"])
expect["самоподписанный сертификат → fail"] = (run("самоподписанный", h2, ok200), "fail")
http1 = serve(["http/1.1"])
expect["сервер без h2 → fail"] = (run("без h2", http1, ok200), "fail")
tls12 = serve(["h2"], ssl.TLSVersion.TLSv1_2)
expect["только TLS 1.2 → fail"] = (run("TLS 1.2", tls12, ok200), "fail")

soon = {"notAfter": ssl.cert_time_to_seconds and "Jan  1 00:00:00 2100 GMT",
        "issuer": ((("organizationName", "Test CA"),),),
        "subject": ((("commonName", "sni-test.example"),),)}
expect["всё в порядке, но чужая сеть → warn"] = (run("годный сертификат", h2, ok200, soon), "warn")
expect["редирект → warn"] = (run("редирект", h2, ("2", "301", ""), soon), "warn")
expect["ответ 403 → fail"] = (run("403", h2, ("2", "403", ""), soon), "fail")
expect["нет curl → warn"] = (run("нет curl", h2, None, soon), "warn")

# сам probe_http без curl в системе
real_run = subprocess.run
def no_curl(*a, **k):
    raise FileNotFoundError("curl")
subprocess.run = no_curl
import types
fresh = importlib.util.module_from_spec(spec)
loader.exec_module(fresh)
expect["probe_http без curl → None"] = (str(fresh.probe_http("a.ru", "8.8.8.8")), "None")
subprocess.run = real_run

print("\nИТОГ")
bad = 0
for name, (got, want) in expect.items():
    mark = "OK " if got == want else "ОШИБКА"
    bad += got != want
    print(f"  {mark} {name} (получено {got})")
sys.exit(1 if bad else 0)
