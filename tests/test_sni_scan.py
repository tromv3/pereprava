"""Прогон sni scan на локальных TLS-серверах 127.0.0.x. Настоящая сеть не сканируется."""
import contextlib, importlib.machinery, importlib.util, io, json, os, socket, ssl, subprocess, sys, tempfile, threading

sys.dont_write_bytecode = True
exitctl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exitctl")
workdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp()
loader = importlib.machinery.SourceFileLoader("exitctl", exitctl_path)
spec = importlib.util.spec_from_loader("exitctl", loader)
ex = importlib.util.module_from_spec(spec)
loader.exec_module(ex)
PORT = 18443
ex.SNI_PORT = PORT


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


ca_k, ca_c = os.path.join(workdir, "ca.key"), os.path.join(workdir, "ca.crt")
sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_k, "-out", ca_c,
   "-days", "2", "-subj", "/CN=Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
   "-addext", "keyUsage=critical,keyCertSign")


def leaf(tag, names, signed=True):
    k, c = os.path.join(workdir, tag + ".key"), os.path.join(workdir, tag + ".crt")
    san = "subjectAltName=" + ",".join("DNS:" + n for n in names)
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c,
           "-days", "2", "-subj", "/CN=" + names[0], "-addext", san]
    if signed:
        cmd += ["-CA", ca_c, "-CAkey", ca_k]
    sh(*cmd)
    return c, k


def serve(ip, tag, names, signed=True, max_tls=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*leaf(tag, names, signed))
    if max_tls:
        ctx.maximum_version = max_tls
    srv = socket.create_server((ip, PORT))

    def loop():
        while True:
            c, _ = srv.accept()
            try:
                with ctx.wrap_socket(c, server_side=True) as s:
                    s.settimeout(0.5)
                    s.recv(100)
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()


real_ctx = ssl.create_default_context
def test_ctx(*a, **k):
    ctx = real_ctx(*a, **k)
    ctx.load_verify_locations(ca_c)
    return ctx
ssl.create_default_context = test_ctx

net = "127.0.0."
serve(net + "1", "self", ["own-server.ru"])
serve(net + "2", "good", ["example.ru", "www.example.ru"])
serve(net + "3", "svc", ["mail.hosting.ru", "cpanel.hosting.ru"])
serve(net + "4", "vpn", ["fastvpn-node.ru"])
serve(net + "5", "brand", ["google.com", "www.google.com"])
serve(net + "6", "far", ["far-away.ru"])
serve(net + "7", "selfsigned", ["selfsigned.ru"], signed=False)
serve(net + "8", "tls12", ["old-tls.ru"], max_tls=ssl.TLSVersion.TLSv1_2)
serve(net + "9", "redir", ["redirect-site.com"])
serve(net + "10", "fail", ["broken-site.ru"])
serve(net + "11", "wild", ["*.wildcard.org"])
serve(net + "12", "rdns", ["185-159-82-12.example.net"])
serve(net + "13", "shared", ["a-shop.ru", "b-shop.ru", "c-shop.ru", "d-shop.ru"])

dns = {"example.ru": ["127.0.0.2"], "www.example.ru": ["127.0.0.2"], "far-away.ru": ["8.8.8.8"],
       "redirect-site.com": ["127.0.0.9"], "broken-site.ru": ["127.0.0.10"],
       "wildcard.org": ["127.0.0.200"], "a-shop.ru": ["127.0.0.13"], "b-shop.ru": ["127.0.0.13"],
       "c-shop.ru": ["127.0.0.13"], "d-shop.ru": ["127.0.0.13"]}
ex.resolve_ipv4 = lambda d: dns.get(d, [])
calls = []


def fake_check(domain, server_ip, tries):
    calls.append(domain)
    http = "warn" if domain == "redirect-site.com" else "pass"
    checks = [{"id": "same_subnet", "status": "pass", "message": ""},
              {"id": "http", "status": http, "message": ""}]
    if domain == "broken-site.ru":
        checks.append({"id": "h2", "status": "fail", "message": "нет h2"})
    return {"domain": domain, "checks": checks,
            "details": {"ips": dns[domain], "tcp_ms": 3.0 if domain == "example.ru" else 20.0}}


real_check = ex.sni_check
ex.sni_check = fake_check
res = []
def expect(name, ok, extra=""):
    res.append(ok)
    print(("OK  " if ok else "ОШИБКА "), name, extra)


rep = ex.sni_scan("127.0.0.1", role="bridge", top=5, workers=8, max_checks=15, log=print)
print(json.dumps({k: rep[k] for k in ("subnet", "hosts_scanned", "hosts_with_tls")}, ensure_ascii=False))
for c in rep["candidates"]:
    print(" ", c["domain"], c["ip"], c["score"], c["reasons"])
for r in rep["rejected"]:
    print("  x", r["domain"], "-", r["reason"])
print()
doms = [c["domain"] for c in rep["candidates"]]
rej = {r["domain"]: r["reason"] for r in rep["rejected"]}
all_seen = set(doms) | set(rej)
expect("лучший кандидат example.ru", doms[:1] == ["example.ru"], doms)
expect("свой сервер не сканируется", "own-server.ru" not in all_seen)
expect("самоподписанный не попал в выдачу", "selfsigned.ru" not in all_seen)
expect("TLS 1.2 не попал в выдачу", "old-tls.ru" not in all_seen)
expect("служебные отброшены", "служебное" in rej.get("mail.hosting.ru", ""))
expect("VPN-имя отброшено", "VPN" in rej.get("fastvpn-node.ru", ""))
expect("бренд отброшен", "бренд" in rej.get("google.com", ""))
expect("обратная зона отброшена", "обратную" in rej.get("185-159-82-12.example.net", ""))
expect("DNS вне подсети отброшен", "вне /24" in rej.get("far-away.ru", ""))
expect("проверка fail отброшена", rej.get("broken-site.ru") == "нет h2")
expect("wildcard превращён в домен", "wildcard.org" in rej or "wildcard.org" in doms)
expect("редирект ниже обычного", doms.index("redirect-site.com") > doms.index("example.ru"))
expect("один домен на IP", len({c["ip"] for c in rep["candidates"]}) == len(rep["candidates"]))
expect("на хост не больше 2 проверок", sum(d.endswith("-shop.ru") for d in calls) == 2, calls)
expect("www не вытесняет основной домен", "www.example.ru" in calls and calls.index("example.ru") < calls.index("www.example.ru"))

calls.clear()
rep2 = ex.sni_scan("127.0.0.1", role="bridge", max_checks=2)
expect("лимит проверок соблюдён", len(calls) == 2, calls)
expect("пропуск по лимиту виден", any("--max-checks" in r["reason"] for r in rep2["rejected"]))
rep3 = ex.sni_scan("127.0.0.1", role="exit")
ex3 = {c["domain"]: c["score"] for c in rep3["candidates"]}
expect("роль exit штрафует .ru", ex3["example.ru"] < {c["domain"]: c["score"] for c in rep["candidates"]}["example.ru"])
expect("top ограничивает выдачу", len(ex.sni_scan("127.0.0.1", top=1)["candidates"]) == 1)

# Командная строка: сеть не трогаем, sni_scan подменён
def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            ex.main(["sni", "scan", *args])
        except SystemExit as e:
            code = e.code or 0
    return code, out.getvalue(), err.getvalue()


seen_args = []
def fake_scan(*a, **k):
    seen_args.append(a)
    return {**rep, "candidates": rep["candidates"] if a[0] != "9.9.9.9" else []}
ex.sni_scan = fake_scan
ex.detect_server_ip = lambda: None

c, o, e = cli("--ip", "8.8.8.8", "--role", "bridge", "--json")
expect("JSON разбирается, код 0", c == 0 and json.loads(o)["candidates"][0]["domain"] == "example.ru")
expect("предупреждение только в stderr", "жалобу" in e and "жалобу" not in o)
c, o, e = cli("--ip", "9.9.9.9")
expect("ничего не найдено: код 1 и совет", c == 1 and "exitctl sni check" in o, o.strip())
c, o, e = cli("--ip", "8.8.8.8")
expect("текстовый вывод со списком", c == 0 and "1. example.ru" in o)
expect("IP не определён: ошибка", cli()[0] == 1 and "--ip" in cli()[2])
expect("частный IP отклонён", cli("--ip", "192.168.1.5")[0] == 1)
expect("неверный IP отклонён", cli("--ip", "abc")[0] == 1)
expect("IPv6 отклонён", cli("--ip", "2001:4860::1")[0] == 1)
expect("неверная роль отклонена", cli("--ip", "8.8.8.8", "--role", "x")[0] == 1)
expect("неверный top отклонён", cli("--ip", "8.8.8.8", "--top", "0")[0] == 1)
expect("неизвестный параметр отклонён", cli("--foo")[0] == 1)

print("\nВсего:", len(res), "ошибок:", res.count(False))
sys.exit(1 if False in res else 0)
