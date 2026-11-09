"""exitctl user/status без настоящего Xray: subprocess заменён заглушкой."""
import contextlib, importlib.machinery, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, types

sys.dont_write_bytecode = True
exitctl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exitctl")
tmp = tempfile.mkdtemp()
os.environ.update(XRAY_CONF_DIR=tmp, XRAY_BIN="xray-stub", XRAY_NO_RESTART="1")
loader = importlib.machinery.SourceFileLoader("exitctl", exitctl_path)
spec = importlib.util.spec_from_loader("exitctl", loader)
ex = importlib.util.module_from_spec(spec)
loader.exec_module(ex)

base = {"inbounds": [{"tag": "in", "port": 443,
    "settings": {"clients": [{"id": "aaaaaaaa-0000-0000-0000-000000000000", "flow": "xtls-rprx-vision", "email": "default"}], "decryption": "none"},
    "streamSettings": {"realitySettings": {"privateKey": "PRIV", "serverNames": ["site.example"], "shortIds": ["ab12"]}}}],
    "outbounds": [], "routing": {"rules": []}}
open(os.path.join(tmp, "00_base.json"), "w").write(json.dumps(base))
stats = {"stat": [{"name": "user>>>default>>>traffic>>>uplink", "value": 100},
                  {"name": "user>>>default>>>traffic>>>downlink", "value": 2500}]}
mode = {"test_rc": 0, "api": True, "x25519": "PrivateKey: PRIV\nPassword (PublicKey): PUBKEY123\nHash32: zzz\n"}
api_calls, restarts = [], []
real_run = subprocess.run
def fake_run(cmd, **k):
    cmd = list(cmd)
    r = types.SimpleNamespace(returncode=0, stdout="", stderr="")
    if cmd[1:2] == ["run"]:
        r.returncode = mode["test_rc"]; r.stdout = "bad"
    elif cmd[1:2] == ["x25519"]:
        r.stdout = mode["x25519"]
    elif cmd[1:2] == ["api"] and cmd[2] in ("adu", "rmu"):
        payload = json.load(open(cmd[-1])) if cmd[2] == "adu" else None
        api_calls.append((cmd[2], cmd[3:], payload))
        r.returncode = mode.get("live_rc", 0)
    elif cmd[0] == "systemctl" and cmd[1:2] == ["restart"]:
        restarts.append(1)
    elif cmd[1:2] == ["api"]:
        if mode["api"]: r.stdout = json.dumps(stats)
        else: r.returncode = 1
    elif cmd[1:2] == ["version"]:
        r.stdout = "Xray 26.1.1 (Xray, Penetrates Everything.)\nmore"
    elif cmd[0] == "systemctl":
        r.stdout = "active"
    return r
ex.subprocess.run = fake_run
ex.detect_server_ip = lambda: "203.0.113.9"

def cli(*a):
    o, e, c = io.StringIO(), io.StringIO(), 0
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        try: ex.main(list(a))
        except SystemExit as x: c = x.code or 0
    return c, o.getvalue(), e.getvalue()

res = []
def expect(n, ok, extra=""):
    res.append(bool(ok)); print("OK " if ok else "ОШИБКА", n, extra if not ok else "")

c, o, e = cli("user", "list", "--json")
u = json.loads(o)
expect("list: один пользователь и трафик", c == 0 and u[0]["name"] == "default" and u[0]["uplink"] == 100 and u[0]["downlink"] == 2500, o)
expect("list: ссылка собрана", u[0]["link"] == "vless://aaaaaaaa-0000-0000-0000-000000000000@203.0.113.9:443?type=tcp&security=reality&sni=site.example&pbk=PUBKEY123&sid=ab12&fp=chrome&flow=xtls-rprx-vision#default", u[0]["link"])
c, o, e = cli("user", "add", "Phone 1", "--host", "vpn.example", "--json")
a = json.loads(o) if c == 0 else {}
expect("add --json: чистый JSON, имя нормализовано", c == 0 and a.get("name") == "phone-1", (c, o, e))
expect("add: --host в ссылке", "@vpn.example:443" in a.get("link", ""), a)
expect("add: служебные строки только в stderr", "Конфиг OK" in e and "Конфиг OK" not in o)
expect("add: новый пользователь с нулём трафика", a.get("uplink") == 0)
expect("add: повтор отклонён", cli("user", "add", "phone-1")[0] == 1)
expect("add: кириллица отклонена", cli("user", "add", "телефон")[0] == 1)
c, o, e = cli("user", "link", "phone-1", "--host", "x.example")
expect("link", c == 0 and o.startswith("vless://") and "@x.example:" in o, (o, e))
expect("link: нет пользователя", cli("user", "link", "nope")[0] == 1)
before = open(os.path.join(tmp, "00_base.json")).read()
mode["test_rc"] = 1
expect("add: при провале проверки ошибка", cli("user", "add", "bad-one")[0] == 1)
expect("add: откат конфига", open(os.path.join(tmp, "00_base.json")).read() == before)
mode["test_rc"] = 0
c, o, e = cli("user", "remove", "phone-1")
expect("remove", c == 0 and "phone-1" not in open(os.path.join(tmp, "00_base.json")).read(), (o, e))
c, o, e = cli("user", "remove", "default")
expect("remove: последнего нельзя", c == 1 and "последнего" in e)
c, o, e = cli("user", "remove", "nope"); expect("remove: нет такого", c == 1)
saved_stats = dict(stats)
for empty in ({}, {"stat": []}, {"stat": None}):
    stats.clear(); stats.update(empty)
    u = json.loads(cli("user", "list", "--json")[1])
    expect(f"list: API есть, трафика ещё не было {empty} — нули", u[0]["uplink"] == 0 and u[0]["downlink"] == 0, u[0])
stats.clear(); stats.update(saved_stats)
mode["api"] = False
u = json.loads(cli("user", "list", "--json")[1])
expect("list без API: трафик null", u[0]["uplink"] is None and u[0]["link"])
c, o, e = cli("user", "list"); expect("list текстом", c == 0 and "default" in o and "—" in o, o)
mode["x25519"] = ""
u = json.loads(cli("user", "list", "--json")[1])
expect("нет публичного ключа: link null", u[0]["link"] is None)
expect("user без аргументов", cli("user")[0] == 1)
expect("user неизвестный параметр", cli("user", "list", "--foo")[0] == 1)
expect("неверный --host", cli("user", "list", "--host", "a;b")[0] == 1)

c, o, e = cli("status", "--json")
s = json.loads(o)
expect("status: настроен, simple", c == 0 and s["installed"] and s["mode"] == "simple" and s["sni"] == "site.example" and s["users"] == 1 and s["exits"] == 0, o)
expect("status: xray", s["xray"]["active"] and s["xray"]["version"].startswith("Xray 26"))
expect("status: исходящий доступ", set(s["egress"]) == set(ex.EGRESS_HOSTS) and all(isinstance(v, bool) for v in s["egress"].values()), s.get("egress"))
caps = ex.capabilities
expect("роли: всё открыто", caps({h: True for h in ex.EGRESS_HOSTS}) == {"exit": True, "simple": True, "bridge": True})
expect("роли: закрыт зарубежный трафик — только мост", caps({"ya.ru": True}) == {"exit": False, "simple": False, "bridge": True})
expect("роли: один зарубежный сбой допустим", caps({h: h != "github.com" for h in ex.EGRESS_HOSTS})["exit"])
expect("роли: два сбоя — уже не выход", not caps({h: h not in ("github.com", "www.google.com") for h in ex.EGRESS_HOSTS})["exit"])
expect("роли: нет связи вообще", caps({}) == {"exit": False, "simple": False, "bridge": False})
c, o, e = cli("list", "--json")
expect("list --json без выходов", c == 0 and json.loads(o) == {"pinned": None, "exits": []}, o)
c, o, e = cli("check", "--json")
expect("check --json без выходов", c == 0 and json.loads(o) == [], o)
ex_path = os.path.join(tmp, "exit.json")
ex.EXIT_CONF = ex_path
real_cc = ex.can_connect
ex.can_connect = lambda h: h == "ya.ru"
c, o, e = cli("status")
expect("status текстом: заблокированные адреса", "github.com" in o and "нет связи" in o, o)
ex.can_connect = lambda h: True
c, o, e = cli("status")
expect("status текстом: всё доступно", "в порядке" in o, o)
ex.can_connect = real_cc
expect("глубина домена", ex.domain_depth("a.ru") == 0 and ex.domain_depth("www.a.ru") == 0 and ex.domain_depth("m.a.ru") == 1)
base_rep = {"details": {"ips": ["1.1.1.1"], "tcp_ms": 20.0}, "checks": []}
apex = ex.score_candidate("nicheparfum.ru", "1.1.1.1", base_rep, None)[0]
sub = ex.score_candidate("m.vimpelbank.ru", "1.1.1.1", base_rep, None)[0]
infra = ex.score_candidate("corpcdn.fastprovodnik.com", "1.1.1.1", base_rep, None)[0]
expect("оценка: основной домен выше поддомена и технического имени", apex > sub > infra, (apex, sub, infra))
for d in ("cf-us-01.loftclouds.com", "ru1.kukushka-me.click", "usa07.abvpn.net", "msk-3.edge.vefire.tv", "nl-2.example.org"):
    expect(f"VPN-нода: {d}", ex.reject_reason(d) == "имя похоже на VPN-ноду", ex.reject_reason(d))
for d in ("angelika-garden.ru", "nicheparfum.ru", "m.soberhouse.ru", "us.example.org", "de.wikipedia.org", "ru2023.com", "inner.techhost.ru"):
    expect(f"не VPN-нода: {d}", ex.reject_reason(d) is None, ex.reject_reason(d))
rnd = ex.score_candidate("kjsndckns.name", "1.1.1.1", base_rep, None)[0]
expect("оценка: случайное имя ниже обычного", rnd < apex and ex.score_candidate("angelika-garden.ru", "1.1.1.1", base_rep, None)[0] == apex, (rnd, apex))
c, o, e = cli("status"); expect("status текстом", c == 0 and "simple" in o, o)
expect("status неверно", cli("status", "--foo")[0] == 1)
d = json.loads(open(os.path.join(tmp, "00_base.json")).read())
d["routing"]["balancers"] = [{"tag": "exits"}]
open(os.path.join(tmp, "00_base.json"), "w").write(json.dumps(d))
expect("status: bridge", json.loads(cli("status", "--json")[1])["mode"] == "bridge")
os.remove(os.path.join(tmp, "00_base.json"))
s = json.loads(cli("status", "--json")[1])
expect("status: не настроен", s["installed"] is False and s["mode"] is None)
open(ex_path, "w").write("{}")
expect("status: пустой config.json — не настроен", json.loads(cli("status", "--json")[1])["installed"] is False)
open(ex_path, "w").write("{не json")
expect("status: битый config.json не падает", cli("status", "--json")[0] == 0)
open(ex_path, "w").write(json.dumps({"inbounds": [{"port": 443, "streamSettings": {"realitySettings": {"serverNames": ["x.org"]}}}]}))
s = json.loads(cli("status", "--json")[1])
expect("status: выход определён", s["installed"] and s["mode"] == "exit" and s["sni"] == "x.org" and s["port"] == 443, s)
expect("status текстом: выход", "exit" in cli("status")[1])
# --- изменения пользователей на лету (XRAY_NO_RESTART снимаем: перезапуск — заглушка systemctl)
ex.NO_RESTART = False
ex.time.sleep = lambda s: None
mode.update(api=True, x25519="PrivateKey: PRIV\nPassword: PUBKEY123\n")
def write_base(api):
    b = json.loads(json.dumps(base))
    if api is not None:
        b["api"] = {"tag": "api", "listen": "127.0.0.1:10085", "services": api}
    open(os.path.join(tmp, "00_base.json"), "w").write(json.dumps(b))
def read_base():
    return json.load(open(os.path.join(tmp, "00_base.json")))
def reset():
    api_calls.clear(); restarts.clear()

write_base(None); reset()
c, o, e = cli("user", "add", "old1", "--json")
expect("без API: перезапуск, без adu", c == 0 and restarts and not api_calls and json.loads(o)["restarted"] is True, (o, e, api_calls))

write_base(["StatsService"]); reset()
c, o, e = cli("user", "add", "up1", "--json")
expect("старый API: HandlerService включён, перезапуск", c == 0 and "HandlerService" in read_base()["api"]["services"] and restarts and not api_calls, (o, e))
reset()
c, o, e = cli("user", "add", "live1", "--json")
u = json.loads(o) if c == 0 else {}
added = api_calls[0][2]["inbounds"][0] if api_calls else {}
expect("на лету: adu без перезапуска", c == 0 and not restarts and api_calls and api_calls[0][0] == "adu" and u.get("restarted") is False, (o, e, api_calls))
expect("на лету: в adu только новый пользователь и тег in", added.get("tag") == "in" and [x["email"] for x in added["settings"]["clients"]] == ["live1"], added)
expect("на лету: пользователь записан в конфиг", "live1" in [x["email"] for x in read_base()["inbounds"][0]["settings"]["clients"]])
expect("на лету: временный файл удалён", not os.path.exists(api_calls[0][1][-1]) if api_calls else False)
reset()
c, o, e = cli("user", "remove", "live1")
expect("на лету: rmu -tag=in email", c == 0 and not restarts and api_calls and api_calls[0][0] == "rmu" and api_calls[0][1][-2:] == ["-tag=in", "live1"], (o, e, api_calls))
expect("на лету: удалён из конфига", "live1" not in [x["email"] for x in read_base()["inbounds"][0]["settings"]["clients"]])
reset(); mode["live_rc"] = 1
c, o, e = cli("user", "add", "fail1", "--json")
expect("API отказал: перезапуск", c == 0 and restarts and json.loads(o)["restarted"] is True, (o, e))
mode["live_rc"] = 0
reset(); before = open(os.path.join(tmp, "00_base.json")).read(); mode["test_rc"] = 1
c, o, e = cli("user", "add", "bad2", "--json")
expect("провал проверки: откат и ни adu, ни перезапуска", c == 1 and not api_calls and not restarts and open(os.path.join(tmp, "00_base.json")).read() == before, (o, e))
mode["test_rc"] = 0

# --- exitctl reach
import socket as _s
srv = _s.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); open_port = srv.getsockname()[1]
cl = _s.socket(); cl.bind(("127.0.0.1", 0)); closed_port = cl.getsockname()[1]; cl.close()
c, o, e = cli("reach", "127.0.0.1", str(open_port), "--json")
expect("reach: открытый порт", c == 0 and json.loads(o)["tcp"] == "open" and json.loads(o)["ok"], o)
c, o, e = cli("reach", "127.0.0.1", str(closed_port), "--json")
expect("reach: отказ — это тоже связь", c == 0 and json.loads(o)["tcp"] == "refused" and json.loads(o)["ok"], o)
real_cc_ = ex.socket.create_connection
def timeout_conn(*a, **k): raise _s.timeout()
ex.socket.create_connection = timeout_conn
c, o, e = cli("reach", "198.51.100.7", "22", "--json")
r = json.loads(o) if o else {}
expect("reach: таймаут при пинге — режет хостер", c == 1 and r.get("tcp") == "timeout" and r.get("icmp") and "хостер одного из серверов" in r.get("message", ""), (o, e))
ex.run_text = (lambda orig: (lambda *a: None if a[0] == "ping" else orig(*a)))(ex.run_text)
c, o, e = cli("reach", "198.51.100.7", "22")
expect("reach: ни TCP, ни пинга — текстом, код 1", c == 1 and "ни пинга" in o, o)
ex.socket.create_connection = real_cc_
srv.close()
for bad in (["reach"], ["reach", "a.b", "x"], ["reach", "a.b", "70000"], ["reach", "a;b", "22"]):
    expect(f"reach: неверные аргументы {bad[1:]}", cli(*bad)[0] == 1)

# --- контрольная сумма установленного exitctl и direct list --json
import hashlib as _h
tool = os.path.join(tmp, "installed-exitctl")
ex.INSTALLED_TOOL = tool
write_base(["StatsService", "HandlerService"])
expect("status: exitctl не установлен — null", json.loads(cli("status", "--json")[1])["tool_sha256"] is None)
open(tool, "wb").write(b"print(1)\n")
expect("status: контрольная сумма exitctl", json.loads(cli("status", "--json")[1])["tool_sha256"] == _h.sha256(b"print(1)\n").hexdigest())
ex.NO_RESTART = True
c, o, e = cli("direct", "list", "--json")
expect("direct list --json: пусто", c == 0 and json.loads(o) == [], o)
c, o, e = cli("direct", "add", "https://Example.RU/path")
c, o, e = cli("direct", "list", "--json")
expect("direct list --json: домен без схемы и пути", json.loads(o) == ["example.ru"], o)
c, o, e = cli("direct", "list")
expect("direct list текстом", o.strip() == "example.ru", o)
c, o, e = cli("direct", "remove", "example.ru")
expect("direct remove", c == 0 and json.loads(cli("direct", "list", "--json")[1]) == [], (o, e))

# --- перенос пользователей
ex.NO_RESTART = False  # раздел выше его включал: здесь считаем перезапуски
def bridge_base(clients, priv, sids, direct=None):
    b = json.loads(json.dumps(base))
    b["inbounds"][0]["settings"]["clients"] = clients
    b["inbounds"][0]["streamSettings"]["realitySettings"].update(privateKey=priv, shortIds=sids)
    b["routing"] = {"balancers": [{"tag": "exits", "selector": ["exit-"]}],
                    "rules": [{"ruleTag": "to-exits", "inboundTag": ["in"], "balancerTag": "exits"}]}
    if direct:
        b["routing"]["rules"].insert(0, {"ruleTag": "user-direct", "domain": direct, "outboundTag": "direct"})
    return b
def put(b, exits):
    open(os.path.join(tmp, "00_base.json"), "w").write(json.dumps(b))
    open(os.path.join(tmp, "20_exits.json"), "w").write(json.dumps({"outbounds": exits}))
exit_nl = {"tag": "exit-nl1", "protocol": "vless", "settings": {"vnext": [{"address": "198.51.100.1", "port": 443, "users": [{"id": "x"}]}]}}
exit_us = {"tag": "exit-us1", "protocol": "vless", "settings": {"vnext": [{"address": "198.51.100.2", "port": 443, "users": [{"id": "y"}]}]}}
src_clients = [{"id": "11111111-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision", "email": "anna"},
               {"id": "11111111-0000-0000-0000-000000000002", "flow": "xtls-rprx-vision", "email": "boris"},
               {"id": "11111111-0000-0000-0000-000000000003", "flow": "xtls-rprx-vision", "email": "client1"}]
put(bridge_base(src_clients, "SRCPRIV", ["aa11"], ["domain:gosuslugi.ru"]), [exit_nl, exit_us])
c, o, e = cli("migrate", "export")
exp = json.loads(o) if c == 0 else {}
expect("migrate export: всё на месте", exp.get("mode") == "bridge" and len(exp.get("clients", [])) == 3 and exp["reality"] == {"privateKey": "SRCPRIV", "shortIds": ["aa11"]} and exp["direct"] == ["domain:gosuslugi.ru"] and [x["tag"] for x in exp["exits"]] == ["exit-nl1", "exit-us1"], o)
mig = os.path.join(tmp, "m.json"); open(mig, "w").write(o)

# Целевой мост: свой client1 (другой UUID), свой выход us1, свои ключи
dst_clients = [{"id": "22222222-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision", "email": "client1"},
               {"id": "11111111-0000-0000-0000-000000000002", "flow": "xtls-rprx-vision", "email": "boris-old"}]
put(bridge_base(dst_clients, "DSTPRIV", ["bb22"]), [exit_us])
reset()
c, o, e = cli("migrate", "import", mig, "--json")
rep = json.loads(o) if c == 0 else {}
b2 = read_base(); ex2 = json.load(open(os.path.join(tmp, "20_exits.json")))
expect("import: добавлена только anna", rep.get("added") == ["anna"], rep)
expect("import: client1 (имя) и boris (UUID) пропущены", sorted(rep.get("skipped", [])) == ["boris", "client1"], rep)
expect("import: UUID anna сохранён", any(x["id"] == "11111111-0000-0000-0000-000000000001" and x["email"] == "anna" for x in b2["inbounds"][0]["settings"]["clients"]))
expect("import: ключи без --keys не тронуты", b2["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == "DSTPRIV" and rep.get("keys") is False)
expect("import: выход nl1 добавлен, us1 не задвоен", rep.get("exits_added") == ["nl1"] and [x["tag"] for x in ex2["outbounds"]] == ["exit-us1", "exit-nl1"], ex2)
expect("import: fallbackTag выставлен", b2["routing"]["balancers"][0].get("fallbackTag") == "exit-us1")
expect("import: сайт напрямую перенесён первым правилом", rep.get("direct_added") == 1 and b2["routing"]["rules"][0] == {"ruleTag": "user-direct", "domain": ["domain:gosuslugi.ru"], "outboundTag": "direct"})
expect("import: один перезапуск", len(restarts) == 1, restarts)

reset()
c, o, e = cli("migrate", "import", mig, "--json")
rep = json.loads(o)
expect("повторный import: ничего не добавлено и без перезапуска", rep["added"] == [] and rep["direct_added"] == 0 and rep["exits_added"] == [] and not restarts, (rep, restarts))

reset()
c, o, e = cli("migrate", "import", mig, "--keys", "--json")
rep = json.loads(o); rs = read_base()["inbounds"][0]["streamSettings"]["realitySettings"]
expect("import --keys: ключи заменены", rep["keys"] and rs["privateKey"] == "SRCPRIV" and rs["shortIds"] == ["aa11"] and restarts, rep)

# Простой целевой сервер: выходы и сайты напрямую не переносятся
simple = json.loads(json.dumps(base)); simple["inbounds"][0]["settings"]["clients"] = [{"id": "33333333-0000-0000-0000-000000000001", "email": "default"}]
put(simple, [])
c, o, e = cli("migrate", "import", mig, "--json")
rep = json.loads(o)
expect("import на простой: пользователи да, выходы и сайты нет", len(rep["added"]) == 3 and rep["exits_added"] == [] and len(rep["ignored"]) == 2 and json.load(open(os.path.join(tmp, "20_exits.json")))["outbounds"] == [], rep)
c, o, e = cli("migrate", "import", mig)
expect("import текстом", c == 0 and "Добавлены" in o, o)

bad = os.path.join(tmp, "bad.json"); open(bad, "w").write('{"version": 99}')
expect("import: чужая версия отклонена", cli("migrate", "import", bad)[0] == 1)
open(bad, "w").write("{не json")
expect("import: битый файл отклонён", cli("migrate", "import", bad)[0] == 1)
expect("import: нет файла", cli("migrate", "import", os.path.join(tmp, "nope.json"))[0] == 1)
expect("import: неизвестный параметр", cli("migrate", "import", mig, "--force")[0] == 1)
expect("migrate без аргументов", cli("migrate")[0] == 1)

shutil.rmtree(tmp, ignore_errors=True)
print("Всего:", len(res), "ошибок:", res.count(False))
sys.exit(1 if False in res else 0)
