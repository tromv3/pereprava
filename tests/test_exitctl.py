"""exitctl user/status без настоящего Xray: subprocess заменён заглушкой."""
import contextlib, importlib.machinery, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, types

sys.dont_write_bytecode = True
exitctl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exitctl")
tmp = tempfile.mkdtemp()
os.environ.update(XRAY_CONF_DIR=tmp, XRAY_BIN="xray-stub", XRAY_NO_RESTART="1",
                  XRAY_USERS_META=os.path.join(tmp, "users-meta.json"), EXITCTL_CRON=os.path.join(tmp, "cron-exitctl"))
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
    elif cmd[1:2] == ["api"] and cmd[2] in ("adu", "rmu", "ado", "rmo", "adrules"):
        payload = json.load(open(cmd[-1])) if cmd[2] in ("adu", "ado", "adrules") else None
        api_calls.append((cmd[2], cmd[3:], payload))
        r.returncode = mode.get("live_rc", 0)
    elif cmd[0] == "systemctl" and cmd[1:2] == ["restart"]:
        restarts.append(1)
    elif cmd[1:2] == ["api"] and "-reset" in cmd:
        # Сбор с обнулением: отдаём накопившееся с прошлого сбора и обнуляем.
        if mode["api"]: r.stdout = json.dumps(mode.pop("reset_stats", {}))
        else: r.returncode = 1
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

# --- выходы и правила на лету
def live_bridge(services, exits):
    b = bridge_base(src_clients, "P", ["aa"])
    if services is not None:
        b["api"] = {"tag": "api", "listen": "127.0.0.1:10085", "services": services}
    put(b, exits)
def calls():
    return [x[0] for x in api_calls]
def link(name):
    return f"vless://dddd@198.51.100.3:443?type=tcp&security=reality&pbk=PK&sni=s.example&sid=01#{name}"
exits_path = os.path.join(tmp, "20_exits.json")

live_bridge(None, [exit_us]); reset()
c, o, e = cli("add", link("de1"))
expect("выходы без API: перезапуск", c == 0 and restarts and not api_calls, (o, e, api_calls))
live_bridge(["StatsService", "HandlerService"], [exit_us]); reset()
c, o, e = cli("add", link("de1"))
expect("выходы, старый API: RoutingService включён, перезапуск", c == 0 and "RoutingService" in read_base()["api"]["services"] and restarts and not api_calls, (o, e))
reset()
c, o, e = cli("add", link("de2"))
expect("add на лету: ado, затем adrules, без перезапуска", c == 0 and not restarts and calls() == ["ado", "adrules"] and "без перезапуска" in o, (o, e, calls()))
expect("add: в ado только новый выход", [x["tag"] for x in api_calls[0][2]["outbounds"]] == ["exit-de2"] if api_calls else False)
expect("add: в adrules вся маршрутизация из конфига", api_calls[1][2] == {"routing": read_base()["routing"]} if len(api_calls) > 1 else False)
expect("add: временные файлы удалены", all(not os.path.exists(x[1][-1]) for x in api_calls))
reset()
c, o, e = cli("use", "de2")
expect("use на лету: только adrules с outboundTag", c == 0 and not restarts and calls() == ["adrules"] and api_calls[0][2]["routing"]["rules"][-1].get("outboundTag") == "exit-de2", (o, e, calls()))
reset()
c, o, e = cli("remove", "de2")
expect("remove закреплённого: сначала правила с балансировщиком, потом rmo", c == 0 and not restarts and calls() == ["adrules", "rmo"]
       and api_calls[0][2]["routing"]["rules"][-1].get("balancerTag") == "exits" and api_calls[1][1][-1] == "exit-de2", (o, e, calls()))
reset()
c, o, e = cli("auto")
expect("auto на лету", c == 0 and not restarts and calls() == ["adrules"], (o, e, calls()))
reset()
c, o, e = cli("direct", "add", "example.ru")
expect("direct на лету: правило user-direct первым", c == 0 and not restarts and calls() == ["adrules"] and api_calls[0][2]["routing"]["rules"][0]["ruleTag"] == "user-direct", (o, e, calls()))
b_now, ex_now = read_base(), json.load(open(exits_path))
old_ex = json.loads(json.dumps(ex_now))
ex_now["outbounds"][0]["settings"]["vnext"][0]["port"] = 8443
reset()
with contextlib.redirect_stdout(io.StringIO()):
    restarted = ex.apply_routing_change(b_now, ex_now, old_ex)
expect("изменённый выход: rmo, ado, adrules", restarted is False and calls() == ["rmo", "ado", "adrules"], calls())
reset(); mode["live_rc"] = 1
c, o, e = cli("add", link("de3"))
expect("API выходов отказал: перезапуск", c == 0 and restarts and "de3" in open(exits_path).read(), (o, e))
mode["live_rc"] = 0
reset(); before = open(exits_path).read(); mode["test_rc"] = 1
c, o, e = cli("add", link("de4"))
expect("провал проверки выходов: откат, ни API, ни перезапуска", c == 1 and not api_calls and not restarts and open(exits_path).read() == before, (o, e))
mode["test_rc"] = 0

# --- exitctl health
real = {k: getattr(ex, k) for k in ("can_connect", "cert_report", "exits_health", "probe_tls", "resolve_ipv4")}
ex.can_connect = lambda h: True
ex.cert_report = lambda d: {"domain": d, "ok": True, "days_left": 60, "error": None}
ex.exits_health = lambda e: [{"name": o["tag"][5:], "ok": True, "ms": 10} for o in ex.exits_list(e)]
def health():
    c, o, e = cli("health", "--json")
    return c, (json.loads(o) if o else {}), e
put(bridge_base(src_clients, "P", ["aa"]), [exit_nl, exit_us])
c, h, e = health()
expect("health: всё в порядке, код 0", c == 0 and h["mode"] == "bridge" and h["problems"] == [] and h["warnings"] == [] and len(h["exits"]) == 2, (c, h, e))
ex.exits_health = lambda e: [{"name": "nl1", "ok": False, "ms": None}, {"name": "us1", "ok": True, "ms": 10}]
c, h, e = health()
expect("health: один выход недоступен — предупреждение", c == 0 and not h["problems"] and "nl1" in h["warnings"][0], h)
b = bridge_base(src_clients, "P", ["aa"]); b["routing"]["rules"][-1] = {"ruleTag": "to-exits", "inboundTag": ["in"], "outboundTag": "exit-nl1"}
put(b, [exit_nl, exit_us])
c, h, e = health()
expect("health: закреплён недоступный выход — проблема", c == 1 and any("закреплён" in p for p in h["problems"]), h)
ex.exits_health = lambda e: [{"name": "nl1", "ok": False, "ms": None}, {"name": "us1", "ok": False, "ms": None}]
c, h, e = health()
expect("health: все выходы недоступны", c == 1 and any("ни до одного" in p for p in h["problems"]), h)
put(bridge_base(src_clients, "P", ["aa"]), [])
ex.exits_health = real["exits_health"]
c, h, e = health()
expect("health: выходов нет", c == 1 and any("выходов нет" in p for p in h["problems"]), h)
ex.cert_report = lambda d: {"domain": d, "ok": True, "days_left": 5, "error": None}
put(bridge_base(src_clients, "P", ["aa"]), [exit_us]); ex.exits_health = lambda e: [{"name": "us1", "ok": True, "ms": 1}]
c, h, e = health()
expect("health: сертификат SNI скоро истекает — предупреждение", c == 0 and any("5 дн." in w for w in h["warnings"]), h)
ex.cert_report = lambda d: {"domain": d, "ok": False, "days_left": None, "error": "сайт не отвечает по TLS: timeout"}
c, h, e = health()
expect("health: сайт SNI сломан — проблема", c == 1 and any("site.example" in p for p in h["problems"]), h)
ex.cert_report = lambda d: {"domain": d, "ok": True, "days_left": 60, "error": None}
ex.can_connect = lambda h: h == "ya.ru"
c, h, e = health()
expect("health: мосту хватает ya.ru", c == 0 and not h["problems"], h)
simple = json.loads(json.dumps(base)); put(simple, [])
c, h, e = health()
expect("health: простому режиму закрыли зарубежный трафик", c == 1 and h["mode"] == "simple" and any("github.com" in p for p in h["problems"]) and h["exits"] is None, h)
ex.can_connect = lambda h: True
restore_run = ex.subprocess.run
ex.subprocess.run = lambda cmd, **k: types.SimpleNamespace(returncode=3, stdout="inactive", stderr="") if list(cmd)[:2] == ["systemctl", "is-active"] else restore_run(cmd, **k)
c, h, e = health()
expect("health: Xray не работает", c == 1 and h["xray"] is False and any("Xray не работает" in p for p in h["problems"]), h)
ex.subprocess.run = restore_run
c, o, e = cli("health")
expect("health текстом", c == 0 and "в порядке" in o, o)
expect("health: неверный параметр", cli("health", "--foo")[0] == 1)
c, h, e = health()
os.remove(os.path.join(tmp, "00_base.json"))
c2, h2, e2 = health()
expect("health: выход проверяется без выходов и пользователей", c2 == 0 and h2["mode"] == "exit" and h2["sni"]["domain"] == "x.org" and h2["exits"] is None, h2)
os.remove(ex_path)
c, h, e = health()
expect("health: не настроен — без проблем", c == 0 and h["installed"] is False and h["problems"] == [], h)
for k, v in real.items():
    setattr(ex, k, v)
ex.resolve_ipv4 = lambda d: ["192.0.2.10"]
def tls(version="TLSv1.3", err=None, cert_err=None, days=40):
    import time as _t
    exp = _t.strftime("%b %d %H:%M:%S %Y GMT", _t.gmtime(_t.time() + days * 86400 + 3600))
    return lambda d, ip: {"error": err, "cert_error": cert_err, "version": version, "cert": {"notAfter": exp}}
ex.probe_tls = tls()
r = ex.cert_report("site.example")
expect("cert_report: срок действия", r["ok"] and r["days_left"] == 40, r)
ex.probe_tls = tls(cert_err="certificate has expired")
expect("cert_report: истёкший сертификат", not ex.cert_report("site.example")["ok"])
ex.probe_tls = tls(version="TLSv1.2")
expect("cert_report: нет TLS 1.3", "TLS 1.3" in (ex.cert_report("site.example")["error"] or ""))
ex.probe_tls = tls(err="timed out")
expect("cert_report: не отвечает", "не отвечает" in (ex.cert_report("site.example")["error"] or ""))
ex.resolve_ipv4 = lambda d: []
expect("cert_report: нет DNS", ex.cert_report("site.example")["error"] == "домен не резолвится")
for k, v in real.items():
    setattr(ex, k, v)

# --- сроки и лимиты пользователей
ex.NO_RESTART = False
mode.update(api=True, test_rc=0, live_rc=0)
meta_path = os.environ["XRAY_USERS_META"]
cron_path = os.environ["EXITCTL_CRON"]
for f in (meta_path, cron_path):
    if os.path.exists(f): os.remove(f)
write_base(["StatsService", "HandlerService"])
open(os.path.join(tmp, "20_exits.json"), "w").write('{"outbounds": []}')
stats.clear()
def users():
    return {u["name"]: u for u in json.loads(cli("user", "list", "--json")[1])}
def active():
    return [x["email"] for x in read_base()["inbounds"][0]["settings"]["clients"]]
def gbs(n):
    return {"stat": [{"name": "user>>>anna>>>traffic>>>uplink", "value": int(n * ex.GB / 2)},
                     {"name": "user>>>anna>>>traffic>>>downlink", "value": int(n * ex.GB / 2)}]}
reset()
c, o, e = cli("user", "add", "anna", "--json")
anna_id = json.loads(o)["uuid"] if c == 0 else None
c, o, e = cli("user", "limit", "anna", "--traffic", "1", "--json")
u = json.loads(o) if c == 0 else {}
expect("limit: лимит 1 ГБ записан, пользователь активен", c == 0 and u.get("limit") == ex.GB and u.get("disabled") is None, (o, e))
expect("limit: cron для enforce поставлен", os.path.exists(cron_path) and "user enforce" in open(cron_path).read())
mode["reset_stats"] = gbs(1.2); reset()
c, o, e = cli("user", "enforce", "--json")
r = json.loads(o) if c == 0 else {}
expect("enforce: трафик собран, anna отключена без перезапуска", c == 0 and r.get("collected") and r.get("disabled") == [{"name": "anna", "reason": "traffic"}]
       and "anna" not in active() and not restarts and calls() == ["rmu"], (o, e, calls()))
u = users()
expect("list: отключённая видна, причина, трафик и прежняя ссылка", u["anna"]["disabled"] == "traffic" and u["anna"]["total"] >= ex.GB and u["anna"]["uuid"] == anna_id and u["anna"]["link"], u.get("anna"))
reset()
c, o, e = cli("user", "enforce", "--json")
expect("enforce повторно: ничего не меняет", c == 0 and json.loads(o)["disabled"] == [] and json.loads(o)["enabled"] == [] and not api_calls, (o, calls()))
reset()
c, o, e = cli("user", "limit", "anna", "--traffic", "2", "--json")
expect("лимит увеличен: anna снова включена с тем же UUID через adu", c == 0 and "anna" in active() and calls() == ["adu"]
       and api_calls[0][2]["inbounds"][0]["settings"]["clients"][0]["id"] == anna_id and json.loads(o)["disabled"] is None, (o, e, calls()))
reset()
c, o, e = cli("user", "limit", "anna", "--until", "2020-01-01", "--json")
expect("срок в прошлом: сразу отключена", c == 0 and json.loads(o)["disabled"] == "expired" and "anna" not in active() and calls() == ["rmu"], (o, e))
c, o, e = cli("user", "limit", "anna", "--days", "30", "--json")
u = json.loads(o) if c == 0 else {}
expect("продление на 30 дней: включена", c == 0 and u.get("disabled") is None and 29 * 86400 < u["expires"] - ex.time.time() <= 30 * 86400, (o, e))
c, o, e = cli("user", "limit", "anna", "--until", "2099-01-02T03:04:05+03:00", "--json")
expect("--until с поясом", c == 0 and json.loads(o)["expires"] == int(__import__("datetime").datetime.fromisoformat("2099-01-02T03:04:05+03:00").timestamp()), o)
c, o, e = cli("user", "limit", "anna", "--no-expiry", "--no-traffic", "--json")
u = json.loads(o) if c == 0 else {}
expect("сняты срок и лимит", c == 0 and u.get("expires") is None and u.get("limit") is None, o)
reset()
c, o, e = cli("user", "disable", "anna", "--json")
expect("disable: вручную", c == 0 and json.loads(o)["disabled"] == "manual" and "anna" not in active() and calls() == ["rmu"], (o, e))
expect("disable повторно — ошибка", cli("user", "disable", "anna")[0] == 1)
c, o, e = cli("user", "limit", "anna", "--traffic", "5", "--json")
expect("лимит не включает отключённого вручную", c == 0 and json.loads(o)["disabled"] == "manual" and "anna" not in active(), o)
mode["reset_stats"] = {}
c, o, e = cli("user", "enforce", "--json")
expect("enforce не включает отключённого вручную", c == 0 and "anna" not in active(), o)
reset()
c, o, e = cli("user", "enable", "anna", "--json")
expect("enable: включена", c == 0 and json.loads(o)["disabled"] is None and "anna" in active() and calls() == ["adu"], (o, e))
expect("enable включённого — ошибка", cli("user", "enable", "anna")[0] == 1)
cli("user", "disable", "anna"); cli("user", "limit", "anna", "--until", "2020-01-01")
c, o, e = cli("user", "enable", "anna")
expect("enable при истёкшем сроке — отказ с причиной", c == 1 and "истёк срок" in e and "anna" not in active(), (o, e))
cli("user", "limit", "anna", "--no-expiry")
expect("после снятия срока всё ещё отключена вручную", users()["anna"]["disabled"] == "manual" and "anna" not in active(), users()["anna"])
cli("user", "enable", "anna")
c, o, e = cli("user", "reset", "anna", "--json")
expect("reset: трафик обнулён", c == 0 and json.loads(o)["total"] == 0, o)
c, o, e = cli("user", "list")
expect("list текстом: колонки срока и состояния", c == 0 and "СОСТОЯНИЕ" in o and "активен" in o, o)
# Сорванное изменение: в файле ограничений отключена, а в конфиге есть — считается активной
m = json.load(open(meta_path)); m["users"]["anna"].update(disabled="traffic", client={"id": anna_id, "email": "anna"})
open(meta_path, "w").write(json.dumps(m))
expect("reconcile: есть в конфиге — значит активна", users()["anna"]["disabled"] is None and list(users()).count("anna") == 1)
# Перенос с ограничениями
cli("user", "add", "boris"); cli("user", "limit", "boris", "--traffic", "3"); cli("user", "limit", "boris", "--days", "10"); cli("user", "disable", "anna")
c, o, e = cli("migrate", "export")
exp2 = json.loads(o) if c == 0 else {}
expect("export: отключённая в списке с причиной, ограничения boris", any(x["email"] == "anna" and x.get("disabled") == "manual" for x in exp2.get("clients", []))
       and exp2.get("limits", {}).get("boris", {}).get("limit") == 3 * ex.GB, exp2.get("limits"))
mig2 = os.path.join(tmp, "m2.json"); open(mig2, "w").write(o)
write_base(["StatsService", "HandlerService"]); os.remove(meta_path)
c, o, e = cli("migrate", "import", mig2, "--json")
u = users()
expect("import: отключённая осталась отключённой, лимиты перенесены", c == 0 and u["anna"]["disabled"] == "manual" and "anna" not in active()
       and u["boris"]["limit"] == 3 * ex.GB and u["boris"]["expires"] and "boris" in active(), (o, e, u))
c, o, e = cli("user", "remove", "anna")
expect("remove отключённой: исчезает из списка и файла", c == 0 and "anna" not in users() and "anna" not in json.load(open(meta_path))["users"], (o, e))
for bad in (["--days", "0"], ["--until", "31.12.2026"], ["--days", "3", "--until", "2030-01-01"], ["--traffic", "-1"],
            ["--traffic", "1", "--no-traffic"], ["--until", "2030-01-01T10:00:00"]):
    expect(f"limit: неверно {bad}", cli("user", "limit", "boris", *bad)[0] == 1)
expect("limit: нет такого", cli("user", "limit", "nobody", "--days", "1")[0] == 1)
# Перезапуск Xray забирает счётчики в накопленный трафик
b = read_base(); b.pop("api"); open(os.path.join(tmp, "00_base.json"), "w").write(json.dumps(b)); reset()
before_total = users()["boris"]["total"]
mode["reset_stats"] = {"stat": [{"name": "user>>>boris>>>traffic>>>uplink", "value": 700}]}
c, o, e = cli("user", "add", "carl")
expect("перезапуск: счётчики сохранены до него", c == 0 and restarts and users()["boris"]["total"] == before_total + 700, (o, e, users()["boris"]))
mode["api"] = False
c, o, e = cli("user", "enforce", "--json")
expect("enforce без API: collected false, без ошибок", c == 0 and json.loads(o)["collected"] is False, (o, e))
mode["api"] = True

shutil.rmtree(tmp, ignore_errors=True)
print("Всего:", len(res), "ошибок:", res.count(False))
sys.exit(1 if False in res else 0)
