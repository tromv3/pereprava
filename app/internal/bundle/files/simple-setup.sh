#!/usr/bin/env bash
# Простой режим: один VPS, клиенты подключаются к нему напрямую по VLESS Reality.
# Запуск:  bash simple-setup.sh SNI     (exitctl должен лежать рядом)
# SSH_PORT — порт SSH, который надо оставить открытым в ufw (по умолчанию 22).
# PORT — порт для клиентов (по умолчанию 443). Чужой Xray, занятый порт и правила файрвола не трогаются.
set -euo pipefail

SNI="${1:-}"
SSH_PORT="${SSH_PORT:-22}"
PORT="${PORT:-443}"
API_PORT=10085
DIR=/usr/local/etc/xray/conf.d
INFO=/root/simple-info.txt
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
[ -n "$SNI" ] || { echo "Использование: bash simple-setup.sh SNI"; exit 1; }
[ -f "$HERE/exitctl" ] || { echo "Положите exitctl рядом с этим скриптом"; exit 1; }
if [ -f "$DIR/00_base.json" ]; then
  echo "$DIR/00_base.json уже существует — сервер уже настроен. Удалите файл, если хотите начать заново."
  exit 1
fi

# --- Бережная установка: чужое не трогаем (одинаковый блок в exit-, bridge- и simple-setup.sh) ---
# Файл состояния: чем мы владеем. Его читает uninstall.sh, чтобы убрать только своё.
STATE=/usr/local/etc/xray/pereprava.state

state_get() { [ -f "$STATE" ] && sed -n "s/^$1=//p" "$STATE" | awk 'NR==1'; return 0; }
state_set() {
  mkdir -p "$(dirname "$STATE")"
  touch "$STATE" && chmod 600 "$STATE"
  { grep -v "^$1=" "$STATE" || true; echo "$1=$2"; } > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

# Наша ли установка Xray: файл состояния или ссылки, которые оставляли прошлые версии установщиков.
ours() {
  [ -f "$STATE" ] && return 0
  for f in /root/bridge-info.txt /root/exit-info.txt /root/simple-info.txt; do [ -f "$f" ] && return 0; done
  return 1
}

# Чужой Xray (свои настройки или работающая служба) не трогаем: установка его бы перенастроила.
check_foreign_xray() {
  ours && return 0
  local conf=/usr/local/etc/xray/config.json
  if { [ -s "$conf" ] && [ "$(tr -d ' \t\r\n' < "$conf")" != "{}" ]; } \
     || ls /usr/local/etc/xray/conf.d/*.json >/dev/null 2>&1 \
     || systemctl is-active --quiet xray 2>/dev/null; then
    echo "На сервере уже работает Xray с чужими настройками (/usr/local/etc/xray, служба xray)."
    echo "Установка его бы перенастроила, поэтому остановлена. Используйте другой сервер или снимите тот Xray сами."
    exit 1
  fi
}

# Порт для клиентов: число, не SSH и не API Xray, свободен (или его уже слушает наш же Xray).
check_port() {
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "PORT — число от 1 до 65535"; exit 1
  fi
  if [ "$PORT" = "${SSH_PORT:-22}" ] || [ "$PORT" = 10085 ]; then
    echo "Порт $PORT занят SSH или API Xray: выберите другой (PORT=...)"; exit 1
  fi
  command -v ss >/dev/null || return 0
  local busy
  busy=$(ss -ltnpH "sport = :$PORT" 2>/dev/null || true)
  [ -z "$busy" ] && return 0
  if ours && grep -q '"xray"' <<<"$busy"; then return 0; fi
  echo "Порт $PORT уже занят другой программой:"
  echo "$busy"
  echo "Выберите другой порт (PORT=...): программу на сервере установка не трогает."
  exit 1
}

# Запоминаем до установки: был ли Xray и был ли включён ufw. Повторный запуск сохраняет первые значения.
remember_before() {
  if [ -z "$(state_get xray_preexisting)" ]; then
    if ours; then state_set xray_preexisting 0          # ставили прошлые версии установщиков
    elif command -v xray >/dev/null; then state_set xray_preexisting 1
    else state_set xray_preexisting 0; fi
  fi
  UFW_WAS_ACTIVE=0
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then UFW_WAS_ACTIVE=1; fi
}

# ufw allow ...: правило записывается как наше, если ufw не ответил «Skipping» (правило уже было).
# Выключенный ufw отвечает «Rules updated», включённый — «Rule added».
ufw_add() {
  local out
  out=$(ufw allow "$@" 2>&1) || { echo "$out"; return 1; }
  if ! grep -q 'Skipping' <<<"$out" && ! grep -qxF "ufw=$*" "$STATE" 2>/dev/null; then
    echo "ufw=$*" >> "$STATE"
  fi
}

# Включение ufw. Если он был выключен, сначала разрешаем всё, что уже слушает сеть (кроме порта
# Xray и адресов только для этого компьютера): иначе включение отрезало бы сайты, панели и прочее.
ufw_finish() {
  [ "$UFW_WAS_ACTIVE" = 1 ] && return 0
  local line addr port proto
  for proto in tcp udp; do
    while read -r line; do
      addr=${line%:*}; port=${line##*:}
      case "$addr" in 127.*|"[::1]"|*%lo|"[::ffff:127."*) continue ;; esac
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      [ "$port" = "$PORT" ] && continue
      ufw_add "$port/$proto" >/dev/null
    done < <(if [ $proto = tcp ]; then ss -H -ltn; else ss -H -lun; fi 2>/dev/null | awk '{print $4}' | sort -u)
  done
  ufw --force enable >/dev/null
  state_set ufw_enabled_by_us 1
}
# --- конец общего блока ---

check_foreign_xray
check_port
remember_before
state_set role simple
state_set port "$PORT"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl openssl ufw python3
if ! command -v xray >/dev/null; then
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || \
  printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf
sysctl -p >/dev/null || true

install -m 755 "$HERE/exitctl" /usr/local/bin/exitctl

mkdir -p /etc/systemd/system/xray.service.d "$DIR"
cat > /etc/systemd/system/xray.service.d/99-confdir.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -confdir $DIR
EOF
systemctl daemon-reload

UUID=$(xray uuid)
KEYS=$(xray x25519)
PRIV=$(echo "$KEYS" | grep -i '^private' | awk -F': ' '{print $2}')
PUB=$(echo "$KEYS"  | grep -Ei '^(public|password)' | awk -F': ' '{print $2}')
SID=$(openssl rand -hex 8)

cat > "$DIR/00_base.json" <<EOF
{
  "log": { "loglevel": "warning", "access": "none" },
  "stats": {},
  "api": { "tag": "api", "listen": "127.0.0.1:$API_PORT", "services": ["HandlerService", "StatsService", "RoutingService"] },
  "policy": { "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } } },
  "inbounds": [{
    "tag": "in", "port": $PORT, "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision", "email": "default" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "dest": "$SNI:443", "serverNames": ["$SNI"],
        "privateKey": "$PRIV", "shortIds": ["$SID"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "rules": [
      { "protocol": ["bittorrent"], "outboundTag": "block" },
      { "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
EOF
[ -f "$DIR/20_exits.json" ] || echo '{ "outbounds": [] }' > "$DIR/20_exits.json"

xray run -test -confdir "$DIR" >/dev/null
systemctl enable xray >/dev/null 2>&1
systemctl restart xray

# Учёт трафика, сроки и лимиты пользователей: каждые 5 минут (exitctl user enforce)
cat > /etc/cron.d/exitctl-users <<'EOF'
# exitctl: учёт трафика, сроки и лимиты пользователей
*/5 * * * * root /usr/local/bin/exitctl user enforce >/dev/null 2>&1
EOF

ufw_add "$SSH_PORT/tcp"
ufw_add "$PORT/tcp"
ufw_finish

IP=$(curl -4 -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
LINK="vless://$UUID@$IP:$PORT?type=tcp&security=reality&sni=$SNI&pbk=$PUB&sid=$SID&fp=chrome&flow=xtls-rprx-vision#default"
printf "UUID=%s\nPRIVATE=%s\nPUBLIC=%s\nSHORTID=%s\nCLIENT_LINK=%s\n" "$UUID" "$PRIV" "$PUB" "$SID" "$LINK" > "$INFO"
chmod 600 "$INFO"

echo
echo "Сервер готов. Xray: $(systemctl is-active xray)."
echo "Ссылка для клиента сохранена в $INFO"
