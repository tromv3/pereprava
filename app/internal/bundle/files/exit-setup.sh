#!/usr/bin/env bash
# Настройка выходного сервера: Xray + VLESS Reality, доступ только с моста.
# Запуск:  [PORT=443] bash exit-setup.sh BRIDGE_IP [SNI]
# PORT — порт для моста (по умолчанию 443); SSH_PORT — порт SSH для ufw (по умолчанию 22).
# Чужой Xray, занятый порт и правила файрвола не трогаются: см. общий блок ниже.
set -euo pipefail

BRIDGE_IP="${1:-}"
SNI="${2:-www.samsung.com}"
PORT="${PORT:-443}"
CONF=/usr/local/etc/xray/config.json
INFO=/root/exit-info.txt

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
[ -n "$BRIDGE_IP" ] || { echo "Использование: bash exit-setup.sh BRIDGE_IP [SNI]"; exit 1; }

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
state_set role exit
state_set port "$PORT"

apt-get update -q
apt-get install -y -q curl openssl ufw
if ! command -v xray >/dev/null; then
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || \
  printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf
sysctl -p >/dev/null || true

UUID=$(xray uuid)
KEYS=$(xray x25519)
PRIV=$(echo "$KEYS" | grep -i '^private' | awk -F': ' '{print $2}')
PUB=$(echo "$KEYS"  | grep -Ei '^(public|password)' | awk -F': ' '{print $2}')
SID=$(openssl rand -hex 8)

cat > "$CONF" <<EOF
{
  "log": { "loglevel": "warning", "access": "none" },
  "inbounds": [{
    "port": $PORT, "protocol": "vless",
    "settings": { "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "dest": "$SNI:443", "serverNames": ["$SNI"],
        "privateKey": "$PRIV", "shortIds": ["$SID"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

xray run -test -config "$CONF" >/dev/null
systemctl enable --now xray >/dev/null 2>&1
systemctl restart xray

ufw_add "${SSH_PORT:-22}/tcp"
ufw_add from "$BRIDGE_IP" to any port "$PORT" proto tcp
ufw_finish

IP=$(curl -4 -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
NAME=$(hostname -s)
LINK="vless://$UUID@$IP:$PORT?type=tcp&security=reality&sni=$SNI&pbk=$PUB&sid=$SID&fp=chrome&flow=xtls-rprx-vision#$NAME"

printf "UUID=%s\nPRIVATE=%s\nPUBLIC=%s\nSHORTID=%s\nLINK=%s\n" "$UUID" "$PRIV" "$PUB" "$SID" "$LINK" > "$INFO"
chmod 600 "$INFO"

echo
echo "Готово. Xray: $(systemctl is-active xray). Порт $PORT открыт только для $BRIDGE_IP."
echo "Ссылка для моста (сохранена в $INFO):"
echo
echo "$LINK"
