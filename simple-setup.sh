#!/usr/bin/env bash
# Простой режим: один VPS, клиенты подключаются к нему напрямую по VLESS Reality.
# Запуск:  bash simple-setup.sh SNI     (exitctl должен лежать рядом)
# SSH_PORT — порт SSH, который надо оставить открытым в ufw (по умолчанию 22).
set -euo pipefail

SNI="${1:-}"
SSH_PORT="${SSH_PORT:-22}"
PORT=443
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
if command -v ss >/dev/null && ss -ltnH "sport = :$PORT" | grep -q .; then
  echo "Порт $PORT уже занят, освободите его:"
  ss -ltnp "sport = :$PORT" || true
  exit 1
fi

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
  "api": { "tag": "api", "listen": "127.0.0.1:$API_PORT", "services": ["StatsService"] },
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

ufw allow "$SSH_PORT/tcp" >/dev/null
ufw allow $PORT/tcp >/dev/null
ufw --force enable >/dev/null

IP=$(curl -4 -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
LINK="vless://$UUID@$IP:$PORT?type=tcp&security=reality&sni=$SNI&pbk=$PUB&sid=$SID&fp=chrome&flow=xtls-rprx-vision#default"
printf "UUID=%s\nPRIVATE=%s\nPUBLIC=%s\nSHORTID=%s\nCLIENT_LINK=%s\n" "$UUID" "$PRIV" "$PUB" "$SID" "$LINK" > "$INFO"
chmod 600 "$INFO"

echo
echo "Сервер готов. Xray: $(systemctl is-active xray)."
echo "Ссылка для клиента сохранена в $INFO"
