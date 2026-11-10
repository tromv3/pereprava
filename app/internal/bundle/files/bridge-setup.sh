#!/usr/bin/env bash
# Настройка моста: Xray + VLESS Reality для клиентов, сайты РФ напрямую,
# остальное через выходы (их добавляет exitctl).
# Запуск:  bash bridge-setup.sh [SNI]     (exitctl должен лежать рядом)
set -euo pipefail

SNI="${1:-www.samsung.com}"
PORT=443
DIR=/usr/local/etc/xray/conf.d
INFO=/root/bridge-info.txt
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
[ -f "$HERE/exitctl" ] || { echo "Положите exitctl рядом с этим скриптом"; exit 1; }
if [ -f "$DIR/00_base.json" ]; then
  echo "$DIR/00_base.json уже существует — мост уже настроен. Удалите файл, если хотите начать заново."
  exit 1
fi

apt-get update -q
apt-get install -y -q curl openssl ufw python3
if ! command -v xray >/dev/null; then
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || \
  printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf
sysctl -p >/dev/null || true

install -m 755 "$HERE/exitctl" /usr/local/bin/exitctl

# Xray читает все файлы из папки conf.d
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
  "api": { "tag": "api", "listen": "127.0.0.1:10085", "services": ["HandlerService", "StatsService", "RoutingService"] },
  "policy": { "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } } },
  "inbounds": [{
    "tag": "in", "port": $PORT, "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision", "email": "client1" }],
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
  "observatory": {
    "subjectSelector": ["exit-"],
    "probeUrl": "https://www.gstatic.com/generate_204",
    "probeInterval": "1m"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "balancers": [{ "tag": "exits", "selector": ["exit-"], "strategy": { "type": "leastPing" } }],
    "rules": [
      { "protocol": ["bittorrent"], "outboundTag": "block" },
      { "domain": ["geosite:category-ru", "geosite:yandex", "geosite:vk", "geosite:mailru",
                   "domain:ru", "domain:su", "domain:xn--p1ai"], "outboundTag": "direct" },
      { "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct" },
      { "ruleTag": "to-exits", "inboundTag": ["in"], "balancerTag": "exits" }
    ]
  }
}
EOF
[ -f "$DIR/20_exits.json" ] || echo '{ "outbounds": [] }' > "$DIR/20_exits.json"

xray run -test -confdir "$DIR" >/dev/null
systemctl enable xray >/dev/null 2>&1
systemctl restart xray

# Еженедельное обновление списков geosite/geoip (понедельник, 04:00)
cat > /etc/cron.d/xray-geodata <<'EOF'
0 4 * * 1 root bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata >/dev/null 2>&1 && systemctl restart xray
EOF

ufw allow "${SSH_PORT:-22}/tcp" >/dev/null
ufw allow $PORT/tcp >/dev/null
ufw --force enable >/dev/null

IP=$(curl -4 -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
LINK="vless://$UUID@$IP:$PORT?type=tcp&security=reality&sni=$SNI&pbk=$PUB&sid=$SID&fp=chrome&flow=xtls-rprx-vision#Bridge"
printf "UUID=%s\nPRIVATE=%s\nPUBLIC=%s\nSHORTID=%s\nCLIENT_LINK=%s\n" "$UUID" "$PRIV" "$PUB" "$SID" "$LINK" > "$INFO"
chmod 600 "$INFO"

echo
echo "Мост готов. Xray: $(systemctl is-active xray)."
echo "Ссылка для клиента (сохранена в $INFO):"
echo
echo "$LINK"
echo
echo "Теперь добавьте выход:  exitctl add 'vless://...ссылка с выхода...' nl1"
