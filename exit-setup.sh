#!/usr/bin/env bash
# Настройка выходного сервера: Xray + VLESS Reality, доступ только с моста.
# Запуск:  bash exit-setup.sh BRIDGE_IP [SNI]
set -euo pipefail

BRIDGE_IP="${1:-}"
SNI="${2:-www.samsung.com}"
PORT=443
CONF=/usr/local/etc/xray/config.json
INFO=/root/exit-info.txt

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
[ -n "$BRIDGE_IP" ] || { echo "Использование: bash exit-setup.sh BRIDGE_IP [SNI]"; exit 1; }

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

ufw allow "${SSH_PORT:-22}/tcp" >/dev/null
ufw allow from "$BRIDGE_IP" to any port $PORT proto tcp >/dev/null
ufw --force enable >/dev/null

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
