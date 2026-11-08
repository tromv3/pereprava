#!/usr/bin/env bash
# Подготовка VPS с ограниченным исходящим трафиком, до bridge-setup.sh и других скриптов установки.
# Запуск:  bash prepare-restricted.sh [ПАПКА]
# Если Debian/Ubuntu недоступны, apt переключается на mirror.yandex.ru.
# В ПАПКЕ лежат xray, geoip.dat и geosite.dat: без неё Xray не ставится.
set -euo pipefail

DIST="${1:-}"

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }

reachable() { timeout 6 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

apt_hosts_ok() {
  local files=(/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
  local host
  for host in $(sed -nE 's#.*https?://([^/ ]+)/.*#\1#p' "${files[@]}" 2>/dev/null | sort -u); do
    reachable "$host" 80 || return 1
  done
}

if ! apt_hosts_ok; then
  reachable mirror.yandex.ru 80 || { echo "Нет доступа ни к обычным репозиториям, ни к mirror.yandex.ru"; exit 1; }
  echo "Обычные репозитории недоступны, переключаю apt на mirror.yandex.ru"
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    [ -f "$f.vless-bak" ] || cp -p "$f" "$f.vless-bak"
    sed -i -E \
      -e 's#https?://deb\.debian\.org/debian-security#http://mirror.yandex.ru/debian-security#g' \
      -e 's#https?://security\.debian\.org(/debian-security)?#http://mirror.yandex.ru/debian-security#g' \
      -e 's#https?://deb\.debian\.org/debian#http://mirror.yandex.ru/debian#g' \
      -e 's#https?://([a-z]+\.)?archive\.ubuntu\.com/ubuntu#http://mirror.yandex.ru/ubuntu#g' \
      -e 's#https?://security\.ubuntu\.com/ubuntu#http://mirror.yandex.ru/ubuntu#g' \
      "$f"
  done
fi

[ -n "$DIST" ] || exit 0
command -v xray >/dev/null && exit 0

for f in xray geoip.dat geosite.dat; do
  [ -s "$DIST/$f" ] || { echo "В $DIST нет файла $f"; exit 1; }
done

install -m 755 "$DIST/xray" /usr/local/bin/xray
install -d /usr/local/share/xray /usr/local/etc/xray
install -m 644 "$DIST/geoip.dat" "$DIST/geosite.dat" /usr/local/share/xray/

cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
echo "Xray $(/usr/local/bin/xray version | awk 'NR==1{print $2}') установлен из файлов приложения."
