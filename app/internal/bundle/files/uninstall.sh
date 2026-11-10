#!/usr/bin/env bash
# Снимает установку, сделанную этими скриптами: Xray, его конфиги и списки, exitctl,
# файлы со ссылками и ключами, правила ufw для порта 443.
# Файрвол остаётся включённым с открытым SSH; зеркало apt и настройки BBR не трогаются.
# Запуск:  bash uninstall.sh
set -uo pipefail

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }

systemctl disable --now xray >/dev/null 2>&1 || true
rm -rf /etc/systemd/system/xray.service /etc/systemd/system/xray@.service \
       /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d
systemctl daemon-reload

rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray
rm -f /usr/local/bin/xray /usr/local/bin/exitctl /etc/cron.d/xray-geodata /etc/cron.d/exitctl-users \
      /root/bridge-info.txt /root/exit-info.txt /root/simple-info.txt

if command -v ufw >/dev/null; then
  for _ in $(seq 20); do
    n=$(ufw status numbered | sed -nE 's/^\[ *([0-9]+)\] 443\/tcp .*/\1/p' | awk 'NR==1')
    [ -n "$n" ] || break
    ufw --force delete "$n" >/dev/null
  done
fi

echo "Готово: Xray и его настройки удалены. Файрвол ufw включён, SSH открыт."
