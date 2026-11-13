#!/usr/bin/env bash
# Снимает установку, сделанную этими скриптами: Xray, его конфиги и списки, exitctl,
# файлы со ссылками и ключами, свои правила ufw.
# Убирается только своё: по файлу состояния /usr/local/etc/xray/pereprava.state удаляются лишь
# правила ufw, которые добавили установщики; ufw выключается, только если его включали они;
# Xray, стоявший на сервере до установки, остаётся (без наших настроек).
# Установки прошлых версий (без файла состояния) снимаются по-старому: удаляются правила для 443/tcp.
# Зеркало apt и настройки BBR не трогаются.
# Запуск:  bash uninstall.sh
set -uo pipefail

STATE=/usr/local/etc/xray/pereprava.state
[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }

HAVE_STATE=0
PREEXISTING=0
UFW_OURS=0
RULES=()
if [ -f "$STATE" ]; then
  HAVE_STATE=1
  PREEXISTING=$(sed -n 's/^xray_preexisting=//p' "$STATE" | awk 'NR==1')
  UFW_OURS=$(sed -n 's/^ufw_enabled_by_us=//p' "$STATE" | awk 'NR==1')
  mapfile -t RULES < <(sed -n 's/^ufw=//p' "$STATE")
fi

systemctl disable --now xray >/dev/null 2>&1 || true
# Наши дополнения к службе убираем всегда; саму службу и программу — только если ставили их мы.
rm -rf /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d
if [ "$PREEXISTING" = 1 ]; then
  rm -rf /usr/local/etc/xray/conf.d /usr/local/etc/xray/conf.d.closed \
         /usr/local/etc/xray/exitctl-users.json /usr/local/etc/xray/exitctl-users.json.lock "$STATE"
  # Xray до установки был без настроек: возвращаем пустой конфиг.
  echo '{}' > /usr/local/etc/xray/config.json
else
  rm -rf /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
  rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray
  rm -f /usr/local/bin/xray
fi
systemctl daemon-reload

rm -f /usr/local/bin/exitctl /etc/cron.d/xray-geodata /etc/cron.d/exitctl-users \
      /root/bridge-info.txt /root/exit-info.txt /root/simple-info.txt

if command -v ufw >/dev/null; then
  if [ "$HAVE_STATE" = 1 ]; then
    for r in "${RULES[@]}"; do
      # shellcheck disable=SC2086  # правило — несколько слов: from X to any port N proto tcp
      ufw --force delete allow $r >/dev/null 2>&1 || true
    done
    if [ "$UFW_OURS" = 1 ]; then
      ufw --force disable >/dev/null
      UFW_MSG="Файрвол ufw выключен, как было до установки."
    else
      UFW_MSG="Убраны только правила ufw, добавленные установкой; остальные на месте."
    fi
  else
    for _ in $(seq 20); do
      n=$(ufw status numbered | sed -nE 's/^\[ *([0-9]+)\] 443\/tcp .*/\1/p' | awk 'NR==1')
      [ -n "$n" ] || break
      ufw --force delete "$n" >/dev/null
    done
    UFW_MSG="Файрвол ufw включён, SSH открыт."
  fi
else
  UFW_MSG=""
fi

if [ "$PREEXISTING" = 1 ]; then
  echo "Готово: наши настройки Xray удалены, сам Xray, стоявший до установки, оставлен (служба остановлена). $UFW_MSG"
else
  echo "Готово: Xray и его настройки удалены. $UFW_MSG"
fi
