#!/usr/bin/env bash
# Обновляет списки geoip.dat и geosite.dat из ПАПКИ: для сервера без доступа к GitHub,
# где не срабатывает еженедельный cron. Если Xray не принимает новые списки, старые возвращаются.
# Запуск:  bash update-geodata.sh ПАПКА
set -euo pipefail

SRC="${1:-}"
DST=/usr/local/share/xray

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
for f in geoip.dat geosite.dat; do
  [ -s "$SRC/$f" ] || { echo "В $SRC нет файла $f"; exit 1; }
done

if [ -d /usr/local/etc/xray/conf.d ]; then
  TEST=(-confdir /usr/local/etc/xray/conf.d)
else
  TEST=(-config /usr/local/etc/xray/config.json)
fi

install -d "$DST"
for f in geoip.dat geosite.dat; do
  [ -f "$DST/$f" ] && cp -p "$DST/$f" "$DST/$f.bak"
  install -m 644 "$SRC/$f" "$DST/$f"
done

if xray run -test "${TEST[@]}" >/dev/null 2>&1; then
  rm -f "$DST"/*.bak
  systemctl restart xray
  echo "Списки сайтов обновлены, Xray перезапущен."
else
  for f in geoip.dat geosite.dat; do
    [ -f "$DST/$f.bak" ] && mv "$DST/$f.bak" "$DST/$f"
  done
  echo "Xray не принял новые списки, возвращены старые."
  exit 1
fi
