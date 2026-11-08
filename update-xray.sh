#!/usr/bin/env bash
# Обновляет Xray из ПАПКИ (файл xray): для сервера без доступа к GitHub или чтобы обновить из приложения.
# Новая версия сначала проверяет текущий конфиг; если она не запустилась, возвращается старая.
# Запуск:  bash update-xray.sh ПАПКА
set -euo pipefail

SRC="${1:-}"
BIN=/usr/local/bin/xray

[ "$(id -u)" = 0 ] || { echo "Запустите от root"; exit 1; }
[ -s "$SRC/xray" ] || { echo "В $SRC нет файла xray"; exit 1; }
[ -x "$BIN" ] || { echo "Xray не установлен: сначала настройте сервер"; exit 1; }

if [ -d /usr/local/etc/xray/conf.d ]; then
  TEST=(-confdir /usr/local/etc/xray/conf.d)
else
  TEST=(-config /usr/local/etc/xray/config.json)
fi

OLD=$("$BIN" version | awk 'NR==1{print $2}')
install -m 755 "$SRC/xray" "$BIN.new"
NEW=$("$BIN.new" version | awk 'NR==1{print $2}')

if ! "$BIN.new" run -test "${TEST[@]}" >/dev/null 2>&1; then
  rm -f "$BIN.new"
  echo "Xray $NEW не принимает текущий конфиг, оставлен $OLD."
  exit 1
fi

cp -p "$BIN" "$BIN.bak"
mv "$BIN.new" "$BIN"
systemctl restart xray
sleep 2
if [ "$(systemctl is-active xray)" != active ]; then
  mv "$BIN.bak" "$BIN"
  systemctl restart xray
  echo "Xray $NEW не запустился, возвращён $OLD."
  exit 1
fi
rm -f "$BIN.bak"

if [ "$OLD" = "$NEW" ]; then
  echo "Xray $NEW уже последней версии, переустановлен и перезапущен."
else
  echo "Xray обновлён: $OLD → $NEW."
fi
