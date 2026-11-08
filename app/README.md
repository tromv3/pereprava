# Приложение «Переправа»

Windows-приложение на Go и Wails v2, интерфейс на обычном JavaScript без фреймворка. Описание проекта — в [README в корне репозитория](../README.md).

- `app.go` — методы, которые вызывает интерфейс.
- `internal/remote` — выполнение команд на сервере по SSH.
- `internal/store` — список серверов в `%APPDATA%\pereprava\servers.json`, пароли зашифрованы DPAPI.
- `internal/bundle` — вшитые серверные скрипты (копия файлов из корня, обновляется `go generate ./internal/bundle`).
- `internal/xraydist` — скачивание Xray и списков сайтов на компьютере для серверов без доступа к GitHub.
- `frontend/` — интерфейс.

Сборка: `wails build -clean`, результат — `build/bin/pereprava.exe`. Режим разработки: `wails dev`.
