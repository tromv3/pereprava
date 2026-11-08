// Package bundle содержит серверные скрипты, вшитые в .exe.
// Источник — файлы в корне репозитория; files/ обновляет go generate.
package bundle

//go:generate go run sync.go

import (
	"embed"
	"path"
)

// Names — файлы, которые заливаются на сервер.
var Names = []string{"exitctl", "simple-setup.sh", "bridge-setup.sh", "exit-setup.sh", "prepare-restricted.sh", "uninstall.sh", "update-geodata.sh"}

//go:embed files
var files embed.FS

// Read возвращает содержимое вшитого файла.
func Read(name string) ([]byte, error) {
	return files.ReadFile(path.Join("files", name))
}
