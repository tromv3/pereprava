//go:build ignore

// Копирует серверные скрипты из корня репозитория в files/.
package main

import (
	"log"
	"os"
	"path/filepath"
)

func main() {
	if err := os.MkdirAll("files", 0o755); err != nil {
		log.Fatal(err)
	}
	for _, name := range []string{"exitctl", "simple-setup.sh", "bridge-setup.sh", "exit-setup.sh", "prepare-restricted.sh", "uninstall.sh", "update-geodata.sh"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", name))
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("files", name), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
