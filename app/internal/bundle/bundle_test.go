package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Вшитые файлы должны совпадать с корнем репозитория и не содержать CRLF.
func TestFilesMatchRepoRoot(t *testing.T) {
	for _, name := range Names {
		got, err := Read(name)
		if err != nil {
			t.Fatalf("%s не вшит: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s устарел: выполните go generate ./internal/bundle", name)
		}
		if bytes.Contains(got, []byte("\r")) {
			t.Errorf("%s содержит CR, на Linux он не запустится", name)
		}
	}
}
