package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	const secret = "пароль-p@ss'word"
	enc, err := Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if enc == secret || strings.Contains(enc, "word") {
		t.Fatalf("секрет не зашифрован: %q", enc)
	}
	got, err := Decrypt(enc)
	if err != nil || got != secret {
		t.Fatalf("got %q, err %v", got, err)
	}
	if e, _ := Encrypt(""); e != "" {
		t.Fatalf("пустая строка должна остаться пустой: %q", e)
	}
	if _, err := Decrypt("bm90LXZhbGlk"); err == nil {
		t.Fatal("чужие данные не должны расшифровываться")
	}
}

func TestStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := s.List(); err != nil || len(l) != 0 {
		t.Fatalf("новый список: %v %v", l, err)
	}
	a, err := s.Put(Server{Name: "a", Host: "1.1.1.1", Port: 22})
	if err != nil || a.ID == "" {
		t.Fatalf("put: %+v %v", a, err)
	}
	b, _ := s.Put(Server{Name: "b"})
	a.Name = "a2"
	if _, err := s.Put(a); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Get(a.ID); g.Name != "a2" {
		t.Fatalf("обновление: %+v", g)
	}
	if _, err := s.Put(Server{ID: "нет"}); err == nil {
		t.Fatal("несуществующий ID должен дать ошибку")
	}
	if err := s.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.List(); len(l) != 1 || l[0].ID != b.ID {
		t.Fatalf("удаление: %+v", l)
	}
	if err := os.WriteFile(filepath.Join(dir, "servers.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("повреждённый файл должен дать ошибку")
	}
}
