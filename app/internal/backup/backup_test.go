package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const secret = `{"version":1,"clients":[{"id":"11111111-0000-0000-0000-000000000001","email":"anna"}],"reality":{"privateKey":"SECRETKEY"}}`

func TestRoundTrip(t *testing.T) {
	content, err := Seal([]byte(secret), "пароль-123", "Русский мост", "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("SECRETKEY")) || bytes.Contains(content, []byte("anna")) {
		t.Fatal("секреты видны в файле открытым текстом")
	}
	h, err := Inspect(content)
	if err != nil || h.Server != "Русский мост" || h.Host != "203.0.113.5" {
		t.Fatalf("заголовок: %+v %v", h, err)
	}
	h, plain, err := Open(content, "пароль-123")
	if err != nil || string(plain) != secret || h.Server != "Русский мост" {
		t.Fatalf("расшифровка: %q %v", plain, err)
	}
}

func TestWrongPasswordAndTampering(t *testing.T) {
	content, _ := Seal([]byte(secret), "пароль-123", "мост", "203.0.113.5")
	if _, _, err := Open(content, "пароль-124"); !errors.Is(err, ErrPassword) {
		t.Fatalf("неверный пароль: %v", err)
	}

	// Подмена открытого заголовка тоже обнаруживается.
	var f map[string]any
	json.Unmarshal(content, &f)
	f["server"] = "другой сервер"
	changed, _ := json.Marshal(f)
	if _, _, err := Open(changed, "пароль-123"); !errors.Is(err, ErrPassword) {
		t.Fatalf("подмена заголовка не обнаружена: %v", err)
	}

	// Порча данных.
	json.Unmarshal(content, &f)
	data := f["data"].(string)
	f["data"] = "A" + data[1:]
	if data[0] == 'A' {
		f["data"] = "B" + data[1:]
	}
	broken, _ := json.Marshal(f)
	if _, _, err := Open(broken, "пароль-123"); err == nil {
		t.Fatal("испорченные данные расшифровались")
	}
}

func TestRejects(t *testing.T) {
	if _, err := Seal([]byte(secret), "короткий", "м", "h"); err != nil {
		t.Fatalf("8 символов должно хватать: %v", err)
	}
	if _, err := Seal([]byte(secret), "1234567", "м", "h"); err == nil {
		t.Fatal("короткий пароль должен отклоняться")
	}
	if _, err := Inspect([]byte("не json")); err == nil {
		t.Fatal("мусор — не копия")
	}
	if _, err := Inspect([]byte(`{"format":"другое"}`)); err == nil {
		t.Fatal("чужой формат — не копия")
	}
	content, _ := Seal([]byte(secret), "пароль-123", "м", "h")
	var f map[string]any
	json.Unmarshal(content, &f)
	f["version"] = 2
	v2, _ := json.Marshal(f)
	if _, err := Inspect(v2); err == nil || !strings.Contains(err.Error(), "версии 2") {
		t.Fatalf("новая версия: %v", err)
	}
	json.Unmarshal(content, &f)
	f["n"] = 1 << 30
	huge, _ := json.Marshal(f)
	if _, err := Inspect(huge); err == nil {
		t.Fatal("огромный N для scrypt должен отклоняться")
	}
}
