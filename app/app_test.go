package main

import (
	"strings"
	"testing"
)

func TestSetupCommand(t *testing.T) {
	cmd, err := setupCommand("/tmp/d", "bridge", "site.ru", "", 2222)
	if err != nil || !strings.Contains(cmd, "SSH_PORT=2222 bash '/tmp/d/bridge-setup.sh' 'site.ru'") {
		t.Fatalf("%q %v", cmd, err)
	}
	cmd, err = setupCommand("/tmp/d", "simple", "site.ru", "", 22)
	if err != nil || !strings.Contains(cmd, "simple-setup.sh") {
		t.Fatalf("%q %v", cmd, err)
	}
	cmd, err = setupCommand("/tmp/d", "exit", "site.org", " 1.2.3.4 ", 22)
	if err != nil || !strings.HasSuffix(cmd, "'/tmp/d/exit-setup.sh' '1.2.3.4' 'site.org'") {
		t.Fatalf("%q %v", cmd, err)
	}
	for _, ip := range []string{"", "abc", "::1", "1.2.3.4; rm -rf /"} {
		if _, err := setupCommand("/tmp/d", "exit", "s.org", ip, 22); err == nil {
			t.Errorf("адрес моста %q должен дать ошибку", ip)
		}
	}
	if _, err := setupCommand("/tmp/d", "x", "s.org", "", 22); err == nil {
		t.Error("неизвестный режим должен дать ошибку")
	}
}

func TestModeAllowed(t *testing.T) {
	st := map[string]any{"capabilities": map[string]any{"bridge": true, "simple": false, "exit": false}}
	if err := modeAllowed(st, "bridge"); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"simple", "exit"} {
		if err := modeAllowed(st, m); err == nil {
			t.Errorf("%s должен быть запрещён", m)
		}
	}
	if err := modeAllowed(nil, "bridge"); err == nil {
		t.Error("без данных о сервере режим должен быть запрещён")
	}
}
