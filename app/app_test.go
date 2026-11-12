package main

import (
	"strings"
	"testing"
)

func TestSetupCommand(t *testing.T) {
	cmd, err := setupCommand("/tmp/d", "bridge", "site.ru", "", "", 2222)
	if err != nil || !strings.Contains(cmd, "COUNTRY=ru DEBIAN_FRONTEND=noninteractive SSH_PORT=2222 bash '/tmp/d/bridge-setup.sh' 'site.ru'") {
		t.Fatalf("%q %v", cmd, err)
	}
	cmd, err = setupCommand("/tmp/d", "simple", "site.ru", "", "", 22)
	if err != nil || !strings.Contains(cmd, "simple-setup.sh") {
		t.Fatalf("%q %v", cmd, err)
	}
	cmd, err = setupCommand("/tmp/d", "exit", "site.org", " 1.2.3.4 ", "", 22)
	if err != nil || !strings.HasSuffix(cmd, "'/tmp/d/exit-setup.sh' '1.2.3.4' 'site.org'") {
		t.Fatalf("%q %v", cmd, err)
	}
	for _, ip := range []string{"", "abc", "::1", "1.2.3.4; rm -rf /"} {
		if _, err := setupCommand("/tmp/d", "exit", "s.org", ip, "", 22); err == nil {
			t.Errorf("адрес моста %q должен дать ошибку", ip)
		}
	}
	if _, err := setupCommand("/tmp/d", "x", "s.org", "", "", 22); err == nil {
		t.Error("неизвестный режим должен дать ошибку")
	}
	cmd, err = setupCommand("/tmp/d", "bridge", "site.kz", "", " KZ ", 22)
	if err != nil || !strings.HasPrefix(cmd, "COUNTRY=kz ") {
		t.Fatalf("%q %v", cmd, err)
	}
	for _, cc := range []string{"rus", "k1", "ru;id"} {
		if _, err := setupCommand("/tmp/d", "bridge", "s.org", "", cc, 22); err == nil {
			t.Errorf("код страны %q должен дать ошибку", cc)
		}
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

func TestParsePoll(t *testing.T) {
	st := parsePoll("run\n\n" + pollMark + "\nпервая\nнедопис")
	if !st.running || st.done || len(st.lines) != 1 || st.lines[0] != "первая" {
		t.Fatalf("идёт: %+v", st)
	}
	st = parsePoll("stop\n3\n\n" + pollMark + "\nпервая\r\nпоследняя")
	if st.running || !st.done || st.code != 3 || len(st.lines) != 2 || st.lines[1] != "последняя" {
		t.Fatalf("закончилось: %+v", st)
	}
	st = parsePoll("stop\n\n" + pollMark + "\n")
	if st.done || st.running || len(st.lines) != 0 {
		t.Fatalf("прервалось: %+v", st)
	}
	st = parsePoll("run\n0\n\n" + pollMark + "\n")
	if !st.done || st.code != 0 {
		t.Fatalf("код записан, юнит ещё не ушёл: %+v", st)
	}
}

func TestJobScript(t *testing.T) {
	s := jobScript("bash '/tmp/d/update-xray.sh' '/tmp/d/x'", "/tmp/d/job")
	want := "#!/bin/bash\nbash '/tmp/d/update-xray.sh' '/tmp/d/x' >'/tmp/d/job.log' 2>&1\n" +
		"echo $? >'/tmp/d/job.rc.tmp'\nmv '/tmp/d/job.rc.tmp' '/tmp/d/job.rc'\n"
	if s != want {
		t.Fatalf("%q", s)
	}
}
