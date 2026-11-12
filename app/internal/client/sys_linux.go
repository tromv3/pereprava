package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ExeName — имя программы Xray в архиве для этой системы.
const ExeName = "xray"

// prepareCmd: Xray получает SIGKILL, если приложение завершится, не остановив его.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func bindToApp(*os.Process) {}

// IsAdmin сообщает, запущено ли приложение от root.
func IsAdmin() bool { return os.Geteuid() == 0 }

// hasNetAdmin — есть ли у файла xray право настраивать сеть (setcap cap_net_admin).
func hasNetAdmin(xray string) bool {
	out, err := exec.Command("getcap", xray).Output()
	return err == nil && strings.Contains(string(out), "cap_net_admin")
}

// TunReady сообщает, можно ли включить TUN, и что для этого сделать. Запускать всё
// приложение от root в Linux не нужно: достаточно дать право на сеть самому Xray.
func TunReady(xray string) (bool, string) {
	if IsAdmin() || (xray != "" && hasNetAdmin(xray)) {
		return true, ""
	}
	return false, "Для режима TUN Xray нужно право настраивать сеть: приложение выдаст его через pkexec (спросит пароль администратора). После обновления Xray право выдаётся заново."
}

// EnableTUN выдаёт файлу xray права cap_net_admin и cap_net_bind_service через pkexec.
func EnableTUN(xray string) (restart bool, err error) {
	if xray == "" {
		return false, errors.New("Xray ещё не скачан: подключитесь один раз в другом режиме")
	}
	if _, err := exec.LookPath("pkexec"); err != nil {
		return false, fmt.Errorf("нет pkexec: выполните вручную sudo setcap cap_net_admin,cap_net_bind_service+ep %s", xray)
	}
	out, err := exec.Command("pkexec", "setcap", "cap_net_admin,cap_net_bind_service+ep", xray).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("не удалось выдать права: %v %s", err, strings.TrimSpace(string(out)))
	}
	return false, nil
}

// Системный прокси в Linux — настройки GNOME (gsettings): их читают GNOME, Cinnamon, MATE,
// Budgie, браузеры и многие программы. В KDE и других окружениях используйте локальный прокси или TUN.

// ProxyState — прежние значения ключей gsettings.
type ProxyState map[string]string

var proxyKeys = [][2]string{
	{"org.gnome.system.proxy", "mode"},
	{"org.gnome.system.proxy", "ignore-hosts"},
	{"org.gnome.system.proxy.http", "host"},
	{"org.gnome.system.proxy.http", "port"},
	{"org.gnome.system.proxy.https", "host"},
	{"org.gnome.system.proxy.https", "port"},
	{"org.gnome.system.proxy.socks", "host"},
	{"org.gnome.system.proxy.socks", "port"},
}

func gsettings(args ...string) (string, error) {
	out, err := exec.Command("gsettings", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gsettings %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// SetSystemProxy включает системный прокси (HTTP и HTTPS на httpPort, SOCKS на httpPort-1)
// и запоминает прежние настройки в backup.
func SetSystemProxy(httpPort int, backup string) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return errors.New("системный прокси настраивается через gsettings (GNOME и похожие окружения), а его здесь нет: выберите «Только локальный прокси» или TUN")
	}
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		prev := ProxyState{}
		for _, k := range proxyKeys {
			v, err := gsettings("get", k[0], k[1])
			if err != nil {
				return err
			}
			prev[k[0]+" "+k[1]] = v
		}
		data, _ := json.Marshal(prev)
		if err := os.WriteFile(backup, data, 0o600); err != nil {
			return err
		}
	}
	port, socks := itoa(httpPort), itoa(httpPort-1)
	for _, kv := range [][3]string{
		{"org.gnome.system.proxy.http", "host", "127.0.0.1"}, {"org.gnome.system.proxy.http", "port", port},
		{"org.gnome.system.proxy.https", "host", "127.0.0.1"}, {"org.gnome.system.proxy.https", "port", port},
		{"org.gnome.system.proxy.socks", "host", "127.0.0.1"}, {"org.gnome.system.proxy.socks", "port", socks},
		{"org.gnome.system.proxy", "ignore-hosts", "['localhost', '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1']"},
		{"org.gnome.system.proxy", "mode", "manual"},
	} {
		if _, err := gsettings("set", kv[0], kv[1], kv[2]); err != nil {
			return err
		}
	}
	return nil
}

// RestoreSystemProxy возвращает настройки из backup, если там что-то сохранено.
func RestoreSystemProxy(backup string) error {
	data, err := os.ReadFile(backup)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var prev ProxyState
	if err := json.Unmarshal(data, &prev); err != nil {
		return err
	}
	for _, k := range proxyKeys {
		if v, ok := prev[k[0]+" "+k[1]]; ok {
			if _, err := gsettings("set", k[0], k[1], v); err != nil {
				return err
			}
		}
	}
	return os.Remove(backup)
}
