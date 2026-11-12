package client

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

var (
	jobOnce sync.Once
	job     windows.Handle
)

// bindToApp кладёт процесс в задание Windows, которое закрывается вместе с приложением:
// если «Переправа» упадёт, Xray не останется работать сам по себе.
func bindToApp(p *os.Process) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			return
		}
		job = h
	})
	if job == 0 {
		return
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(ph)
	_ = windows.AssignProcessToJobObject(job, ph)
}

// IsAdmin сообщает, запущено ли приложение с правами администратора (нужны для TUN).
func IsAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// RestartAsAdmin запускает это же приложение с правами администратора (Windows спросит разрешение).
func RestartAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_NORMAL)
}

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// ProxyState — системный прокси пользователя Windows.
type ProxyState struct {
	Enable   uint32 `json:"enable"`
	Server   string `json:"server"`
	Override string `json:"override"`
}

func readProxy() (ProxyState, error) {
	var st ProxyState
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return st, err
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		st.Enable = uint32(v)
	}
	st.Server, _, _ = k.GetStringValue("ProxyServer")
	st.Override, _, _ = k.GetStringValue("ProxyOverride")
	return st, nil
}

func writeProxy(st ProxyState) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", st.Enable); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", st.Server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", st.Override); err != nil {
		return err
	}
	notifyProxy()
	return nil
}

var (
	wininet            = windows.NewLazySystemDLL("wininet.dll")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")
	optSettingsChanged = uintptr(39)
	optRefresh         = uintptr(37)
)

// notifyProxy сообщает браузерам и другим программам, что настройки прокси изменились.
func notifyProxy() {
	if internetSetOptionW.Find() != nil {
		return
	}
	internetSetOptionW.Call(0, optSettingsChanged, 0, 0)
	internetSetOptionW.Call(0, optRefresh, 0, 0)
}

// SetSystemProxy включает системный прокси на 127.0.0.1:port и запоминает прежние настройки
// в файле backup: по нему их вернёт RestoreSystemProxy, даже после падения приложения.
func SetSystemProxy(port int, backup string) error {
	prev, err := readProxy()
	if err != nil {
		return err
	}
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		data, _ := json.Marshal(prev)
		if err := os.WriteFile(backup, data, 0o600); err != nil {
			return err
		}
	}
	return writeProxy(ProxyState{
		Enable:   1,
		Server:   "127.0.0.1:" + itoa(port),
		Override: "localhost;127.*;10.*;172.16.*;192.168.*;<local>",
	})
}

// RestoreSystemProxy возвращает настройки прокси из backup, если там что-то сохранено.
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
	if err := writeProxy(prev); err != nil {
		return err
	}
	return os.Remove(backup)
}

// ExeName — имя программы Xray в архиве для этой системы.
const ExeName = "xray.exe"

// TunReady сообщает, можно ли включить TUN, и что для этого сделать.
func TunReady(xray string) (bool, string) {
	if IsAdmin() {
		return true, ""
	}
	return false, "Для режима TUN приложение должно работать с правами администратора."
}

// EnableTUN готовит режим TUN. В Windows — перезапуск приложения от администратора:
// после успешного вызова приложение надо закрыть (restart = true).
func EnableTUN(xray string) (restart bool, err error) {
	return true, RestartAsAdmin()
}
