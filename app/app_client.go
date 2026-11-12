package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"vless-bridge/internal/client"
	"vless-bridge/internal/store"
	"vless-bridge/internal/xraydist"
)

// Порты встроенного клиента на 127.0.0.1. Не 10808/10809, как у v2rayN, чтобы не мешать ему.
const (
	clientSocksPort = 10880
	clientHTTPPort  = 10881
)

// ClientRequest — с чем подключаться.
type ClientRequest struct {
	Link        string `json:"link"`
	ServerID    string `json:"serverId"` // откуда ссылка: сервер и пользователь из списка, для подсказки в интерфейсе
	User        string `json:"user"`
	SystemProxy bool   `json:"systemProxy"`
	TUN         bool   `json:"tun"`
	Country     string `json:"country"` // сайты этой страны — напрямую; пусто — всё через сервер
}

// clientSaved — последние настройки клиента в client.json; ссылка зашифрована DPAPI.
type clientSaved struct {
	LinkEnc     string `json:"link"`
	ServerID    string `json:"serverId"`
	User        string `json:"user"`
	SystemProxy bool   `json:"systemProxy"`
	TUN         bool   `json:"tun"`
	Country     string `json:"country"`
}

// ClientInfo — состояние клиента для интерфейса.
type ClientInfo struct {
	Running     bool          `json:"running"`
	Name        string        `json:"name"`
	Host        string        `json:"host"`
	SocksPort   int           `json:"socksPort"`
	HTTPPort    int           `json:"httpPort"`
	SystemProxy bool          `json:"systemProxy"`
	TUN         bool          `json:"tun"`
	Country     string        `json:"country"`
	Admin       bool          `json:"admin"`
	Error       string        `json:"error"`
	Log         []string      `json:"log"`
	Saved       ClientRequest `json:"saved"`
}

type clientState struct {
	mu      sync.Mutex
	runner  client.Runner
	running ClientRequest
	name    string
	host    string
	err     string
}

func (a *App) clientDir() string { return filepath.Join(a.store.Dir(), "client") }
func (a *App) proxyBackup() string {
	return filepath.Join(a.clientDir(), "proxy-backup.json")
}

// restoreProxyAfterCrash возвращает системный прокси, если приложение в прошлый раз закрылось,
// не успев его вернуть.
func (a *App) restoreProxyAfterCrash() {
	if err := client.RestoreSystemProxy(a.proxyBackup()); err != nil {
		runtime.LogErrorf(a.ctx, "системный прокси: %v", err)
	}
}

// ClientState возвращает состояние встроенного клиента.
func (a *App) ClientState() ClientInfo {
	cs := &a.client
	cs.mu.Lock()
	defer cs.mu.Unlock()
	info := ClientInfo{
		Running: cs.runner.Running(), Name: cs.name, Host: cs.host,
		SocksPort: clientSocksPort, HTTPPort: clientHTTPPort,
		SystemProxy: cs.running.SystemProxy, TUN: cs.running.TUN, Country: cs.running.Country,
		Admin: client.IsAdmin(), Error: cs.err, Log: cs.runner.Log(),
	}
	if saved, err := a.loadClientSaved(); err == nil {
		info.Saved = saved
	}
	return info
}

func (a *App) loadClientSaved() (ClientRequest, error) {
	var req ClientRequest
	data, err := os.ReadFile(filepath.Join(a.store.Dir(), "client.json"))
	if err != nil {
		return req, err
	}
	var s clientSaved
	if err := json.Unmarshal(data, &s); err != nil {
		return req, err
	}
	link, err := store.Decrypt(s.LinkEnc)
	if err != nil {
		return req, err
	}
	return ClientRequest{Link: link, ServerID: s.ServerID, User: s.User, SystemProxy: s.SystemProxy, TUN: s.TUN, Country: s.Country}, nil
}

func (a *App) saveClient(req ClientRequest) error {
	enc, err := store.Encrypt(req.Link)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(clientSaved{LinkEnc: enc, ServerID: req.ServerID, User: req.User,
		SystemProxy: req.SystemProxy, TUN: req.TUN, Country: req.Country}, "", "  ")
	return os.WriteFile(filepath.Join(a.store.Dir(), "client.json"), data, 0o600)
}

// ClientConnect запускает встроенный клиент: локальный Xray с SOCKS5 и HTTP-прокси на 127.0.0.1,
// по желанию — системный прокси Windows или режим TUN для всего трафика.
func (a *App) ClientConnect(req ClientRequest) error {
	link, err := client.ParseLink(req.Link)
	if err != nil {
		return err
	}
	if req.TUN && !client.IsAdmin() {
		return errors.New("для режима TUN приложение должно работать с правами администратора: нажмите «Перезапустить от администратора»")
	}
	cs := &a.client
	if cs.runner.Running() {
		a.ClientDisconnect()
	}
	for _, p := range []int{clientSocksPort, clientHTTPPort} {
		if !client.PortFree(p) {
			return fmt.Errorf("порт 127.0.0.1:%d занят другой программой: закройте её или другой клиент", p)
		}
	}
	dir := a.clientDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := a.installClientXray(dir); err != nil {
		return err
	}
	opts := client.Options{SocksPort: clientSocksPort, HTTPPort: clientHTTPPort, TUN: req.TUN}
	if req.Country != "" {
		geoip, _ := os.ReadFile(filepath.Join(dir, "geoip.dat"))
		geosite, _ := os.ReadFile(filepath.Join(dir, "geosite.dat"))
		opts.DirectDomains, opts.DirectIPs, err = client.CountryRules(req.Country, geoip, geosite)
		if err != nil {
			return fmt.Errorf("%v: обновите списки сайтов (кнопка «Обновить списки сайтов» у любого сервера скачает полные списки и на этот компьютер)", err)
		}
	}
	cfg, err := client.Config(link, opts)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	cs.mu.Lock()
	cs.err = ""
	cs.runner.OnExit = func(err error) {
		_ = client.RestoreSystemProxy(a.proxyBackup())
		cs.mu.Lock()
		cs.err = "Xray завершился сам: " + fmt.Sprint(err)
		cs.mu.Unlock()
		runtime.EventsEmit(a.ctx, "client")
	}
	cs.mu.Unlock()
	exe := filepath.Join(dir, "xray.exe")
	if err := cs.runner.Start(exe, cfgPath, dir, clientSocksPort); err != nil {
		return err
	}
	if req.SystemProxy && !req.TUN {
		if err := client.SetSystemProxy(clientHTTPPort, a.proxyBackup()); err != nil {
			cs.runner.Stop()
			return fmt.Errorf("не удалось включить системный прокси: %w", err)
		}
	}
	cs.mu.Lock()
	cs.running, cs.name, cs.host = req, link.Name, link.Host
	cs.mu.Unlock()
	if err := a.saveClient(req); err != nil {
		runtime.LogErrorf(a.ctx, "настройки клиента: %v", err)
	}
	runtime.EventsEmit(a.ctx, "client")
	return nil
}

// ClientDisconnect останавливает клиент и возвращает прежний системный прокси.
func (a *App) ClientDisconnect() {
	a.client.runner.Stop()
	_ = client.RestoreSystemProxy(a.proxyBackup())
	a.client.mu.Lock()
	a.client.running = ClientRequest{}
	a.client.mu.Unlock()
	runtime.EventsEmit(a.ctx, "client")
}

// RestartAsAdmin перезапускает приложение с правами администратора: они нужны режиму TUN.
func (a *App) RestartAsAdmin() error {
	if err := client.RestartAsAdmin(); err != nil {
		return fmt.Errorf("Windows не дала прав администратора: %w", err)
	}
	a.ClientDisconnect()
	runtime.Quit(a.ctx)
	return nil
}

// installClientXray кладёт в dir Xray для Windows (xray.exe, wintun.dll для TUN) и списки сайтов.
// Xray берётся так же, как для серверов: сохранённый на компьютере или с GitHub.
// Списки — полные из кэша, если их уже скачивали для серверов, иначе из архива Xray.
func (a *App) installClientXray(dir string) error {
	archive, err := a.getXray("windows-" + goruntime.GOARCH)
	if err != nil {
		return err
	}
	files, err := xraydist.ExtractNames(archive, []string{"xray.exe", "geoip.dat", "geosite.dat"}, []string{"wintun.dll"})
	if err != nil {
		return err
	}
	if geo, _, err := a.cache.LoadGeo(); err == nil {
		files["geoip.dat"], files["geosite.dat"] = geo["geoip.dat"], geo["geosite.dat"]
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
			continue
		}
		if err := os.WriteFile(path, data, 0o700); err != nil {
			return fmt.Errorf("не удалось записать %s (возможно, Xray ещё работает): %w", name, err)
		}
	}
	return nil
}
