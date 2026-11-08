package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"vless-bridge/internal/bundle"
	"vless-bridge/internal/remote"
	"vless-bridge/internal/store"
	"vless-bridge/internal/xraydist"
)

var (
	reDomain = regexp.MustCompile(`^[A-Za-z0-9а-яА-ЯёЁ.:/-]+$`)
	reUser   = regexp.MustCompile(`^[A-Za-z0-9 _-]+$`)
)

// ServerView — сервер без секретов, для интерфейса.
type ServerView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	AuthType    string `json:"authType"`
	KeyPath     string `json:"keyPath"`
	Fingerprint string `json:"fingerprint"`
	HasPassword bool   `json:"hasPassword"`
	HasSudo     bool   `json:"hasSudo"`
}

// ServerInput — данные формы. Пустой секрет при редактировании оставляет старый.
type ServerInput struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	AuthType     string `json:"authType"`
	KeyPath      string `json:"keyPath"`
	Password     string `json:"password"`
	Passphrase   string `json:"passphrase"`
	SudoPassword string `json:"sudoPassword"`
}

type conn struct {
	client *remote.Client
	dir    string
}

// App — методы, доступные интерфейсу.
type App struct {
	ctx   context.Context
	store *store.Store
	mu    sync.Mutex
	conns map[string]*conn
}

// NewApp создаёт приложение.
func NewApp() *App { return &App{conns: map[string]*conn{}} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	s, err := store.Open("")
	if err != nil {
		runtime.LogErrorf(ctx, "хранилище: %v", err)
		return
	}
	a.store = s
}

func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, c := range a.conns {
		_, _ = c.client.Run(ctx, "rm -rf "+remote.Quote(c.dir), false, nil)
		c.client.Close()
		delete(a.conns, id)
	}
}

func view(s store.Server) ServerView {
	return ServerView{ID: s.ID, Name: s.Name, Host: s.Host, Port: s.Port, User: s.User,
		AuthType: s.AuthType, KeyPath: s.KeyPath, Fingerprint: s.Fingerprint,
		HasPassword: s.Password != "", HasSudo: s.SudoPassword != ""}
}

// ListServers возвращает серверы без секретов.
func (a *App) ListServers() ([]ServerView, error) {
	list, err := a.store.List()
	if err != nil {
		return nil, err
	}
	out := make([]ServerView, 0, len(list))
	for _, s := range list {
		out = append(out, view(s))
	}
	return out, nil
}

// SaveServer добавляет или изменяет сервер.
func (a *App) SaveServer(in ServerInput) (ServerView, error) {
	in.Host, in.User = strings.TrimSpace(in.Host), strings.TrimSpace(in.User)
	if in.Host == "" || in.User == "" {
		return ServerView{}, errors.New("укажите адрес и пользователя")
	}
	if in.Port == 0 {
		in.Port = 22
	}
	if in.Port < 1 || in.Port > 65535 {
		return ServerView{}, errors.New("порт должен быть от 1 до 65535")
	}
	if in.AuthType != "password" && in.AuthType != "key" {
		return ServerView{}, errors.New("выберите способ входа")
	}
	if in.AuthType == "key" && strings.TrimSpace(in.KeyPath) == "" {
		return ServerView{}, errors.New("укажите файл ключа")
	}

	srv := store.Server{}
	if in.ID != "" {
		old, err := a.store.Get(in.ID)
		if err != nil {
			return ServerView{}, err
		}
		srv = old
		if old.Host != in.Host || old.Port != in.Port {
			srv.Fingerprint = "" // другой адрес — другой сервер, подтверждаем заново
		}
	} else if in.AuthType == "password" && in.Password == "" {
		return ServerView{}, errors.New("укажите пароль")
	}
	srv.Name, srv.Host, srv.Port, srv.User = in.Name, in.Host, in.Port, in.User
	srv.AuthType, srv.KeyPath = in.AuthType, strings.TrimSpace(in.KeyPath)
	if srv.Name == "" {
		srv.Name = in.Host
	}
	for _, f := range []struct {
		plain string
		dst   *string
	}{{in.Password, &srv.Password}, {in.Passphrase, &srv.Passphrase}, {in.SudoPassword, &srv.SudoPassword}} {
		if f.plain == "" {
			continue
		}
		enc, err := store.Encrypt(f.plain)
		if err != nil {
			return ServerView{}, err
		}
		*f.dst = enc
	}
	srv, err := a.store.Put(srv)
	if err != nil {
		return ServerView{}, err
	}
	a.dropConn(srv.ID)
	return view(srv), nil
}

// DeleteServer убирает сервер из приложения. На VPS ничего не меняется.
func (a *App) DeleteServer(id string) error {
	a.dropConn(id)
	return a.store.Delete(id)
}

// TrustServer сохраняет подтверждённый пользователем ключ хоста.
func (a *App) TrustServer(id, fingerprint string) error {
	srv, err := a.store.Get(id)
	if err != nil {
		return err
	}
	if srv.Fingerprint != "" {
		return errors.New("ключ уже сохранён; чтобы сменить его, удалите сервер и добавьте заново")
	}
	srv.Fingerprint = fingerprint
	_, err = a.store.Put(srv)
	return err
}

func (a *App) dropConn(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.conns[id]; ok {
		c.client.Close()
		delete(a.conns, id)
	}
}

func remoteConfig(s store.Server) (remote.Config, error) {
	pw, err := store.Decrypt(s.Password)
	if err != nil {
		return remote.Config{}, err
	}
	pp, err := store.Decrypt(s.Passphrase)
	if err != nil {
		return remote.Config{}, err
	}
	sudo, err := store.Decrypt(s.SudoPassword)
	if err != nil {
		return remote.Config{}, err
	}
	if sudo == "" && s.AuthType == "password" {
		sudo = pw // обычно пароль sudo совпадает с паролем входа
	}
	return remote.Config{Host: s.Host, Port: s.Port, User: s.User, AuthType: s.AuthType,
		Password: pw, KeyPath: s.KeyPath, Passphrase: pp, SudoPassword: sudo,
		Fingerprint: s.Fingerprint}, nil
}

// hostError превращает ошибку ключа хоста в код, понятный интерфейсу.
func hostError(err error) error {
	var unknown *remote.UnknownHostError
	if errors.As(err, &unknown) {
		return errors.New("UNKNOWN_HOST:" + unknown.KeyType + " " + unknown.Fingerprint)
	}
	var changed *remote.HostKeyChangedError
	if errors.As(err, &changed) {
		return errors.New("HOST_KEY_CHANGED:" + changed.Fingerprint)
	}
	return err
}

// connect возвращает живое соединение с залитыми скриптами.
func (a *App) connect(id string) (*conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.conns[id]; ok {
		if c.client.Alive() {
			return c, nil
		}
		c.client.Close()
		delete(a.conns, id)
	}
	srv, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	cfg, err := remoteConfig(srv)
	if err != nil {
		return nil, err
	}
	client, err := remote.Dial(cfg)
	if err != nil {
		return nil, hostError(err)
	}
	dir, err := uploadBundle(a.ctx, client)
	if err != nil {
		client.Close()
		return nil, err
	}
	c := &conn{client: client, dir: dir}
	a.conns[id] = c
	return c, nil
}

func uploadBundle(ctx context.Context, client *remote.Client) (string, error) {
	r, err := client.Run(ctx, "mktemp -d", false, nil)
	if err != nil {
		return "", err
	}
	dir := strings.TrimSpace(r.Stdout)
	if r.Code != 0 || dir == "" {
		return "", fmt.Errorf("не удалось создать временную папку: %s", strings.TrimSpace(r.Stderr))
	}
	for _, name := range bundle.Names {
		data, err := bundle.Read(name)
		if err != nil {
			return "", err
		}
		if err := client.Upload(ctx, dir+"/"+name, data, "700"); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (a *App) emit(line string) { runtime.EventsEmit(a.ctx, "log", line) }

// tool запускает exitctl от root. Код выхода 1 с JSON в stdout — обычный результат.
func (a *App) tool(id string, emit bool, args ...string) (any, error) {
	c, err := a.connect(id)
	if err != nil {
		return nil, err
	}
	quoted := make([]string, len(args))
	for i, x := range args {
		quoted[i] = remote.Quote(x)
	}
	cmd := "PYTHONUTF8=1 python3 " + remote.Quote(c.dir+"/exitctl") + " " + strings.Join(quoted, " ")
	var onLog func(string)
	if emit {
		onLog = a.emit
	}
	r, err := c.client.RunResult(a.ctx, cmd, true, onLog)
	if err != nil {
		return nil, err
	}
	var out any
	if json.Unmarshal([]byte(r.Stdout), &out) == nil && out != nil {
		return out, nil
	}
	return nil, commandError(r)
}

func commandError(r remote.Result) error {
	msg := strings.TrimSpace(r.Stderr)
	if msg == "" {
		msg = strings.TrimSpace(r.Stdout)
	}
	if strings.Contains(msg, "a password is required") || strings.Contains(msg, "incorrect password") ||
		strings.Contains(msg, "Sorry, try again") {
		msg = "sudo не принял пароль: укажите пароль sudo в настройках сервера"
	}
	if msg == "" {
		msg = "команда завершилась с кодом " + strconv.Itoa(r.Code)
	}
	return errors.New(msg)
}

// ensurePython ставит python3 и curl, если их нет: они нужны exitctl ещё до установки Xray.
func (a *App) ensurePython(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	// prepare-restricted.sh без аргументов только переключает apt на доступное зеркало.
	cmd := "command -v python3 >/dev/null && command -v curl >/dev/null || " +
		"(bash " + remote.Quote(c.dir+"/prepare-restricted.sh") + " && export DEBIAN_FRONTEND=noninteractive && " +
		"apt-get update -q && apt-get install -y -q python3 curl)"
	r, err := c.client.Run(a.ctx, cmd, true, a.emit)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return commandError(r)
	}
	return nil
}

// Status возвращает состояние сервера.
func (a *App) Status(id string) (any, error) {
	if err := a.ensurePython(id); err != nil {
		return nil, err
	}
	return a.tool(id, false, "status", "--json")
}

// ScanSNI подбирает домены в /24 сервера.
func (a *App) ScanSNI(id, role string) (any, error) {
	if err := a.ensurePython(id); err != nil {
		return nil, err
	}
	args := []string{"sni", "scan", "--json"}
	if role != "" {
		args = append(args, "--role", role)
	}
	return a.tool(id, true, args...)
}

// CheckSNI проверяет домен, указанный пользователем.
func (a *App) CheckSNI(id, domain string) (any, error) {
	domain = strings.TrimSpace(domain)
	if !reDomain.MatchString(domain) {
		return nil, errors.New("это не похоже на домен")
	}
	if err := a.ensurePython(id); err != nil {
		return nil, err
	}
	return a.tool(id, false, "sni", "check", domain, "--json")
}

// setupCommand собирает команду установки для роли.
func setupCommand(dir, mode, sni, bridgeIP string, sshPort int) (string, error) {
	env := "DEBIAN_FRONTEND=noninteractive SSH_PORT=" + strconv.Itoa(sshPort) + " bash "
	switch mode {
	case "simple":
		return env + remote.Quote(dir+"/simple-setup.sh") + " " + remote.Quote(sni), nil
	case "bridge":
		return env + remote.Quote(dir+"/bridge-setup.sh") + " " + remote.Quote(sni), nil
	case "exit":
		ip := net.ParseIP(strings.TrimSpace(bridgeIP))
		if ip == nil || ip.To4() == nil {
			return "", errors.New("для выхода укажите IPv4-адрес моста")
		}
		return env + remote.Quote(dir+"/exit-setup.sh") + " " + remote.Quote(ip.String()) + " " + remote.Quote(sni), nil
	}
	return "", fmt.Errorf("неизвестный режим %q", mode)
}

// modeAllowed проверяет режим по разделу capabilities из exitctl status.
func modeAllowed(status any, mode string) error {
	st, _ := status.(map[string]any)
	caps, _ := st["capabilities"].(map[string]any)
	if ok, _ := caps[mode].(bool); ok {
		return nil
	}
	names := map[string]string{"simple": "простой режим", "exit": "выход", "bridge": "мост"}
	return fmt.Errorf("этот сервер не годится как %s: у него ограничен исходящий трафик", names[mode])
}

// prepareRestricted переключает apt и заливает Xray, если сервер сам не может их получить.
func (a *App) prepareRestricted(c *conn) error {
	const probe = "command -v xray >/dev/null && echo has-xray; " +
		"timeout 6 bash -c '</dev/tcp/github.com/443' 2>/dev/null && echo has-github; uname -m"
	r, err := c.client.Run(a.ctx, probe, true, nil)
	if err != nil {
		return err
	}
	lines := strings.Fields(r.Stdout)
	args := ""
	if !slices.Contains(lines, "has-xray") && !slices.Contains(lines, "has-github") {
		if len(lines) == 0 {
			return errors.New("не удалось определить архитектуру сервера")
		}
		a.emit("Сервер не может скачать Xray с GitHub: скачиваю его на этом компьютере...")
		files, err := xraydist.Download(a.ctx, lines[len(lines)-1])
		if err != nil {
			return err
		}
		a.emit("Заливаю Xray на сервер...")
		dist := c.dir + "/xray-dist"
		if r, err := c.client.Run(a.ctx, "mkdir -p "+remote.Quote(dist), false, nil); err != nil {
			return err
		} else if r.Code != 0 {
			return commandError(r)
		}
		for _, name := range xraydist.Files {
			if err := c.client.Upload(a.ctx, dist+"/"+name, files[name], "700"); err != nil {
				return err
			}
		}
		args = " " + remote.Quote(dist)
	}
	return a.runScript(c, "prepare-restricted.sh", args, "подготовка сервера не удалась")
}

// Install настраивает сервер в выбранной роли, вывод идёт событиями log.
func (a *App) Install(id, mode, sni, bridgeIP string) error {
	sni = strings.TrimSpace(sni)
	if !reDomain.MatchString(sni) || strings.ContainsAny(sni, ":/") {
		return errors.New("это не похоже на домен")
	}
	srv, err := a.store.Get(id)
	if err != nil {
		return err
	}
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	cmd, err := setupCommand(c.dir, mode, sni, bridgeIP, srv.Port)
	if err != nil {
		return err
	}
	st, err := a.tool(id, false, "status", "--json")
	if err != nil {
		return err
	}
	if err := modeAllowed(st, mode); err != nil {
		return err
	}
	if err := a.prepareRestricted(c); err != nil {
		return err
	}
	r, err := c.client.Run(a.ctx, cmd, true, a.emit)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return fmt.Errorf("установка не удалась, код %d: смотрите журнал", r.Code)
	}
	return nil
}

// runScript запускает вшитый скрипт от root, вывод идёт событиями log.
func (a *App) runScript(c *conn, script, args, failMsg string) error {
	r, err := c.client.Run(a.ctx, "bash "+remote.Quote(c.dir+"/"+script)+args, true, a.emit)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return fmt.Errorf("%s, код %d: смотрите журнал", failMsg, r.Code)
	}
	return nil
}

// Uninstall снимает установку: Xray, конфиги, ссылки и правила файрвола для 443.
func (a *App) Uninstall(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	return a.runScript(c, "uninstall.sh", "", "удаление не удалось")
}

// UpdateGeodata скачивает свежие списки сайтов на этом компьютере и ставит их на сервер.
func (a *App) UpdateGeodata(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	a.emit("Скачиваю списки сайтов на этом компьютере...")
	files, err := xraydist.DownloadGeo(a.ctx)
	if err != nil {
		return err
	}
	dir := c.dir + "/geo"
	if r, err := c.client.Run(a.ctx, "mkdir -p "+remote.Quote(dir), false, nil); err != nil {
		return err
	} else if r.Code != 0 {
		return commandError(r)
	}
	a.emit("Заливаю списки на сервер...")
	for name, data := range files {
		if err := c.client.Upload(a.ctx, dir+"/"+name, data, "600"); err != nil {
			return err
		}
	}
	return a.runScript(c, "update-geodata.sh", " "+remote.Quote(dir), "обновление не удалось")
}

// plainTool запускает команду exitctl, результат которой нужен только как успех или ошибка.
func (a *App) plainTool(id string, args ...string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, x := range args {
		quoted[i] = remote.Quote(x)
	}
	cmd := "PYTHONUTF8=1 python3 " + remote.Quote(c.dir+"/exitctl") + " " + strings.Join(quoted, " ")
	r, err := c.client.Run(a.ctx, cmd, true, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return commandError(r)
	}
	return nil
}

// ListExits возвращает выходы моста и закреплённый выход.
func (a *App) ListExits(id string) (any, error) { return a.tool(id, false, "list", "--json") }

// CheckExits проверяет с моста, отвечают ли выходы.
func (a *App) CheckExits(id string) (any, error) { return a.tool(id, false, "check", "--json") }

// AddExit добавляет выход на мост по ссылке. Xray при этом перезапускается.
func (a *App) AddExit(id, link, name string) error {
	link, name = strings.TrimSpace(link), strings.TrimSpace(name)
	if !strings.HasPrefix(link, "vless://") {
		return errors.New("ссылка должна начинаться с vless://")
	}
	if name != "" && !reUser.MatchString(name) {
		return errors.New("в имени допустимы латинские буквы, цифры, пробел, - и _")
	}
	if name == "" {
		return a.plainTool(id, "add", link)
	}
	return a.plainTool(id, "add", link, name)
}

// RemoveExit удаляет выход. Xray при этом перезапускается.
func (a *App) RemoveExit(id, name string) error { return a.plainTool(id, "remove", name) }

// UseExit закрепляет весь трафик за одним выходом.
func (a *App) UseExit(id, name string) error { return a.plainTool(id, "use", name) }

// AutoExit включает автовыбор выхода.
func (a *App) AutoExit(id string) error { return a.plainTool(id, "auto") }

// ExitLink возвращает ссылку настроенного выхода для добавления на мост.
func (a *App) ExitLink(id string) (string, error) {
	c, err := a.connect(id)
	if err != nil {
		return "", err
	}
	r, err := c.client.Run(a.ctx, "sed -n 's/^LINK=//p' /root/exit-info.txt", true, nil)
	if err != nil {
		return "", err
	}
	link := strings.TrimSpace(r.Stdout)
	if r.Code != 0 || link == "" {
		return "", errors.New("на сервере нет ссылки выхода: он настроен этим приложением?")
	}
	return link, nil
}

// ListUsers возвращает пользователей со ссылками и трафиком.
func (a *App) ListUsers(id string) (any, error) {
	srv, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	return a.tool(id, false, "user", "list", "--json", "--host", srv.Host)
}

// AddUser добавляет пользователя. Xray при этом перезапускается.
func (a *App) AddUser(id, name string) (any, error) {
	name = strings.TrimSpace(name)
	if !reUser.MatchString(name) {
		return nil, errors.New("в имени допустимы латинские буквы, цифры, пробел, - и _")
	}
	srv, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	return a.tool(id, false, "user", "add", name, "--json", "--host", srv.Host)
}

// RemoveUser удаляет пользователя. Xray при этом перезапускается.
func (a *App) RemoveUser(id, name string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	cmd := "PYTHONUTF8=1 python3 " + remote.Quote(c.dir+"/exitctl") + " user remove " + remote.Quote(name)
	r, err := c.client.Run(a.ctx, cmd, true, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return commandError(r)
	}
	return nil
}

// QRCode рисует ссылку как PNG в data-URL. Работает локально, ссылка никуда не отправляется.
func (a *App) QRCode(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
