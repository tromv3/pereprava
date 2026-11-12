package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"vless-bridge/internal/backup"
	"vless-bridge/internal/bundle"
	"vless-bridge/internal/remote"
	"vless-bridge/internal/store"
	"vless-bridge/internal/xraydist"
)

var (
	reDomain  = regexp.MustCompile(`^[A-Za-z0-9а-яА-ЯёЁ.:/-]+$`)
	reUser    = regexp.MustCompile(`^[A-Za-z0-9 _-]+$`)
	reCountry = regexp.MustCompile(`^[a-z]{2}$`)
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

	latestMu sync.Mutex
	latest   string
	latestAt time.Time

	cache   xraydist.Cache // последние Xray и списки сайтов на этом компьютере
	logHook func(string)   // для тестов: журнал без окна Wails
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
	a.cache = xraydist.Cache{Dir: filepath.Join(s.Dir(), "cache")}
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

func (a *App) emit(line string) {
	if a.logHook != nil {
		a.logHook(line)
		return
	}
	runtime.EventsEmit(a.ctx, "log", line)
}

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
	st, err := a.tool(id, false, "status", "--json")
	if err != nil {
		return nil, err
	}
	// Интерфейс сравнивает с tool_sha256 и предлагает обновить exitctl на сервере.
	if m, ok := st.(map[string]any); ok {
		if data, err := bundle.Read("exitctl"); err == nil {
			sum := sha256.Sum256(data)
			m["bundled_tool_sha256"] = hex.EncodeToString(sum[:])
		}
	}
	return st, nil
}

// Health возвращает проблемы сервера (exitctl health): интерфейс проверяет все серверы по таймеру.
// python3 здесь не ставится: если его нет, сервер ещё не настраивали, и проверять нечего.
func (a *App) Health(id string) (any, error) { return a.tool(id, false, "health", "--json") }

// UpdateTool ставит на сервер exitctl из приложения: для тех, кто пользуется им в консоли сервера.
func (a *App) UpdateTool(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	r, err := c.client.Run(a.ctx, "install -m 755 "+remote.Quote(c.dir+"/exitctl")+" /usr/local/bin/exitctl", true, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return commandError(r)
	}
	return nil
}

// LatestXray возвращает номер последнего релиза Xray (без «v»), запоминая его на час.
func (a *App) LatestXray() (string, error) {
	a.latestMu.Lock()
	defer a.latestMu.Unlock()
	if a.latest != "" && time.Since(a.latestAt) < time.Hour {
		return a.latest, nil
	}
	v, err := xraydist.LatestVersion(a.ctx)
	if err != nil {
		return "", err
	}
	a.latest, a.latestAt = v, time.Now()
	return v, nil
}

// UpdateXray скачивает последний Xray на этом компьютере и ставит его на сервер.
// Если GitHub не отвечает, берётся копия, сохранённая на компьютере.
func (a *App) UpdateXray(id string) error {
	c, machine, err := a.connectMachine(id)
	if err != nil {
		return err
	}
	archive, err := a.getXray(machine)
	if err != nil {
		return err
	}
	return a.installXray(id, c, archive)
}

// UpdateXrayFromFile ставит на сервер Xray из выбранного архива (Xray-linux-64.zip и т. п.)
// и сохраняет архив на компьютере: он пригодится, когда GitHub недоступен.
func (a *App) UpdateXrayFromFile(id, path string) error {
	archive, name, meta, err := xraydist.ReadXrayFile(path)
	if err != nil {
		return err
	}
	c, machine, err := a.connectMachine(id)
	if err != nil {
		return err
	}
	want, err := xraydist.ArchiveName(machine)
	if err != nil {
		return err
	}
	if want != name {
		return fmt.Errorf("архив собран для другой архитектуры: серверу нужен %s, а выбран %s", want, name)
	}
	if !meta.Checked {
		a.emit("Рядом с архивом нет файла .dgst: контрольная сумма не проверена.")
	}
	a.saveXray(name, archive, meta)
	return a.installXray(id, c, archive)
}

// ImportXray сохраняет выбранный архив Xray на компьютере, ничего не ставя на сервер:
// так устанавливают закрытый сервер, когда GitHub недоступен и с компьютера.
func (a *App) ImportXray(path string) (string, error) {
	archive, name, meta, err := xraydist.ReadXrayFile(path)
	if err != nil {
		return "", err
	}
	if err := a.cache.SaveXray(name, archive, meta); err != nil {
		return "", err
	}
	return name + ": " + meta.Describe(), nil
}

// ChooseXrayFile спрашивает архив Xray. Пустая строка — пользователь отменил.
func (a *App) ChooseXrayFile() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Архив Xray для Linux (Xray-linux-64.zip)",
		Filters: []runtime.FileFilter{{DisplayName: "Архив Xray (*.zip)", Pattern: "*.zip"}},
	})
}

// ChooseGeoFiles спрашивает geoip.dat и geosite.dat. Пустой список — пользователь отменил.
func (a *App) ChooseGeoFiles() ([]string, error) {
	return runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Списки сайтов: выберите geoip.dat и geosite.dat (или dlc.dat)",
		Filters: []runtime.FileFilter{{DisplayName: "Списки Xray (*.dat)", Pattern: "*.dat"}},
	})
}

func (a *App) connectMachine(id string) (*conn, string, error) {
	c, err := a.connect(id)
	if err != nil {
		return nil, "", err
	}
	r, err := c.client.Run(a.ctx, "uname -m", false, nil)
	if err != nil {
		return nil, "", err
	}
	return c, strings.TrimSpace(r.Stdout), nil
}

// getXray возвращает проверенный архив Xray для архитектуры сервера: сохранённый, если он
// той же версии, что последняя на GitHub; иначе свежий с GitHub; если GitHub не отвечает — сохранённый.
func (a *App) getXray(machine string) ([]byte, error) {
	name, err := xraydist.ArchiveName(machine)
	if err != nil {
		return nil, err
	}
	cached, meta, cacheErr := a.cache.LoadXray(name)
	latest, latestErr := a.LatestXray()
	if cacheErr == nil && latestErr == nil && meta.Version == latest {
		a.emit("Xray " + latest + " уже скачан на этом компьютере.")
		return cached, nil
	}
	if latestErr == nil {
		a.emit("Скачиваю Xray " + latest + " на этом компьютере...")
		archive, err := xraydist.DownloadArchive(a.ctx, name)
		if err == nil {
			a.saveXray(name, archive, xraydist.Meta{Version: latest, Source: "github", Saved: time.Now(), Checked: true})
			return archive, nil
		}
		latestErr = err
	}
	if cacheErr == nil {
		a.emit(fmt.Sprintf("GitHub не отвечает (%v). Беру Xray, сохранённый на этом компьютере: %s.", latestErr, meta.Describe()))
		return cached, nil
	}
	return nil, fmt.Errorf("%v. На этом компьютере сохранённого Xray тоже нет: скачайте архив %s любым способом "+
		"(с сайта github.com/XTLS/Xray-core, вместе с %s.dgst, если получится) и выберите его кнопкой «Xray из файла…»", latestErr, name, name)
}

func (a *App) saveXray(name string, archive []byte, meta xraydist.Meta) {
	if err := a.cache.SaveXray(name, archive, meta); err != nil {
		a.emit("Не удалось сохранить Xray на компьютере: " + err.Error())
	}
}

// installXray заливает xray из архива на сервер и ставит его через update-xray.sh.
func (a *App) installXray(id string, c *conn, archive []byte) error {
	files, err := xraydist.Extract(archive)
	if err != nil {
		return err
	}
	dir := c.dir + "/xray-new"
	if r, err := c.client.Run(a.ctx, "mkdir -p "+remote.Quote(dir), false, nil); err != nil {
		return err
	} else if r.Code != 0 {
		return commandError(r)
	}
	a.emit("Заливаю Xray на сервер...")
	if err := c.client.Upload(a.ctx, dir+"/xray", files["xray"], "700"); err != nil {
		return err
	}
	return a.runDetached(id, c, "update-xray.sh", " "+remote.Quote(dir), "обновление Xray не удалось")
}

// MigrateUsers переносит пользователей (на мосту — ещё выходы и сайты напрямую) с srcID на dstID.
// Секреты идут через память и временный файл с правами 600 на целевом сервере, который сразу удаляется.
func (a *App) MigrateUsers(srcID, dstID string, keepKeys bool) (any, error) {
	if srcID == dstID {
		return nil, errors.New("выберите другой сервер")
	}
	exported, err := a.tool(srcID, false, "migrate", "export")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(exported)
	if err != nil {
		return nil, err
	}
	return a.importPayload(dstID, payload, keepKeys)
}

// importPayload ставит на dstID данные из migrate export: при переносе и при восстановлении копии.
func (a *App) importPayload(dstID string, payload []byte, keepKeys bool) (any, error) {
	if err := a.ensurePython(dstID); err != nil {
		return nil, err
	}
	c, err := a.connect(dstID)
	if err != nil {
		return nil, err
	}
	path := c.dir + "/migrate.json"
	if err := c.client.Upload(a.ctx, path, payload, "600"); err != nil {
		return nil, err
	}
	defer c.client.Run(a.ctx, "rm -f "+remote.Quote(path), false, nil)
	args := []string{"migrate", "import", path, "--json"}
	if keepKeys {
		args = append(args, "--keys")
	}
	return a.tool(dstID, false, args...)
}

// ChooseBackupSave спрашивает, куда сохранить копию. Пустая строка — пользователь отменил.
func (a *App) ChooseBackupSave(serverName string) (string, error) {
	name := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`\/:*?"<>|`, r) {
			return '-'
		}
		return r
	}, serverName)
	return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Сохранить резервную копию сервера",
		DefaultFilename: fmt.Sprintf("%s %s.pereprava", name, time.Now().Format("2006-01-02")),
		Filters:         []runtime.FileFilter{{DisplayName: "Копия «Переправы» (*.pereprava)", Pattern: "*.pereprava"}},
	})
}

// ChooseBackupOpen спрашивает, какую копию восстановить. Пустая строка — пользователь отменил.
func (a *App) ChooseBackupOpen() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Восстановить сервер из копии",
		Filters: []runtime.FileFilter{{DisplayName: "Копия «Переправы» (*.pereprava)", Pattern: "*.pereprava"}},
	})
}

// BackupServer сохраняет пользователей, ключи Reality, выходы и сайты напрямую в файл с паролем.
func (a *App) BackupServer(id, path, password string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("не выбран файл копии")
	}
	srv, err := a.store.Get(id)
	if err != nil {
		return err
	}
	exported, err := a.tool(id, false, "migrate", "export")
	if err != nil {
		return err
	}
	plain, err := json.Marshal(exported)
	if err != nil {
		return err
	}
	content, err := backup.Seal(plain, password, srv.Name, srv.Host)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

// InspectBackup показывает, с какого сервера и когда сделана копия, без пароля.
func (a *App) InspectBackup(path string) (backup.Header, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return backup.Header{}, err
	}
	return backup.Inspect(content)
}

// RestoreBackup ставит на сервер id данные из копии, как перенос: занятые имена и UUID пропускаются.
func (a *App) RestoreBackup(id, path, password string, keepKeys bool) (any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, plain, err := backup.Open(content, password)
	if err != nil {
		return nil, err
	}
	return a.importPayload(id, plain, keepKeys)
}

// AllowBridgeOnExit открывает порт 443 выхода exitID для адреса моста bridgeID.
func (a *App) AllowBridgeOnExit(exitID, bridgeID string) error {
	bridge, err := a.store.Get(bridgeID)
	if err != nil {
		return err
	}
	ip := net.ParseIP(bridge.Host)
	if ip == nil || ip.To4() == nil {
		return errors.New("у моста в настройках указан не IPv4-адрес: разрешите его на выходе вручную")
	}
	c, err := a.connect(exitID)
	if err != nil {
		return err
	}
	cmd := "ufw allow from " + ip.String() + " to any port 443 proto tcp"
	r, err := c.client.Run(a.ctx, cmd, true, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return commandError(r)
	}
	return nil
}

// ListDirect возвращает свои домены, которые мост открывает напрямую.
func (a *App) ListDirect(id string) (any, error) {
	return a.tool(id, false, "direct", "list", "--json")
}

// OpenExit открывает выход и для клиентов (exitctl exit open): раскладка простого режима с теми же ключами,
// мост становится пользователем bridge, его ссылка не меняется, порт 443 открывается всем.
func (a *App) OpenExit(id string) (any, error) {
	if err := a.ensurePython(id); err != nil {
		return nil, err
	}
	return a.tool(id, true, "exit", "open", "--json")
}

// ListBuiltin возвращает встроенные списки «напрямую» моста: {domains, ips}.
func (a *App) ListBuiltin(id string) (any, error) {
	return a.tool(id, false, "direct", "builtin", "--json")
}

// ChangeBuiltin добавляет (add) или убирает (remove) запись встроенного списка: geosite:, domain:, geoip:, IP/сеть.
func (a *App) ChangeBuiltin(id, action, entry string) (any, error) {
	if action != "add" && action != "remove" {
		return nil, errors.New("неизвестное действие")
	}
	return a.tool(id, false, "direct", "builtin", action, strings.TrimSpace(entry), "--json")
}

// SetCountry заменяет встроенные списки наборами для страны моста.
func (a *App) SetCountry(id, country string) (any, error) {
	country = strings.ToLower(strings.TrimSpace(country))
	if !reCountry.MatchString(country) {
		return nil, errors.New("код страны — две латинские буквы, например ru или kz")
	}
	return a.tool(id, false, "direct", "country", country, "--json")
}

// AddDirect добавляет домен в список «напрямую».
func (a *App) AddDirect(id, domain string) error {
	domain = strings.TrimSpace(domain)
	if !reDomain.MatchString(domain) {
		return errors.New("это не похоже на домен")
	}
	return a.plainTool(id, "direct", "add", domain)
}

// RemoveDirect убирает домен из списка «напрямую».
func (a *App) RemoveDirect(id, domain string) error {
	return a.plainTool(id, "direct", "remove", domain)
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
func setupCommand(dir, mode, sni, bridgeIP, country string, sshPort int) (string, error) {
	env := "DEBIAN_FRONTEND=noninteractive SSH_PORT=" + strconv.Itoa(sshPort) + " bash "
	switch mode {
	case "simple":
		return env + remote.Quote(dir+"/simple-setup.sh") + " " + remote.Quote(sni), nil
	case "bridge":
		if country = strings.ToLower(strings.TrimSpace(country)); country == "" {
			country = "ru"
		}
		if !reCountry.MatchString(country) {
			return "", errors.New("код страны — две латинские буквы, например ru или kz")
		}
		return "COUNTRY=" + country + " " + env + remote.Quote(dir+"/bridge-setup.sh") + " " + remote.Quote(sni), nil
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
		a.emit("Сервер не может скачать Xray с GitHub: беру его на этом компьютере...")
		archive, err := a.getXray(lines[len(lines)-1])
		if err != nil {
			return err
		}
		files, err := xraydist.Extract(archive)
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
// country — код страны моста (ru, kz...): её сайты мост открывает сам; для других ролей не нужен.
func (a *App) Install(id, mode, sni, bridgeIP, country string) error {
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
	cmd, err := setupCommand(c.dir, mode, sni, bridgeIP, country, srv.Port)
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

// runDetached запускает скрипт на сервере отдельно от SSH-сессии (systemd-run) и следит за ним опросом.
// Скрипты, перезапускающие Xray, обрывают SSH, если компьютер ходит на сервер через этот же Xray:
// тогда приложение переподключается и дочитывает журнал и код выхода.
func (a *App) runDetached(id string, c *conn, script, args, failMsg string) error {
	unit := "pereprava-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	job := c.dir + "/" + unit
	if err := c.client.Upload(a.ctx, job+".sh", []byte(jobScript(c.dir+"/"+script, args, job)), "700"); err != nil {
		return err
	}
	r, err := c.client.Run(a.ctx, "systemd-run --quiet --collect --unit="+unit+" /bin/bash "+remote.Quote(job+".sh"), true, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return fmt.Errorf("%s: не удалось запустить задание: %s", failMsg, strings.TrimSpace(r.Stderr+" "+r.Stdout))
	}
	poll := "systemctl is-active --quiet " + unit + " && echo run || echo stop; cat " + remote.Quote(job+".rc") +
		" 2>/dev/null; echo; echo " + pollMark + "; cat " + remote.Quote(job+".log") + " 2>/dev/null"
	shown := 0
	deadline := time.Now().Add(15 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: задание на сервере не закончилось за 15 минут", failMsg)
		}
		ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
		r, err := c.client.Run(ctx, poll, true, nil)
		cancel()
		if err != nil {
			a.emit("Связь с сервером прервалась, переподключаюсь...")
			if c, err = a.reconnect(id, deadline); err != nil {
				return fmt.Errorf("%s: связь с сервером потеряна, а задание на сервере могло закончиться: %w", failMsg, err)
			}
			continue
		}
		st := parsePoll(r.Stdout)
		for ; shown < len(st.lines); shown++ {
			a.emit(st.lines[shown])
		}
		if st.done || !st.running {
			_, _ = c.client.Run(a.ctx, "rm -f "+remote.Quote(job+".sh")+" "+remote.Quote(job+".rc")+" "+remote.Quote(job+".log"), true, nil)
			if !st.done {
				return fmt.Errorf("%s: задание на сервере прервалось без кода выхода", failMsg)
			}
			if st.code != 0 {
				return fmt.Errorf("%s, код %d: смотрите журнал", failMsg, st.code)
			}
			return nil
		}
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// reconnect заново подключается к серверу, пока не выйдет срок: после перезапуска Xray туннель поднимается не сразу.
func (a *App) reconnect(id string, deadline time.Time) (*conn, error) {
	a.mu.Lock()
	if old, ok := a.conns[id]; ok {
		old.client.Close()
		delete(a.conns, id)
	}
	a.mu.Unlock()
	for {
		c, err := a.connect(id)
		if err == nil {
			a.emit("Связь восстановлена.")
			return c, nil
		}
		if time.Now().Add(5 * time.Second).After(deadline) {
			return nil, err
		}
		select {
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

const pollMark = "@@pereprava-log@@"

// jobScript — обёртка для systemd-run: журнал в .log, код выхода в .rc (атомарно, через .tmp).
func jobScript(script, args, job string) string {
	return "#!/bin/bash\n" +
		"bash " + remote.Quote(script) + args + " >" + remote.Quote(job+".log") + " 2>&1\n" +
		"echo $? >" + remote.Quote(job+".rc.tmp") + "\n" +
		"mv " + remote.Quote(job+".rc.tmp") + " " + remote.Quote(job+".rc") + "\n"
}

type pollState struct {
	running, done bool
	code          int
	lines         []string
}

// parsePoll разбирает ответ опроса: состояние юнита, код выхода (если есть), затем журнал.
// Пока задание идёт, последняя строка журнала без перевода строки не показывается: она может быть недописана.
func parsePoll(out string) pollState {
	head, log, _ := strings.Cut(out, pollMark+"\n")
	var st pollState
	f := strings.Fields(head)
	if len(f) > 0 {
		st.running = f[0] == "run"
	}
	if len(f) > 1 {
		if n, err := strconv.Atoi(f[1]); err == nil {
			st.done, st.code = true, n
		}
	}
	log = strings.ReplaceAll(log, "\r", "")
	if !st.done {
		log = log[:strings.LastIndex(log, "\n")+1]
	}
	log = strings.TrimSuffix(log, "\n")
	if log != "" {
		st.lines = strings.Split(log, "\n")
	}
	return st
}

// Uninstall снимает установку: Xray, конфиги, ссылки и правила файрвола для 443.
func (a *App) Uninstall(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	return a.runDetached(id, c, "uninstall.sh", "", "удаление не удалось")
}

// UpdateGeodata скачивает свежие списки сайтов на этом компьютере и ставит их на сервер.
// Если GitHub не отвечает, берутся списки, сохранённые на компьютере.
func (a *App) UpdateGeodata(id string) error {
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	a.emit("Скачиваю списки сайтов на этом компьютере...")
	files, err := xraydist.DownloadGeo(a.ctx)
	if err == nil {
		a.saveGeo(files, xraydist.Meta{Source: "github", Saved: time.Now(), Checked: true})
	} else {
		cached, meta, cacheErr := a.cache.LoadGeo()
		if cacheErr != nil {
			return fmt.Errorf("%v. На этом компьютере сохранённых списков тоже нет: скачайте geoip.dat и dlc.dat "+
				"любым способом (с github.com/v2fly, вместе с файлами .sha256sum, если получится) и выберите их кнопкой «Списки из файлов…»", err)
		}
		a.emit(fmt.Sprintf("GitHub не отвечает (%v). Беру списки, сохранённые на этом компьютере: %s.", err, meta.Describe()))
		files = cached
	}
	return a.installGeo(id, c, files)
}

// UpdateGeodataFromFiles ставит на сервер выбранные geoip.dat и geosite.dat (dlc.dat)
// и сохраняет их на компьютере.
func (a *App) UpdateGeodataFromFiles(id string, paths []string) error {
	files, meta, err := xraydist.ReadGeoFiles(paths)
	if err != nil {
		return err
	}
	c, err := a.connect(id)
	if err != nil {
		return err
	}
	if !meta.Checked {
		a.emit("Не у всех списков рядом лежит файл .sha256sum: их контрольные суммы не проверены.")
	}
	a.saveGeo(files, meta)
	return a.installGeo(id, c, files)
}

func (a *App) saveGeo(files map[string][]byte, meta xraydist.Meta) {
	if err := a.cache.SaveGeo(files, meta); err != nil {
		a.emit("Не удалось сохранить списки на компьютере: " + err.Error())
	}
}

func (a *App) installGeo(id string, c *conn, files map[string][]byte) error {
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
	return a.runDetached(id, c, "update-geodata.sh", " "+remote.Quote(dir), "обновление не удалось")
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

// CheckReach проверяет с сервера fromID, достаёт ли он до SSH-порта сервера toID.
// Порт SSH открыт ещё до установки выхода, поэтому проверка работает заранее.
func (a *App) CheckReach(fromID, toID string) (any, error) {
	to, err := a.store.Get(toID)
	if err != nil {
		return nil, err
	}
	if err := a.ensurePython(fromID); err != nil {
		return nil, err
	}
	return a.tool(fromID, false, "reach", to.Host, strconv.Itoa(to.Port), "--json")
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

// SetUserLimit задаёт срок доступа и лимит трафика. until — ISO-время с поясом или "" (без срока),
// trafficGB <= 0 — без лимита. Пользователь, вышедший за них, сразу отключается, а продлённый — включается.
// Срок и лимит проверяет cron на сервере (exitctl user enforce), поэтому сначала ставится exitctl из приложения:
// на серверах, настроенных старыми версиями, установленный exitctl этой команды не знает.
func (a *App) SetUserLimit(id, name, until string, trafficGB float64) (any, error) {
	if err := a.UpdateTool(id); err != nil {
		return nil, err
	}
	args := []string{"user", "limit", name, "--json"}
	if until = strings.TrimSpace(until); until == "" {
		args = append(args, "--no-expiry")
	} else {
		args = append(args, "--until", until)
	}
	if trafficGB > 0 {
		args = append(args, "--traffic", strconv.FormatFloat(trafficGB, 'f', -1, 64))
	} else {
		args = append(args, "--no-traffic")
	}
	return a.userTool(id, args...)
}

// SetUserEnabled отключает или включает пользователя вручную; ссылка при этом не меняется.
func (a *App) SetUserEnabled(id, name string, enabled bool) (any, error) {
	action := "disable"
	if enabled {
		action = "enable"
	}
	return a.userTool(id, "user", action, name, "--json")
}

// ResetUserTraffic обнуляет накопленный трафик пользователя: например, с начала нового месяца.
func (a *App) ResetUserTraffic(id, name string) (any, error) {
	return a.userTool(id, "user", "reset", name, "--json")
}

// userTool вызывает exitctl user ... с адресом сервера для ссылок.
func (a *App) userTool(id string, args ...string) (any, error) {
	srv, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	return a.tool(id, false, append(args, "--host", srv.Host)...)
}

// QRCode рисует ссылку как PNG в data-URL. Работает локально, ссылка никуда не отправляется.
func (a *App) QRCode(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
