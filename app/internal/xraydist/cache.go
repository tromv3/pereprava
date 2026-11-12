package xraydist

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Meta описывает сохранённую на компьютере копию: откуда она и проверена ли контрольной суммой.
type Meta struct {
	Version string    `json:"version,omitempty"` // номер релиза Xray, если известен
	Source  string    `json:"source"`            // "github" или "file"
	File    string    `json:"file,omitempty"`    // имя выбранного файла
	Saved   time.Time `json:"saved"`
	SHA256  string    `json:"sha256"`
	Checked bool      `json:"checked"` // сверена с .dgst или .sha256sum
}

// Describe — короткое описание копии для журнала.
func (m Meta) Describe() string {
	var parts []string
	if m.Version != "" {
		parts = append(parts, m.Version)
	}
	if m.Source == "file" {
		parts = append(parts, "из файла "+m.File)
	} else {
		parts = append(parts, "с GitHub")
	}
	parts = append(parts, m.Saved.Local().Format("02.01.2006"))
	if !m.Checked {
		parts = append(parts, "без проверки контрольной суммы")
	}
	return strings.Join(parts, ", ")
}

// Cache — последние скачанные или выбранные Xray и списки сайтов на этом компьютере.
// Нужен, когда GitHub не отвечает: тогда на сервер идёт сохранённая копия.
type Cache struct{ Dir string }

// ErrNoCache — сохранённой копии нет.
var ErrNoCache = errors.New("сохранённой копии нет")

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c Cache) save(files map[string][]byte, sub string, meta Meta) error {
	if c.Dir == "" {
		return nil
	}
	dir := filepath.Join(c.Dir, sub)
	for name, data := range files {
		if err := writeAtomic(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	m, _ := json.MarshalIndent(meta, "", "  ")
	return writeAtomic(filepath.Join(dir, "meta.json"), m)
}

func (c Cache) load(sub string, names []string) (map[string][]byte, Meta, error) {
	var meta Meta
	if c.Dir == "" {
		return nil, meta, ErrNoCache
	}
	dir := filepath.Join(c.Dir, sub)
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, meta, ErrNoCache
	}
	if err != nil {
		return nil, meta, err
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, meta, fmt.Errorf("сохранённая копия повреждена: %w", err)
	}
	out := map[string][]byte{}
	h := sha256.New()
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			return nil, meta, ErrNoCache
		}
		if err != nil {
			return nil, meta, err
		}
		h.Write(data)
		out[name] = data
	}
	if hex.EncodeToString(h.Sum(nil)) != meta.SHA256 {
		return nil, meta, errors.New("сохранённая копия повреждена: контрольная сумма не совпала")
	}
	return out, meta, nil
}

func sumOf(names []string, files map[string][]byte) string {
	h := sha256.New()
	for _, name := range names {
		h.Write(files[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func xraySub(archiveName string) string {
	return filepath.Join("xray", strings.TrimSuffix(archiveName, ".zip"))
}

// GeoFiles — имена списков сайтов на сервере.
var GeoFiles = []string{"geoip.dat", "geosite.dat"}

// SaveXray сохраняет проверенный архив Xray для архитектуры archiveName.
func (c Cache) SaveXray(archiveName string, archive []byte, meta Meta) error {
	meta.SHA256 = sumOf([]string{"archive.zip"}, map[string][]byte{"archive.zip": archive})
	return c.save(map[string][]byte{"archive.zip": archive}, xraySub(archiveName), meta)
}

// LoadXray возвращает сохранённый архив Xray для архитектуры archiveName.
func (c Cache) LoadXray(archiveName string) ([]byte, Meta, error) {
	files, meta, err := c.load(xraySub(archiveName), []string{"archive.zip"})
	if err != nil {
		return nil, meta, err
	}
	return files["archive.zip"], meta, nil
}

// SaveGeo сохраняет geoip.dat и geosite.dat.
func (c Cache) SaveGeo(files map[string][]byte, meta Meta) error {
	meta.SHA256 = sumOf(GeoFiles, files)
	return c.save(files, "geo", meta)
}

// LoadGeo возвращает сохранённые geoip.dat и geosite.dat.
func (c Cache) LoadGeo() (map[string][]byte, Meta, error) { return c.load("geo", GeoFiles) }

// ELF-архитектуры, для которых есть архивы Xray.
var elfMachines = map[uint16]string{62: "Xray-linux-64.zip", 183: "Xray-linux-arm64-v8a.zip"}

// ArchiveNameOf определяет по файлу xray внутри архива, для какой архитектуры он собран.
func ArchiveNameOf(archive []byte) (string, error) {
	files, err := Extract(archive)
	if err != nil {
		return "", err
	}
	bin := files["xray"]
	if len(bin) < 20 || !bytes.Equal(bin[:4], []byte("\x7fELF")) {
		return "", errors.New("xray в архиве — не программа для Linux")
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if bin[5] == 2 {
		order = binary.BigEndian
	}
	name, ok := elfMachines[order.Uint16(bin[18:20])]
	if !ok {
		return "", errors.New("архив собран для архитектуры, которую приложение не поддерживает: нужен Xray-linux-64.zip или Xray-linux-arm64-v8a.zip")
	}
	return name, nil
}

// ReadXrayFile читает выбранный пользователем архив Xray. Если рядом лежит файл .dgst,
// архив сверяется с ним; без него принимается, но помечается как непроверенный.
func ReadXrayFile(path string) (archive []byte, archiveName string, meta Meta, err error) {
	archive, err = readLimited(path)
	if err != nil {
		return nil, "", meta, err
	}
	archiveName, err = ArchiveNameOf(archive)
	if err != nil {
		return nil, "", meta, fmt.Errorf("%s не подходит: нужен архив Xray для Linux (Xray-linux-64.zip): %w", filepath.Base(path), err)
	}
	meta = Meta{Source: "file", File: filepath.Base(path), Saved: time.Now()}
	if dgst, err := os.ReadFile(path + ".dgst"); err == nil {
		if err := Verify(archive, string(dgst)); err != nil {
			return nil, "", meta, err
		}
		meta.Checked = true
	}
	return archive, archiveName, meta, nil
}

// ReadGeoFiles читает выбранные пользователем списки: geoip.dat и geosite.dat (или dlc.dat),
// узнавая их по имени. Файлы .sha256sum рядом, если есть, сверяются.
func ReadGeoFiles(paths []string) (map[string][]byte, Meta, error) {
	meta := Meta{Source: "file", Saved: time.Now(), Checked: true}
	out := map[string][]byte{}
	var names []string
	for _, p := range paths {
		base := strings.ToLower(filepath.Base(p))
		var name string
		switch {
		case strings.Contains(base, "geoip"):
			name = "geoip.dat"
		case strings.Contains(base, "geosite"), strings.Contains(base, "dlc"):
			name = "geosite.dat"
		default:
			return nil, meta, fmt.Errorf("%s: по имени не понять, geoip это или geosite", filepath.Base(p))
		}
		if out[name] != nil {
			return nil, meta, fmt.Errorf("выбрано два файла %s", name)
		}
		data, err := readLimited(p)
		if err != nil {
			return nil, meta, err
		}
		// Список — protobuf, где каждая запись — поле 1 с длиной: первый байт 0x0A.
		if len(data) < 2 || data[0] != 0x0a {
			return nil, meta, fmt.Errorf("%s не похож на список сайтов Xray", filepath.Base(p))
		}
		if sum, err := os.ReadFile(p + ".sha256sum"); err == nil {
			if err := VerifySum(data, string(sum)); err != nil {
				return nil, meta, fmt.Errorf("%s: %w", filepath.Base(p), err)
			}
		} else {
			meta.Checked = false
		}
		out[name] = data
		names = append(names, filepath.Base(p))
	}
	for _, name := range GeoFiles {
		if out[name] == nil {
			return nil, meta, fmt.Errorf("не выбран %s: нужны оба файла, geoip.dat и geosite.dat (или dlc.dat)", name)
		}
	}
	meta.File = strings.Join(names, ", ")
	return out, meta, nil
}

func readLimited(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxArchive {
		return nil, fmt.Errorf("%s: файл слишком большой", filepath.Base(path))
	}
	return os.ReadFile(path)
}
