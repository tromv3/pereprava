// Package xraydist скачивает Xray на этом компьютере, чтобы залить его на VPS без доступа к GitHub.
package xraydist

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// BaseURL — адрес последнего релиза Xray-core.
var BaseURL = "https://github.com/XTLS/Xray-core/releases/latest/download"

// Files — файлы архива, которые нужны на сервере.
var Files = []string{"xray", "geoip.dat", "geosite.dat"}

const maxArchive = 200 << 20

var reSHA256 = regexp.MustCompile(`(?m)^SHA2-256=\s*([0-9a-fA-F]{64})\s*$`)

// ArchiveName возвращает имя архива для вывода `uname -m`.
func ArchiveName(machine string) (string, error) {
	switch strings.TrimSpace(machine) {
	case "x86_64", "amd64":
		return "Xray-linux-64.zip", nil
	case "aarch64", "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "windows-amd64":
		return "Xray-windows-64.zip", nil
	case "windows-arm64":
		return "Xray-windows-arm64-v8a.zip", nil
	}
	return "", fmt.Errorf("архитектура сервера %q не поддерживается", strings.TrimSpace(machine))
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: ответ %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArchive {
		return nil, fmt.Errorf("%s: файл слишком большой", url)
	}
	return data, nil
}

// Verify сверяет архив с контрольной суммой из файла .dgst.
func Verify(archive []byte, dgst string) error {
	m := reSHA256.FindStringSubmatch(dgst)
	if m == nil {
		return fmt.Errorf("в файле .dgst нет суммы SHA2-256")
	}
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m[1]) {
		return fmt.Errorf("контрольная сумма архива не совпала")
	}
	return nil
}

// Extract достаёт из архива файлы Files.
func Extract(archive []byte) (map[string][]byte, error) { return ExtractNames(archive, Files, nil) }

// ExtractNames достаёт из архива файлы names (обязательные) и optional (если есть).
func ExtractNames(archive []byte, names, optional []string) (map[string][]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("архив повреждён: %w", err)
	}
	out := map[string][]byte{}
	for _, f := range r.File {
		for _, want := range append(append([]string{}, names...), optional...) {
			if f.Name != want {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(io.LimitReader(rc, maxArchive))
			rc.Close()
			if err != nil {
				return nil, err
			}
			out[want] = data
		}
	}
	for _, want := range names {
		if len(out[want]) == 0 {
			return nil, fmt.Errorf("в архиве нет файла %s", want)
		}
	}
	return out, nil
}

// Адреса списков сайтов: те же, откуда их берёт официальный установщик Xray.
var (
	GeoipURL   = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
	GeositeURL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
)

var reSum = regexp.MustCompile(`(?m)^([0-9a-fA-F]{64})\b`)

// VerifySum сверяет файл с содержимым .sha256sum.
func VerifySum(data []byte, sumFile string) error {
	m := reSum.FindStringSubmatch(sumFile)
	if m == nil {
		return fmt.Errorf("в файле .sha256sum нет суммы")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m[1]) {
		return fmt.Errorf("контрольная сумма не совпала")
	}
	return nil
}

// DownloadGeo скачивает и проверяет свежие geoip.dat и geosite.dat.
func DownloadGeo(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	for name, url := range map[string]string{"geoip.dat": GeoipURL, "geosite.dat": GeositeURL} {
		data, err := fetch(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("не удалось скачать %s: %w", name, err)
		}
		sum, err := fetch(ctx, url+".sha256sum")
		if err != nil {
			return nil, fmt.Errorf("не удалось скачать контрольную сумму %s: %w", name, err)
		}
		if err := VerifySum(data, string(sum)); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = data
	}
	return out, nil
}

// Download скачивает и проверяет Xray для архитектуры machine.
func Download(ctx context.Context, machine string) (map[string][]byte, error) {
	name, err := ArchiveName(machine)
	if err != nil {
		return nil, err
	}
	archive, err := DownloadArchive(ctx, name)
	if err != nil {
		return nil, err
	}
	return Extract(archive)
}

// DownloadArchive скачивает архив Xray name и сверяет его с .dgst.
func DownloadArchive(ctx context.Context, name string) ([]byte, error) {
	archive, err := fetch(ctx, BaseURL+"/"+name)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать Xray: %w", err)
	}
	dgst, err := fetch(ctx, BaseURL+"/"+name+".dgst")
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать контрольную сумму Xray: %w", err)
	}
	if err := Verify(archive, string(dgst)); err != nil {
		return nil, err
	}
	if _, err := ExtractNames(archive, FilesFor(name), nil); err != nil {
		return nil, err
	}
	return archive, nil
}

// FilesFor — обязательные файлы архива name: для Windows программа называется xray.exe.
func FilesFor(name string) []string {
	if strings.Contains(name, "windows") {
		return []string{"xray.exe", "geoip.dat", "geosite.dat"}
	}
	return Files
}

var reTag = regexp.MustCompile(`/tag/v?([0-9][0-9A-Za-z.\-]*)$`)

// LatestVersion узнаёт номер последнего релиза Xray по переадресации страницы latest на страницу тега:
// так не тратится лимит API GitHub.
func LatestVersion(ctx context.Context) (string, error) {
	url := strings.TrimSuffix(BaseURL, "/download")
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось узнать последнюю версию Xray: %w", err)
	}
	resp.Body.Close()
	m := reTag.FindStringSubmatch(resp.Header.Get("Location"))
	if m == nil {
		return "", fmt.Errorf("не удалось узнать последнюю версию Xray: ответ %d без ссылки на релиз", resp.StatusCode)
	}
	return m[1], nil
}
