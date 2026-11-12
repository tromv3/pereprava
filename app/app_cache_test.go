package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vless-bridge/internal/xraydist"
)

func fakeXrayZip(t *testing.T, mark string) []byte {
	t.Helper()
	elf := make([]byte, 64)
	copy(elf, "\x7fELF")
	elf[4], elf[5], elf[18] = 2, 1, 62
	copy(elf[32:], mark)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"xray": elf, "geoip.dat": {0x0a, 0}, "geosite.dat": {0x0a, 0}} {
		f, _ := w.Create(name)
		f.Write(data)
	}
	w.Close()
	return buf.Bytes()
}

// fakeGitHub отдаёт релиз version с архивом archive; down — GitHub «не отвечает».
func fakeGitHub(t *testing.T, version string, archive []byte, down *bool, downloads *int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *down {
			http.Error(w, "нет", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/releases/latest":
			http.Redirect(w, r, "https://github.com/XTLS/Xray-core/releases/tag/v"+version, http.StatusFound)
		case "/releases/latest/download/Xray-linux-64.zip":
			*downloads++
			w.Write(archive)
		case "/releases/latest/download/Xray-linux-64.zip.dgst":
			s := sha256.Sum256(archive)
			w.Write([]byte("SHA2-256= " + hex.EncodeToString(s[:]) + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := xraydist.BaseURL
	xraydist.BaseURL = srv.URL + "/releases/latest/download"
	t.Cleanup(func() { xraydist.BaseURL = old })
}

func TestGetXray(t *testing.T) {
	var log []string
	a := &App{ctx: context.Background(), cache: xraydist.Cache{Dir: t.TempDir()}, logHook: func(l string) { log = append(log, l) }}
	archive := fakeXrayZip(t, "v1")
	down, downloads := false, 0
	fakeGitHub(t, "26.11.9", archive, &down, &downloads)

	// Первый раз — скачивание и сохранение.
	got, err := a.getXray("x86_64")
	if err != nil || !bytes.Equal(got, archive) || downloads != 1 {
		t.Fatalf("скачивание: %v, загрузок %d", err, downloads)
	}
	// Та же версия уже сохранена — без скачивания.
	if got, err = a.getXray("x86_64"); err != nil || !bytes.Equal(got, archive) || downloads != 1 {
		t.Fatalf("из кэша: %v, загрузок %d", err, downloads)
	}
	if !strings.Contains(strings.Join(log, "\n"), "уже скачан") {
		t.Fatalf("журнал: %q", log)
	}

	// GitHub не отвечает — сохранённая копия.
	down = true
	a.latest = ""
	log = nil
	if got, err = a.getXray("x86_64"); err != nil || !bytes.Equal(got, archive) {
		t.Fatalf("без GitHub: %v", err)
	}
	if !strings.Contains(strings.Join(log, "\n"), "сохранённый на этом компьютере: 26.11.9") {
		t.Fatalf("журнал: %q", log)
	}

	// Без GitHub и без копии — ошибка с подсказкой про файл.
	a.cache = xraydist.Cache{Dir: t.TempDir()}
	if _, err = a.getXray("x86_64"); err == nil || !strings.Contains(err.Error(), "Xray из файла") || !strings.Contains(err.Error(), "Xray-linux-64.zip") {
		t.Fatalf("без копии: %v", err)
	}

	// Новая версия на GitHub — скачивается, хотя копия есть.
	down = false
	newer := fakeXrayZip(t, "v2")
	a.cache.SaveXray("Xray-linux-64.zip", archive, xraydist.Meta{Version: "26.11.9", Source: "github", Saved: time.Now()})
	fakeGitHub(t, "26.12.1", newer, &down, &downloads)
	a.latest = ""
	if got, err = a.getXray("x86_64"); err != nil || !bytes.Equal(got, newer) {
		t.Fatalf("новая версия: %v", err)
	}
	if _, meta, _ := a.cache.LoadXray("Xray-linux-64.zip"); meta.Version != "26.12.1" {
		t.Fatalf("в кэше %+v", meta)
	}
}
