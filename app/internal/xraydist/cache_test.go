package xraydist

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// xrayZip — архив, где xray начинается с заголовка ELF для машины machine (62 — x86_64, 183 — aarch64).
func xrayZip(t *testing.T, machine byte) []byte {
	t.Helper()
	elf := make([]byte, 64)
	copy(elf, "\x7fELF")
	elf[4], elf[5] = 2, 1 // 64 бита, little-endian
	elf[18] = machine
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"xray": elf, "geoip.dat": {0x0a, 1, 0}, "geosite.dat": {0x0a, 1, 0}} {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(data)
	}
	w.Close()
	return buf.Bytes()
}

func TestArchiveNameOf(t *testing.T) {
	if n, err := ArchiveNameOf(xrayZip(t, 62)); err != nil || n != "Xray-linux-64.zip" {
		t.Fatalf("x86_64: %q %v", n, err)
	}
	if n, err := ArchiveNameOf(xrayZip(t, 183)); err != nil || n != "Xray-linux-arm64-v8a.zip" {
		t.Fatalf("arm64: %q %v", n, err)
	}
	if _, err := ArchiveNameOf(xrayZip(t, 40)); err == nil {
		t.Fatal("arm32 не поддерживается")
	}
	if _, err := ArchiveNameOf(makeZip(t, Files...)); err == nil {
		t.Fatal("не ELF — ошибка")
	}
}

func TestCacheXray(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	if _, _, err := c.LoadXray("Xray-linux-64.zip"); err != ErrNoCache {
		t.Fatalf("пустой кэш: %v", err)
	}
	archive := xrayZip(t, 62)
	saved := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	if err := c.SaveXray("Xray-linux-64.zip", archive, Meta{Version: "26.11.9", Source: "github", Saved: saved, Checked: true}); err != nil {
		t.Fatal(err)
	}
	got, meta, err := c.LoadXray("Xray-linux-64.zip")
	if err != nil || !bytes.Equal(got, archive) || meta.Version != "26.11.9" || !meta.Saved.Equal(saved) {
		t.Fatalf("%v %+v", err, meta)
	}
	if _, _, err := c.LoadXray("Xray-linux-arm64-v8a.zip"); err != ErrNoCache {
		t.Fatalf("другая архитектура: %v", err)
	}
	// Испорченный файл не отдаётся.
	os.WriteFile(filepath.Join(c.Dir, "xray", "Xray-linux-64", "archive.zip"), []byte("мусор"), 0o600)
	if _, _, err := c.LoadXray("Xray-linux-64.zip"); err == nil || err == ErrNoCache {
		t.Fatalf("испорченный кэш: %v", err)
	}
	// Без каталога кэш просто не работает.
	if err := (Cache{}).SaveXray("Xray-linux-64.zip", archive, Meta{}); err != nil {
		t.Fatal(err)
	}
}

func TestCacheGeo(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	files := map[string][]byte{"geoip.dat": {0x0a, 1}, "geosite.dat": {0x0a, 2}}
	if err := c.SaveGeo(files, Meta{Source: "file", File: "geoip.dat, dlc.dat", Saved: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, meta, err := c.LoadGeo()
	if err != nil || !bytes.Equal(got["geosite.dat"], files["geosite.dat"]) || meta.Source != "file" {
		t.Fatalf("%v %+v", err, meta)
	}
	if d := meta.Describe(); !strings.Contains(d, "из файла geoip.dat, dlc.dat") || !strings.Contains(d, "без проверки") {
		t.Fatalf("описание: %q", d)
	}
}

func TestReadXrayFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "Xray-linux-64.zip")
	archive := xrayZip(t, 62)
	os.WriteFile(p, archive, 0o600)
	_, name, meta, err := ReadXrayFile(p)
	if err != nil || name != "Xray-linux-64.zip" || meta.Checked || meta.Source != "file" || meta.File != "Xray-linux-64.zip" {
		t.Fatalf("без .dgst: %q %+v %v", name, meta, err)
	}
	os.WriteFile(p+".dgst", []byte(dgstFor(archive)), 0o600)
	if _, _, meta, err := ReadXrayFile(p); err != nil || !meta.Checked {
		t.Fatalf("с .dgst: %+v %v", meta, err)
	}
	os.WriteFile(p+".dgst", []byte(dgstFor([]byte("другое"))), 0o600)
	if _, _, _, err := ReadXrayFile(p); err == nil {
		t.Fatal("сумма не совпала — ошибка")
	}
}

func TestReadGeoFiles(t *testing.T) {
	dir := t.TempDir()
	ip, site := filepath.Join(dir, "geoip.dat"), filepath.Join(dir, "dlc.dat")
	os.WriteFile(ip, []byte{0x0a, 3, 'a', 'b', 'c'}, 0o600)
	os.WriteFile(site, []byte{0x0a, 1, 'x'}, 0o600)
	files, meta, err := ReadGeoFiles([]string{site, ip})
	if err != nil || files["geosite.dat"][2] != 'x' || meta.Checked {
		t.Fatalf("%v %+v", err, meta)
	}
	os.WriteFile(ip+".sha256sum", []byte(strings.Repeat("0", 64)+"  geoip.dat\n"), 0o600)
	if _, _, err := ReadGeoFiles([]string{site, ip}); err == nil {
		t.Fatal("сумма не совпала — ошибка")
	}
	os.Remove(ip + ".sha256sum")
	if _, _, err := ReadGeoFiles([]string{ip}); err == nil || !strings.Contains(err.Error(), "geosite.dat") {
		t.Fatalf("нужны оба: %v", err)
	}
	other := filepath.Join(dir, "list.dat")
	os.WriteFile(other, []byte{0x0a, 0}, 0o600)
	if _, _, err := ReadGeoFiles([]string{ip, other}); err == nil {
		t.Fatal("имя не опознано — ошибка")
	}
	bad := filepath.Join(dir, "geosite.dat")
	os.WriteFile(bad, []byte("<html>"), 0o600)
	if _, _, err := ReadGeoFiles([]string{ip, bad}); err == nil {
		t.Fatal("не protobuf — ошибка")
	}
}
