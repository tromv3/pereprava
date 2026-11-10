package xraydist

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
)

func makeZip(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range names {
		f, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("содержимое " + n))
	}
	w.Close()
	return buf.Bytes()
}

func dgstFor(data []byte) string {
	s := sha256.Sum256(data)
	return "MD5= 00\nSHA1= 00\nSHA2-256= " + hex.EncodeToString(s[:]) + "\nSHA2-512= 00\n"
}

func TestArchiveName(t *testing.T) {
	for in, want := range map[string]string{"x86_64\n": "Xray-linux-64.zip", "aarch64": "Xray-linux-arm64-v8a.zip"} {
		if got, err := ArchiveName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ArchiveName("mips"); err == nil {
		t.Error("неизвестная архитектура должна дать ошибку")
	}
}

func TestVerify(t *testing.T) {
	data := []byte("архив")
	if err := Verify(data, dgstFor(data)); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("другое"), dgstFor(data)); err == nil {
		t.Fatal("чужая сумма должна дать ошибку")
	}
	if err := Verify(data, "мусор"); err == nil {
		t.Fatal("файл без суммы должен дать ошибку")
	}
}

func TestExtract(t *testing.T) {
	out, err := Extract(makeZip(t, "xray", "geoip.dat", "geosite.dat", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || !strings.Contains(string(out["xray"]), "xray") {
		t.Fatalf("%v", out)
	}
	if _, err := Extract(makeZip(t, "xray")); err == nil {
		t.Fatal("неполный архив должен дать ошибку")
	}
	if _, err := Extract([]byte("не zip")); err == nil {
		t.Fatal("повреждённый архив должен дать ошибку")
	}
}

func TestDownloadGeo(t *testing.T) {
	files := map[string][]byte{"/geoip.dat": []byte("ip-список"), "/dlc.dat": []byte("сайты")}
	broken := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := files[strings.TrimSuffix(r.URL.Path, ".sha256sum")]; ok {
			if strings.HasSuffix(r.URL.Path, ".sha256sum") {
				s := sha256.Sum256(data)
				w.Write([]byte(hex.EncodeToString(s[:]) + "  file.dat\n"))
				return
			}
			if broken {
				w.Write([]byte("подмена"))
				return
			}
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	oldIP, oldSite := GeoipURL, GeositeURL
	GeoipURL, GeositeURL = srv.URL+"/geoip.dat", srv.URL+"/dlc.dat"
	defer func() { GeoipURL, GeositeURL = oldIP, oldSite }()

	out, err := DownloadGeo(context.Background())
	if err != nil || string(out["geoip.dat"]) != "ip-список" || string(out["geosite.dat"]) != "сайты" {
		t.Fatalf("%v %v", out, err)
	}
	broken = true
	if _, err := DownloadGeo(context.Background()); err == nil {
		t.Fatal("подменённый файл должен дать ошибку")
	}
	if err := VerifySum([]byte("x"), "мусор"); err == nil {
		t.Fatal("файл без суммы должен дать ошибку")
	}
}

func TestDownload(t *testing.T) {
	archive := makeZip(t, "xray", "geoip.dat", "geosite.dat")
	bad := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Xray-linux-64.zip":
			if bad {
				w.Write([]byte("подмена"))
				return
			}
			w.Write(archive)
		case "/Xray-linux-64.zip.dgst":
			w.Write([]byte(dgstFor(archive)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	out, err := Download(context.Background(), "x86_64")
	if err != nil || len(out) != 3 {
		t.Fatalf("%v %v", out, err)
	}
	bad = true
	if _, err := Download(context.Background(), "x86_64"); err == nil {
		t.Fatal("подменённый архив должен дать ошибку")
	}
	if _, err := Download(context.Background(), "aarch64"); err == nil {
		t.Fatal("404 должен дать ошибку")
	}
}

func TestLatestVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "https://github.com/XTLS/Xray-core/releases/tag/v26.11.9", http.StatusFound)
	}))
	defer srv.Close()
	old := BaseURL
	defer func() { BaseURL = old }()
	BaseURL = srv.URL + "/releases/latest/download"
	v, err := LatestVersion(context.Background())
	if err != nil || v != "26.11.9" {
		t.Fatalf("%q %v", v, err)
	}
	BaseURL = srv.URL + "/nowhere/download"
	if _, err := LatestVersion(context.Background()); err == nil {
		t.Fatal("без переадресации нужна ошибка")
	}
}
