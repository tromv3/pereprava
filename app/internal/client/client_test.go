package client

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodLink = "vless://aaaaaaaa-0000-0000-0000-000000000000@203.0.113.9:443?type=tcp&security=reality&sni=site.example&pbk=PUBKEY1234567890abcdefXYZ&sid=ab12&fp=chrome&flow=xtls-rprx-vision#live-one"

func TestParseLink(t *testing.T) {
	l, err := ParseLink(goodLink)
	if err != nil || l.Host != "203.0.113.9" || l.Port != 443 || l.SNI != "site.example" || l.SID != "ab12" || l.Name != "live-one" {
		t.Fatalf("%+v %v", l, err)
	}
	bad := map[string]string{
		"не vless":    "vmess://abc",
		"без reality": strings.Replace(goodLink, "security=reality", "security=tls", 1),
		"ws":          strings.Replace(goodLink, "type=tcp", "type=ws", 1),
		"без порта":   strings.Replace(goodLink, ":443", "", 1),
		"без pbk":     strings.Replace(goodLink, "pbk=PUBKEY1234567890abcdefXYZ", "pbk=", 1),
		"плохой uuid": strings.Replace(goodLink, "aaaaaaaa-0000", "zz", 1),
		"плохой sid":  strings.Replace(goodLink, "sid=ab12", "sid=xyz", 1),
		"чужой flow":  strings.Replace(goodLink, "xtls-rprx-vision", "other", 1),
	}
	for name, link := range bad {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestConfig(t *testing.T) {
	l, _ := ParseLink(goodLink)
	data, err := Config(l, Options{SocksPort: 10880, HTTPPort: 10881, DirectDomains: []string{"domain:ru"}, DirectIPs: []string{"geoip:ru"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(data, &cfg)
	s := string(data)
	for _, want := range []string{`"publicKey": "PUBKEY1234567890abcdefXYZ"`, `"serverName": "site.example"`, `"flow": "xtls-rprx-vision"`,
		`"port": 10880`, `"port": 10881`, `"listen": "127.0.0.1"`, `"domain:ru"`, `"geoip:ru"`} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %s", want)
		}
	}
	if strings.Contains(s, `"tun"`) {
		t.Error("без TUN не должно быть адаптера")
	}
	if len(cfg["inbounds"].([]any)) != 2 {
		t.Error("ожидались socks и http")
	}
	data, _ = Config(l, Options{SocksPort: 1, HTTPPort: 2, TUN: true})
	s = string(data)
	for _, want := range []string{`"protocol": "tun"`, `"autoOutboundsInterface": "auto"`, `"autoSystemRoutingTable"`, `"protocol": "dns"`} {
		if !strings.Contains(s, want) {
			t.Errorf("TUN: нет %s", want)
		}
	}
	if _, err := Config(Link{}, Options{}); err == nil {
		t.Error("без ссылки — ошибка")
	}
}

// geoFile собирает protobuf-список с записями names.
func geoFile(names ...string) []byte {
	var out []byte
	for _, n := range names {
		entry := append([]byte{0x0a, byte(len(n))}, n...)
		entry = append(entry, 0x12, 0x02, 0x08, 0x01) // лишнее поле записи
		out = append(out, 0x0a, byte(len(entry)))
		out = append(out, entry...)
	}
	return out
}

func TestCountryRules(t *testing.T) {
	geoip := geoFile("RU", "PRIVATE", "KZ")
	geosite := geoFile("CATEGORY-RU", "GOOGLE")
	d, ips, err := CountryRules("ru", geoip, geosite)
	if err != nil || strings.Join(d, ",") != "domain:ru,geosite:category-ru" || strings.Join(ips, ",") != "geoip:ru" {
		t.Fatalf("ru: %v %v %v", d, ips, err)
	}
	d, _, err = CountryRules("kz", geoip, geosite)
	if err != nil || strings.Join(d, ",") != "domain:kz" {
		t.Fatalf("kz без категории: %v %v", d, err)
	}
	if _, _, err := CountryRules("de", geoip, geosite); err == nil {
		t.Fatal("страны нет в списках — ошибка")
	}
	if _, _, err := CountryRules("RUS", geoip, geosite); err == nil {
		t.Fatal("неверный код — ошибка")
	}
	if _, err := GeoCodes([]byte{0x0a, 0x50}); err == nil {
		t.Fatal("обрезанный файл — ошибка")
	}
}
