package client

import (
	"encoding/json"
	"errors"
)

// Options — как работает клиент.
type Options struct {
	SocksPort int  // локальный SOCKS5 на 127.0.0.1
	HTTPPort  int  // локальный HTTP-прокси на 127.0.0.1, его ставит системный прокси
	TUN       bool // весь трафик компьютера через виртуальный адаптер (нужны права администратора)
	// Сайты и адреса, которые идут напрямую, мимо сервера (например, сайты своей страны).
	DirectDomains []string
	DirectIPs     []string
}

// TunName — имя адаптера Wintun.
const TunName = "Pereprava"

// Config собирает конфиг локального Xray.
func Config(l Link, o Options) ([]byte, error) {
	if l.UUID == "" {
		return nil, errors.New("нет ссылки на сервер")
	}
	user := map[string]any{"id": l.UUID, "encryption": "none"}
	if l.Flow != "" {
		user["flow"] = l.Flow
	}
	proxy := map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": l.Host, "port": l.Port, "users": []any{user},
		}}},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"serverName": l.SNI, "publicKey": l.PBK, "shortId": l.SID, "fingerprint": l.FP,
			},
		},
	}
	inbounds := []any{
		map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": o.SocksPort, "protocol": "socks",
			"settings": map[string]any{"udp": true},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}},
		map[string]any{"tag": "http", "listen": "127.0.0.1", "port": o.HTTPPort, "protocol": "http",
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}},
	}
	var rules []any
	if o.TUN {
		inbounds = append(inbounds, map[string]any{
			"tag": "tun", "protocol": "tun",
			"settings": map[string]any{
				"name": TunName, "mtu": 1500,
				"gateway": []string{"172.19.0.1/30"},
				"dns":     []string{"1.1.1.1", "8.8.8.8"},
				// Весь IPv4 в адаптер; исходящие Xray привязаны к физическому адаптеру, поэтому петли нет.
				"autoSystemRoutingTable": []string{"0.0.0.0/0"},
				"autoOutboundsInterface": "auto",
				"autoSystemWfpBlockLeak": []string{"dns", "misconfigtun"},
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		})
		// DNS из адаптера отвечает Xray: запросы уходят через сервер.
		rules = append(rules, map[string]any{"inboundTag": []string{"tun"}, "port": "53", "outboundTag": "dns"})
	}
	rules = append(rules,
		map[string]any{"protocol": []string{"bittorrent"}, "outboundTag": "direct"},
		map[string]any{"ip": []string{"geoip:private"}, "outboundTag": "direct"},
	)
	if len(o.DirectDomains) > 0 {
		rules = append(rules, map[string]any{"domain": o.DirectDomains, "outboundTag": "direct"})
	}
	if len(o.DirectIPs) > 0 {
		rules = append(rules, map[string]any{"ip": o.DirectIPs, "outboundTag": "direct"})
	}
	outbounds := []any{proxy,
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole"},
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	if o.TUN {
		cfg["outbounds"] = append(outbounds, map[string]any{"tag": "dns", "protocol": "dns"})
		cfg["dns"] = map[string]any{"servers": []string{"1.1.1.1", "8.8.8.8"}, "queryStrategy": "UseIPv4"}
	}
	return json.MarshalIndent(cfg, "", "  ")
}
