// Package client — встроенный клиент: локальный Xray на этом компьютере с прокси для программ
// или (режим TUN) с виртуальным адаптером для всего трафика.
package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Link — разобранная ссылка vless:// с Reality, какие выдаёт сервер.
type Link struct {
	UUID string `json:"uuid"`
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni"`
	PBK  string `json:"pbk"`
	SID  string `json:"sid"`
	FP   string `json:"fp"`
	Flow string `json:"flow"`
	Name string `json:"name"`
}

var (
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reKey  = regexp.MustCompile(`^[A-Za-z0-9_-]{20,64}$`)
	reSID  = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
	reHost = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

// ParseLink разбирает ссылку vless:// с security=reality и type=tcp.
func ParseLink(raw string) (Link, error) {
	var l Link
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" {
		return l, errors.New("это не ссылка vless://")
	}
	q := u.Query()
	if q.Get("security") != "reality" {
		return l, errors.New("поддерживаются только ссылки с Reality (security=reality)")
	}
	if t := q.Get("type"); t != "" && t != "tcp" && t != "raw" {
		return l, fmt.Errorf("транспорт %q не поддерживается: нужен tcp", t)
	}
	l.UUID = u.User.Username()
	l.Host = u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return l, errors.New("в ссылке нет порта сервера")
	}
	l.Port = port
	l.SNI, l.PBK, l.SID, l.FP, l.Flow = q.Get("sni"), q.Get("pbk"), q.Get("sid"), q.Get("fp"), q.Get("flow")
	if l.FP == "" {
		l.FP = "chrome"
	}
	l.Name = u.Fragment
	switch {
	case !reUUID.MatchString(l.UUID):
		return l, errors.New("в ссылке нет UUID пользователя")
	case net.ParseIP(l.Host) == nil && !reHost.MatchString(l.Host):
		return l, errors.New("в ссылке неверный адрес сервера")
	case !reHost.MatchString(l.SNI):
		return l, errors.New("в ссылке нет SNI")
	case !reKey.MatchString(l.PBK):
		return l, errors.New("в ссылке нет ключа Reality (pbk)")
	case !reSID.MatchString(l.SID):
		return l, errors.New("в ссылке неверный sid")
	case l.Flow != "" && l.Flow != "xtls-rprx-vision":
		return l, fmt.Errorf("flow %q не поддерживается", l.Flow)
	}
	return l, nil
}
