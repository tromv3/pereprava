package client

import (
	"errors"
	"regexp"
	"strings"
)

var reCountry = regexp.MustCompile(`^[a-z]{2}$`)

// CountryRules — что пускать напрямую для страны cc при данных списках: domain:cc всегда,
// geosite:category-cc и geoip:cc — если они есть в списках. Ошибка — если адресов страны в списках нет.
func CountryRules(cc string, geoip, geosite []byte) (domains, ips []string, err error) {
	if !reCountry.MatchString(cc) {
		return nil, nil, errors.New("неверный код страны")
	}
	ipCodes, err := GeoCodes(geoip)
	if err != nil {
		return nil, nil, err
	}
	if !ipCodes[cc] {
		return nil, nil, errors.New("в списках адресов нет страны " + strings.ToUpper(cc))
	}
	domains = []string{"domain:" + cc}
	if siteCodes, err := GeoCodes(geosite); err == nil && siteCodes["category-"+cc] {
		domains = append(domains, "geosite:category-"+cc)
	}
	return domains, []string{"geoip:" + cc}, nil
}

// GeoCodes возвращает имена записей geoip.dat или geosite.dat (в нижнем регистре).
// Файл — protobuf: повторяющееся поле 1 с записями, у записи поле 1 — имя.
func GeoCodes(data []byte) (map[string]bool, error) {
	out := map[string]bool{}
	for len(data) > 0 {
		key, n := uvarint(data)
		if n <= 0 {
			return nil, errors.New("список повреждён")
		}
		data = data[n:]
		if key&7 != 2 { // ожидаем только поля с длиной
			return nil, errors.New("список повреждён")
		}
		size, n := uvarint(data)
		if n <= 0 || uint64(len(data)-n) < size {
			return nil, errors.New("список повреждён")
		}
		entry := data[n : n+int(size)]
		data = data[n+int(size):]
		if key>>3 != 1 {
			continue
		}
		if k, n := uvarint(entry); n > 0 && k == 1<<3|2 {
			if l, m := uvarint(entry[n:]); m > 0 && uint64(len(entry)-n-m) >= l {
				out[strings.ToLower(string(entry[n+m:n+m+int(l)]))] = true
			}
		}
	}
	return out, nil
}

func uvarint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}
