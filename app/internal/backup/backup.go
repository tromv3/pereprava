// Package backup шифрует резервную копию сервера паролем.
//
// Пароль, а не DPAPI: копия должна пригодиться и тогда, когда этого компьютера уже нет.
// Ключ — scrypt(пароль, соль), шифр — AES-256-GCM; заголовок файла входит в проверку
// подлинности, поэтому подмена имени сервера или параметров тоже обнаруживается.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// Format — метка файла копии.
const Format = "pereprava-backup"

// MinPassword — минимальная длина пароля в символах.
const MinPassword = 8

// Параметры scrypt: около 0,1 с на современном компьютере.
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

// Header — открытая часть файла: по ней видно, что за копия, без пароля.
type Header struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Created string `json:"created"`
	Server  string `json:"server"`
	Host    string `json:"host"`
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
}

type file struct {
	Header
	Data []byte `json:"data"`
}

// ErrPassword — неверный пароль или повреждённый файл: GCM их не различает.
var ErrPassword = errors.New("неверный пароль или файл копии повреждён")

func key(password string, h Header) ([]byte, error) {
	return scrypt.Key([]byte(password), h.Salt, h.N, h.R, h.P, 32)
}

func aead(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// additional — заголовок без самих данных, его подлинность проверяет GCM.
func additional(h Header) ([]byte, error) { return json.Marshal(h) }

// Seal шифрует plain паролем и возвращает содержимое файла копии.
func Seal(plain []byte, password, server, host string) ([]byte, error) {
	if utf8.RuneCountInString(password) < MinPassword {
		return nil, fmt.Errorf("пароль должен быть не короче %d символов", MinPassword)
	}
	h := Header{Format: Format, Version: 1, Created: time.Now().UTC().Format(time.RFC3339),
		Server: server, Host: host, N: scryptN, R: scryptR, P: scryptP,
		Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, err := rand.Read(h.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(h.Nonce); err != nil {
		return nil, err
	}
	k, err := key(password, h)
	if err != nil {
		return nil, err
	}
	g, err := aead(k)
	if err != nil {
		return nil, err
	}
	ad, err := additional(h)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(file{Header: h, Data: g.Seal(nil, h.Nonce, plain, ad)}, "", "  ")
}

// Inspect читает открытую часть файла, не расшифровывая данные.
func Inspect(content []byte) (Header, error) {
	var f file
	if err := json.Unmarshal(content, &f); err != nil || f.Format != Format {
		return Header{}, errors.New("это не файл резервной копии «Переправы»")
	}
	if f.Version != 1 {
		return Header{}, fmt.Errorf("копия версии %d, а приложение знает только версию 1", f.Version)
	}
	// Ограничения защищают от файла, который заставит scrypt съесть всю память.
	if f.N < 1<<10 || f.N > 1<<20 || f.R < 1 || f.R > 32 || f.P < 1 || f.P > 16 || len(f.Salt) < 16 || len(f.Nonce) != 12 {
		return Header{}, errors.New("у файла копии недопустимые параметры шифрования")
	}
	return f.Header, nil
}

// Open расшифровывает файл копии.
func Open(content []byte, password string) (Header, []byte, error) {
	h, err := Inspect(content)
	if err != nil {
		return Header{}, nil, err
	}
	var f file
	if err := json.Unmarshal(content, &f); err != nil {
		return Header{}, nil, err
	}
	k, err := key(password, h)
	if err != nil {
		return Header{}, nil, err
	}
	g, err := aead(k)
	if err != nil {
		return Header{}, nil, err
	}
	ad, err := additional(h)
	if err != nil {
		return Header{}, nil, err
	}
	plain, err := g.Open(nil, h.Nonce, f.Data, ad)
	if err != nil {
		return Header{}, nil, ErrPassword
	}
	return h, plain, nil
}
