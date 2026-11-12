//go:build !windows

package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Вне Windows нет DPAPI: секреты шифруются AES-256-GCM ключом из файла secret.key
// в каталоге данных (права 600). Это защищает от случайного показа servers.json,
// но не от того, кто может читать файлы этого пользователя.

var (
	keyMu   sync.Mutex
	keyData []byte
)

// KeyFile — путь к ключу; PEREPRAVA_KEY_FILE задаёт другой (для тестов).
func KeyFile() (string, error) {
	if p := os.Getenv("PEREPRAVA_KEY_FILE"); p != "" {
		return p, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, dirName, "secret.key"), nil
}

func secretKey() ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if keyData != nil {
		return keyData, nil
	}
	path, err := KeyFile()
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("файл ключа %s повреждён", path)
	}
	keyData = key
	return key, nil
}

func gcm() (cipher.AEAD, error) {
	key, err := secretKey()
	if err != nil {
		return nil, fmt.Errorf("нет ключа для секретов: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt шифрует строку ключом этого пользователя.
func Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	g, err := gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// Decrypt расшифровывает строку, полученную от Encrypt.
func Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("секрет повреждён: %w", err)
	}
	g, err := gcm()
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("секрет повреждён")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return "", errors.New("не удалось расшифровать секрет: ключ не тот или файл повреждён")
	}
	return string(plain), nil
}
