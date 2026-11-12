// Package store хранит список серверов на этом компьютере. Секреты шифруются через DPAPI.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Server — сохранённый сервер. Поля секретов зашифрованы и в интерфейс не передаются.
type Server struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	AuthType     string `json:"authType"`
	KeyPath      string `json:"keyPath"`
	Fingerprint  string `json:"fingerprint"`
	Password     string `json:"password,omitempty"`
	Passphrase   string `json:"passphrase,omitempty"`
	SudoPassword string `json:"sudoPassword,omitempty"`
}

// Store — файл servers.json.
type Store struct {
	mu   sync.Mutex
	path string
}

// Каталог данных в %APPDATA%. До переименования приложения он назывался vless-bridge.
const (
	dirName    = "pereprava"
	oldDirName = "vless-bridge"
)

// defaultDir возвращает каталог данных внутри base и переносит туда старый, если новый ещё не создан.
// Секреты зашифрованы DPAPI ключом пользователя, а не путём файла, поэтому перенос их не ломает.
func defaultDir(base string) string {
	dir := filepath.Join(base, dirName)
	old := filepath.Join(base, oldDirName)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(old); err == nil {
			_ = os.Rename(old, dir)
		}
	}
	return dir
}

// Open использует каталог dir или, если он пуст, %APPDATA%\pereprava.
func Open(dir string) (*Store, error) {
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = defaultDir(base)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "servers.json")}, nil
}

// Dir — каталог данных приложения.
func (s *Store) Dir() string { return filepath.Dir(s.path) }

func (s *Store) read() ([]Server, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Server{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Server
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("файл %s повреждён: %w", s.path, err)
	}
	return list, nil
}

func (s *Store) write(list []Server) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// List возвращает все серверы с зашифрованными секретами.
func (s *Store) List() ([]Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

// Get возвращает сервер по ID.
func (s *Store) Get(id string) (Server, error) {
	list, err := s.List()
	if err != nil {
		return Server{}, err
	}
	for _, srv := range list {
		if srv.ID == id {
			return srv, nil
		}
	}
	return Server{}, fmt.Errorf("сервер %s не найден", id)
}

// Put добавляет сервер или заменяет его по ID.
func (s *Store) Put(srv Server) (Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.read()
	if err != nil {
		return Server{}, err
	}
	if srv.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return Server{}, err
		}
		srv.ID = hex.EncodeToString(b)
		list = append(list, srv)
	} else {
		found := false
		for i := range list {
			if list[i].ID == srv.ID {
				list[i], found = srv, true
			}
		}
		if !found {
			return Server{}, fmt.Errorf("сервер %s не найден", srv.ID)
		}
	}
	return srv, s.write(list)
}

// Delete удаляет сервер из списка. На самом VPS ничего не меняется.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.read()
	if err != nil {
		return err
	}
	out := make([]Server, 0, len(list))
	for _, srv := range list {
		if srv.ID != id {
			out = append(out, srv)
		}
	}
	return s.write(out)
}
