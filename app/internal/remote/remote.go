// Package remote выполняет команды на VPS по SSH.
package remote

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config описывает подключение к серверу.
type Config struct {
	Host         string
	Port         int
	User         string
	AuthType     string // password или key
	Password     string
	KeyPath      string
	Passphrase   string
	SudoPassword string
	Fingerprint  string // SHA256 ключа хоста, которому доверяет пользователь
}

// UnknownHostError: сервер ещё не подтверждён пользователем.
type UnknownHostError struct{ Fingerprint, KeyType string }

func (e *UnknownHostError) Error() string { return "неизвестный ключ сервера " + e.Fingerprint }

// HostKeyChangedError: ключ сервера не совпал с сохранённым.
type HostKeyChangedError struct{ Fingerprint, Expected string }

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("ключ сервера изменился: было %s, стало %s", e.Expected, e.Fingerprint)
}

// Client — открытое SSH-соединение.
type Client struct {
	cfg  Config
	conn *ssh.Client
	stop chan struct{}
	once sync.Once
}

// Result — итог выполнения команды.
type Result struct {
	Stdout string
	Stderr string
	Code   int
}

func authMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch cfg.AuthType {
	case "password":
		pw := cfg.Password
		return []ssh.AuthMethod{
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		}, nil
	case "key":
		data, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать ключ: %w", err)
		}
		var signer ssh.Signer
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(data)
		}
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать ключ: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	return nil, fmt.Errorf("неизвестный способ входа %q", cfg.AuthType)
}

// Dial подключается и проверяет ключ хоста.
func Dial(cfg Config) (*Client, error) {
	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}
	var hostErr error
	sshCfg := &ssh.ClientConfig{
		User: cfg.User,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			switch cfg.Fingerprint {
			case fp:
				return nil
			case "":
				hostErr = &UnknownHostError{Fingerprint: fp, KeyType: key.Type()}
			default:
				hostErr = &HostKeyChangedError{Fingerprint: fp, Expected: cfg.Fingerprint}
			}
			return hostErr
		},
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tcp, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("нет соединения с %s: %w", addr, err)
	}
	_ = tcp.SetDeadline(time.Now().Add(30 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(tcp, addr, sshCfg)
	if err != nil {
		tcp.Close()
		if hostErr != nil {
			return nil, hostErr
		}
		return nil, fmt.Errorf("не удалось войти на сервер: %w", err)
	}
	_ = tcp.SetDeadline(time.Time{})

	cl := &Client{cfg: cfg, conn: ssh.NewClient(c, chans, reqs), stop: make(chan struct{})}
	go cl.keepalive()
	return cl, nil
}

func (c *Client) keepalive() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if _, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}
}

// Alive проверяет, живо ли соединение.
func (c *Client) Alive() bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(10 * time.Second):
		return false // оборванное соединение может не ответить никогда
	}
}

// Close закрывает соединение.
func (c *Client) Close() {
	c.once.Do(func() {
		close(c.stop)
		c.conn.Close()
	})
}

// Quote экранирует строку для sh.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrapRoot добавляет sudo, если вход не под root. Пароль идёт через stdin, а не в аргументах.
func (c *Client) wrapRoot(cmd string) (string, io.Reader) {
	if c.cfg.User == "root" {
		return cmd, nil
	}
	if c.cfg.SudoPassword != "" {
		return "sudo -S -p '' sh -c " + Quote(cmd), strings.NewReader(c.cfg.SudoPassword + "\n")
	}
	return "sudo -n sh -c " + Quote(cmd), nil
}

// Run выполняет команду. onLine получает строки stdout и stderr по мере появления.
func (c *Client) Run(ctx context.Context, cmd string, root bool, onLine func(string)) (Result, error) {
	var stdin io.Reader
	if root {
		cmd, stdin = c.wrapRoot(cmd)
	}
	return c.exec(ctx, cmd, stdin, onLine, onLine)
}

// RunResult выполняет команду с результатом в stdout: onLog получает только stderr.
func (c *Client) RunResult(ctx context.Context, cmd string, root bool, onLog func(string)) (Result, error) {
	var stdin io.Reader
	if root {
		cmd, stdin = c.wrapRoot(cmd)
	}
	return c.exec(ctx, cmd, stdin, nil, onLog)
}

// Upload записывает файл от имени пользователя SSH.
func (c *Client) Upload(ctx context.Context, path string, data []byte, mode string) error {
	cmd := "cat > " + Quote(path) + " && chmod " + mode + " " + Quote(path)
	r, err := c.exec(ctx, cmd, bytes.NewReader(data), nil, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return fmt.Errorf("не удалось записать %s: %s", path, strings.TrimSpace(r.Stderr))
	}
	return nil
}

func (c *Client) exec(ctx context.Context, cmd string, stdin io.Reader, onOut, onErr func(string)) (Result, error) {
	s, err := c.conn.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("не удалось открыть сессию: %w", err)
	}
	defer s.Close()
	s.Stdin = stdin
	stdout, err := s.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	stderr, err := s.StderrPipe()
	if err != nil {
		return Result{}, err
	}
	if err := s.Start(cmd); err != nil {
		return Result{}, fmt.Errorf("не удалось запустить команду: %w", err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var outBuf, errBuf bytes.Buffer
	collect := func(r io.Reader, buf *bytes.Buffer, emit func(string)) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			mu.Lock()
			buf.WriteString(line)
			buf.WriteByte('\n')
			if emit != nil {
				emit(line)
			}
			mu.Unlock()
		}
	}
	wg.Add(2)
	go collect(stdout, &outBuf, onOut)
	go collect(stderr, &errBuf, onErr)
	wg.Wait()

	res := Result{}
	err = s.Wait()
	res.Stdout, res.Stderr = outBuf.String(), errBuf.String()
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.Code = exitErr.ExitStatus()
			return res, nil
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		return res, fmt.Errorf("команда прервалась: %w", err)
	}
	return res, nil
}
