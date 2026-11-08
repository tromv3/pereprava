package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

type testServer struct {
	addr string
	port int
	fp   string
	mu   sync.Mutex
	cmds []string
	in   map[string]string
}

// startServer поднимает SSH-сервер, который вместо запуска команд отвечает по их тексту.
func startServer(t *testing.T, clientKey ssh.PublicKey) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == "right" {
				return nil, nil
			}
			return nil, errors.New("нет")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if clientKey != nil && string(k.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("нет")
		},
	}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &testServer{addr: "127.0.0.1", port: l.Addr().(*net.TCPAddr).Port,
		fp: ssh.FingerprintSHA256(signer.PublicKey()), in: map[string]string{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.handle(c, cfg)
		}
	}()
	return s
}

func (s *testServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range chReqs {
				if r.Type != "exec" {
					r.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(r.Payload[:4])
				cmd := string(r.Payload[4 : 4+n])
				r.Reply(true, nil)
				s.mu.Lock()
				s.cmds = append(s.cmds, cmd)
				s.mu.Unlock()
				code := uint32(0)
				switch {
				case strings.Contains(cmd, "fail"):
					io.WriteString(ch.Stderr(), "плохо\n")
					code = 3
				case strings.Contains(cmd, "cat >") || strings.HasPrefix(cmd, "sudo -S"):
					data, _ := io.ReadAll(ch)
					s.mu.Lock()
					s.in[cmd] = string(data)
					s.mu.Unlock()
				default:
					io.WriteString(ch, "строка 1\nстрока 2\n")
					io.WriteString(ch.Stderr(), "журнал\n")
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				return
			}
		}()
	}
}

func cfgFor(s *testServer) Config {
	return Config{Host: s.addr, Port: s.port, User: "root", AuthType: "password", Password: "right", Fingerprint: s.fp}
}

func TestHostKey(t *testing.T) {
	s := startServer(t, nil)
	cfg := cfgFor(s)
	cfg.Fingerprint = ""
	_, err := Dial(cfg)
	var unknown *UnknownHostError
	if !errors.As(err, &unknown) || unknown.Fingerprint != s.fp || unknown.KeyType != "ssh-ed25519" {
		t.Fatalf("ожидался неизвестный хост: %v", err)
	}
	cfg.Fingerprint = "SHA256:другой"
	_, err = Dial(cfg)
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) || changed.Fingerprint != s.fp {
		t.Fatalf("ожидалась смена ключа: %v", err)
	}
	c, err := Dial(cfgFor(s))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close() // повторное закрытие не должно падать
}

func TestAuth(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	s := startServer(t, sshPub)

	bad := cfgFor(s)
	bad.Password = "wrong"
	if _, err := Dial(bad); err == nil {
		t.Fatal("неверный пароль должен дать ошибку")
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id")
	os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600)
	kc := cfgFor(s)
	kc.AuthType, kc.KeyPath, kc.Password = "key", keyFile, ""
	c, err := Dial(kc)
	if err != nil {
		t.Fatalf("вход по ключу: %v", err)
	}
	c.Close()

	kc.KeyPath = filepath.Join(t.TempDir(), "нет")
	if _, err := Dial(kc); err == nil {
		t.Fatal("нет файла ключа — должна быть ошибка")
	}
	if _, err := Dial(Config{AuthType: "x"}); err == nil {
		t.Fatal("неизвестный способ входа — должна быть ошибка")
	}
}

func TestRunUploadSudo(t *testing.T) {
	s := startServer(t, nil)
	c, err := Dial(cfgFor(s))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if !c.Alive() {
		t.Fatal("соединение должно быть живым")
	}

	var lines []string
	r, err := c.Run(ctx, "hello", true, func(l string) { lines = append(lines, l) })
	if err != nil || r.Code != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Stdout != "строка 1\nстрока 2\n" || r.Stderr != "журнал\n" || len(lines) != 3 {
		t.Fatalf("вывод: %+v, строки: %q", r, lines)
	}
	if s.cmds[len(s.cmds)-1] != "hello" {
		t.Fatalf("root не должен получать sudo: %q", s.cmds)
	}

	lines = nil
	r, err = c.RunResult(ctx, "hello", true, func(l string) { lines = append(lines, l) })
	if err != nil || r.Stdout != "строка 1\nстрока 2\n" || len(lines) != 1 || lines[0] != "журнал" {
		t.Fatalf("в журнал должен идти только stderr: %+v, %q, %v", r, lines, err)
	}

	r, err = c.Run(ctx, "fail", true, nil)
	if err != nil || r.Code != 3 || r.Stderr != "плохо\n" {
		t.Fatalf("код выхода: %+v %v", r, err)
	}

	if err := c.Upload(ctx, "/tmp/it's", []byte("данные"), "700"); err != nil {
		t.Fatal(err)
	}
	want := `cat > '/tmp/it'\''s' && chmod 700 '/tmp/it'\''s'`
	if s.in[want] != "данные" {
		t.Fatalf("upload: %q", s.in)
	}

	// Не root: пароль sudo идёт через stdin и не попадает в текст команды.
	cfg := cfgFor(s)
	cfg.User, cfg.SudoPassword = "vps", "s3cret"
	su, err := Dial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer su.Close()
	if _, err := su.Run(ctx, "do it", true, nil); err != nil {
		t.Fatal(err)
	}
	cmd := s.cmds[len(s.cmds)-1]
	if cmd != "sudo -S -p '' sh -c 'do it'" || strings.Contains(cmd, "s3cret") {
		t.Fatalf("sudo: %q", cmd)
	}
	if s.in[cmd] != "s3cret\n" {
		t.Fatalf("stdin sudo: %q", s.in[cmd])
	}
	if _, err := su.Run(ctx, "plain", false, nil); err != nil {
		t.Fatal(err)
	}
	if s.cmds[len(s.cmds)-1] != "plain" {
		t.Fatalf("без root sudo не нужен: %q", s.cmds[len(s.cmds)-1])
	}

	cfg.SudoPassword = ""
	ns, err := Dial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.Run(ctx, "x", true, nil)
	if s.cmds[len(s.cmds)-1] != "sudo -n sh -c 'x'" {
		t.Fatalf("sudo -n: %q", s.cmds[len(s.cmds)-1])
	}
	_ = strconv.Itoa
}

func TestDialRefused(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if _, err := Dial(Config{Host: "127.0.0.1", Port: port, User: "root", AuthType: "password", Password: "x"}); err == nil {
		t.Fatal("закрытый порт должен дать ошибку")
	}
}
