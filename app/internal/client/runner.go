package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner запускает локальный Xray и держит последние строки его журнала.
type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{}
	exitErr error
	lines   []string
	stopped bool
	OnExit  func(err error) // Xray завершился сам, а не по Stop
}

const maxLines = 200

// Running сообщает, работает ли Xray.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

// Log возвращает последние строки журнала Xray.
func (r *Runner) Log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *Runner) add(line string) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > maxLines {
		r.lines = r.lines[len(r.lines)-maxLines:]
	}
	r.mu.Unlock()
}

// Start запускает xray run -c config из каталога dir (там же geoip.dat и geosite.dat)
// и ждёт, пока он начнёт слушать waitPort на 127.0.0.1.
func (r *Runner) Start(xray, config, dir string, waitPort int) error {
	r.mu.Lock()
	if r.cmd != nil {
		r.mu.Unlock()
		return errors.New("клиент уже запущен")
	}
	r.lines = nil
	r.stopped = false
	cmd := exec.Command(xray, "run", "-c", config)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dir)
	hideWindow(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("не удалось запустить Xray: %w", err)
	}
	bindToApp(cmd.Process)
	r.cmd = cmd
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()

	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			r.add(sc.Text())
		}
	}()
	go func() {
		err := cmd.Wait()
		pw.Close()
		r.mu.Lock()
		r.cmd = nil
		r.exitErr = err
		stopped := r.stopped
		cb := r.OnExit
		r.mu.Unlock()
		close(done)
		if !stopped && cb != nil {
			cb(err)
		}
	}()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return fmt.Errorf("Xray сразу завершился: %s", r.tail())
		default:
		}
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(waitPort), 300*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	r.Stop()
	return fmt.Errorf("Xray не начал работать за 8 секунд: %s", r.tail())
}

func (r *Runner) tail() string {
	lines := r.Log()
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	if len(lines) == 0 {
		return "журнал пуст"
	}
	return strings.Join(lines, "\n")
}

// Stop останавливает Xray и ждёт его завершения.
func (r *Runner) Stop() {
	r.mu.Lock()
	cmd, done := r.cmd, r.done
	r.stopped = true
	r.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// PortFree проверяет, свободен ли порт на 127.0.0.1.
func PortFree(port int) bool {
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}
