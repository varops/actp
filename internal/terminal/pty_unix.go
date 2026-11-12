//go:build !windows

package terminal

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// Supported reports whether this platform has a terminal.
const Supported = true

type shell struct {
	*os.File
	cmd  *exec.Cmd
	name string
	done chan struct{}
}

func start(opts Options) (*shell, error) {
	path := opts.Shell
	if path == "" {
		path = os.Getenv("SHELL")
	}
	if path == "" {
		path = "/bin/sh"
		if _, err := os.Stat("/bin/bash"); err == nil {
			path = "/bin/bash"
		}
	}
	cmd := exec.Command(path, "-l")
	cmd.Dir = opts.Dir
	cmd.Env = append(append([]string{}, opts.Env...), "TERM=xterm-256color", "COLORTERM=truecolor")
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 100, Rows: 30})
	if err != nil {
		return nil, err
	}
	s := &shell{File: f, cmd: cmd, name: filepath.Base(path), done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(s.done) }()
	return s, nil
}

func (s *shell) resize(cols, rows uint16) {
	_ = pty.Setsize(s.File, &pty.Winsize{Cols: cols, Rows: rows})
}

// close hangs up the shell's session (it leads its own) and reaps it.
func (s *shell) close() {
	pid := s.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGHUP)
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-s.done
	}
	_ = s.File.Close()
}
