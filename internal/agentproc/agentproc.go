// Package agentproc starts and stops ACP agent processes.
package agentproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// StderrTail is how much of an agent's stderr is kept for error messages.
const StderrTail = 8 << 10

// Spec describes how to start an agent.
type Spec struct {
	Command   string
	Args      []string
	Dir       string
	BaseEnv   []string // nil means os.Environ()
	Env       map[string]string
	EnvRemove []string
}

// Process is a running agent.
type Process struct {
	cmd    *exec.Cmd
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	stderr *tail
	done   chan struct{}
	err    error
	once   sync.Once
}

// Start launches the agent in its own process group.
func Start(spec Spec) (*Process, error) {
	env := BuildEnv(spec.BaseEnv, spec.Env, spec.EnvRemove)
	path, err := LookPath(spec.Command, env)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(path, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = env
	setProcessGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p := &Process{cmd: cmd, Stdin: stdin, Stdout: stdout, stderr: &tail{max: StderrTail}, done: make(chan struct{})}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// PID is the agent's process id.
func (p *Process) PID() int { return p.cmd.Process.Pid }

// Done is closed when the process has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// ExitCode is the exit code, or -1 while running or when killed by a signal.
func (p *Process) ExitCode() int {
	select {
	case <-p.done:
		return p.cmd.ProcessState.ExitCode()
	default:
		return -1
	}
}

// Stderr returns the last bytes the agent wrote to stderr.
func (p *Process) Stderr() string { return p.stderr.String() }

// Stop closes stdin, asks the process group to stop, and kills it after grace.
func (p *Process) Stop(grace time.Duration) {
	p.once.Do(func() {
		_ = p.Stdin.Close()
		select {
		case <-p.done:
			return
		case <-time.After(200 * time.Millisecond):
		}
		terminateGroup(p.cmd)
		select {
		case <-p.done:
		case <-time.After(grace):
			killGroup(p.cmd)
			<-p.done
		}
	})
}

// BuildEnv applies removals and additions to a base environment.
func BuildEnv(base []string, add map[string]string, remove []string) []string {
	if base == nil {
		base = os.Environ()
	}
	drop := map[string]bool{}
	for _, k := range remove {
		drop[envKey(k)] = true
	}
	for k := range add {
		drop[envKey(k)] = true
	}
	out := make([]string, 0, len(base)+len(add))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[envKey(k)] {
			out = append(out, kv)
		}
	}
	for k, v := range add {
		out = append(out, k+"="+v)
	}
	return out
}

func envKey(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

// Getenv reads a variable from an environment list.
func Getenv(env []string, key string) string {
	for i := len(env) - 1; i >= 0; i-- {
		k, v, _ := strings.Cut(env[i], "=")
		if envKey(k) == envKey(key) {
			return v
		}
	}
	return ""
}

// LookPath finds a command using the PATH of the given environment, not of actp itself.
func LookPath(command string, env []string) (string, error) {
	if command == "" {
		return "", errors.New("no command")
	}
	if strings.ContainsAny(command, `/\`) {
		if _, err := os.Stat(command); err != nil {
			return "", fmt.Errorf("%s: %w", command, err)
		}
		return command, nil
	}
	exts := []string{""}
	if runtime.GOOS == "windows" {
		exts = strings.Split(strings.ToLower(Getenv(env, "PATHEXT")), ";")
		if len(exts) == 1 && exts[0] == "" {
			exts = []string{".com", ".exe", ".bat", ".cmd"}
		}
	}
	for _, dir := range filepath.SplitList(Getenv(env, "PATH")) {
		if dir == "" {
			continue
		}
		for _, ext := range exts {
			candidate := filepath.Join(dir, command+ext)
			if isExecutable(candidate) {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("%s was not found on the agent PATH", command)
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode()&0o111 != 0
}

// LoginShellEnv returns the environment of the user's login shell, which has
// the PATH agents usually need. Apps started from a desktop or a service
// manager get a minimal PATH otherwise. Falls back to os.Environ().
func LoginShellEnv(ctx context.Context) []string {
	if runtime.GOOS == "windows" {
		return os.Environ()
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-l", "-c", "env -0")
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return os.Environ()
	}
	var env []string
	for _, kv := range strings.Split(string(out), "\x00") {
		if strings.Contains(kv, "=") {
			env = append(env, kv)
		}
	}
	if Getenv(env, "PATH") == "" {
		return os.Environ()
	}
	return env
}

type tail struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append(t.buf[:0:0], t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
