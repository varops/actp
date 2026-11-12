package terminal

import "errors"

// Supported reports whether this platform has a terminal.
const Supported = false

type shell struct {
	name string
}

func start(Options) (*shell, error) {
	return nil, errors.New("the dashboard terminal is not available on Windows")
}

func (s *shell) Read([]byte) (int, error)  { return 0, errors.New("no shell") }
func (s *shell) Write([]byte) (int, error) { return 0, errors.New("no shell") }
func (s *shell) resize(uint16, uint16)     {}
func (s *shell) close()                    {}
