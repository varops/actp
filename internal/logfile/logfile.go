// Package logfile opens append-only log files with a simple size cap: a file
// over the cap is moved to <name>.1 when it is opened.
package logfile

import (
	"io"
	"os"
	"path/filepath"
)

// MaxSize is the size at which a log file is rotated on open.
const MaxSize = 10 << 20

// Open opens dir/name for appending, readable only by this user.
func Open(dir, name string) (io.WriteCloser, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	if info, err := os.Stat(path); err == nil && info.Size() > MaxSize {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
