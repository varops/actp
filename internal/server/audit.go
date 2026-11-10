package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLog writes one JSON object per line. A nil log drops events.
type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAudit(dir string) (*auditLog, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) event(kind string, fields map[string]any) {
	if a == nil {
		return
	}
	entry := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "event": kind}
	for k, v := range fields {
		entry[k] = v
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.f.Write(append(data, '\n'))
}

func (a *auditLog) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.f.Close()
}
