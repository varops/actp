// Package jsonrpc reads, writes and inspects newline-delimited JSON-RPC 2.0
// messages without decoding fields actp does not need, so unknown fields survive.
package jsonrpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Standard and ACP error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeServerError    = -32000
	CodeCancelled      = -32800
)

// Kind is the shape of a message.
type Kind int

const (
	KindRequest Kind = iota + 1
	KindNotification
	KindResponse
)

// Message is one JSON-RPC message with its header fields peeked.
type Message struct {
	Raw    json.RawMessage
	ID     json.RawMessage // nil when absent
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  *Error
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%d)", e.Message, e.Code) }

type header struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *Error          `json:"error"`
}

// Parse peeks a raw message. The raw bytes are kept as is.
func Parse(raw []byte) (*Message, error) {
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	m := &Message{Raw: compact(raw), Method: h.Method, Params: h.Params, Result: h.Result, Error: h.Error}
	if h.ID != nil && !bytes.Equal(h.ID, []byte("null")) {
		m.ID = compact(h.ID)
	} else if h.ID != nil && h.Method == "" {
		m.ID = json.RawMessage("null")
	}
	if m.Method == "" && m.ID == nil {
		return nil, errors.New("not a JSON-RPC message: no method and no id")
	}
	return m, nil
}

func compact(raw []byte) json.RawMessage {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return append(json.RawMessage(nil), raw...)
	}
	return buf.Bytes()
}

// Kind reports whether the message is a request, notification or response.
func (m *Message) Kind() Kind {
	switch {
	case m.Method != "" && m.ID != nil:
		return KindRequest
	case m.Method != "":
		return KindNotification
	default:
		return KindResponse
	}
}

// IDKey is a map key for the message id.
func (m *Message) IDKey() string { return string(m.ID) }

// NewRequest builds a request.
func NewRequest(id json.RawMessage, method string, params any) (*Message, error) {
	return build(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

// NewNotification builds a notification.
func NewNotification(method string, params any) (*Message, error) {
	return build(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// NewResult builds a success response.
func NewResult(id json.RawMessage, result any) *Message {
	m, err := build(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		panic(err)
	}
	return m
}

// NewError builds an error response.
func NewError(id json.RawMessage, code int, message string, data any) *Message {
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	m, err := build(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	if err != nil {
		panic(err)
	}
	return m
}

func build(v map[string]any) (*Message, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// WithParams returns a copy of the message with new params.
func (m *Message) WithParams(params any) (*Message, error) {
	return m.withField("params", params)
}

// WithResult returns a copy of the message with a new result.
func (m *Message) WithResult(result any) (*Message, error) {
	return m.withField("result", result)
}

func (m *Message) withField(key string, value any) (*Message, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(m.Raw, &obj); err != nil {
		return nil, err
	}
	enc, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	obj[key] = enc
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Reader reads one message per line.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10)}
}

// Read returns the next non-empty line. Lines that are not JSON-RPC return an
// error together with the raw line, so callers can log and skip them.
func (r *Reader) Read() (*Message, []byte, error) {
	for {
		line, err := r.r.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			m, perr := Parse(trimmed)
			if perr != nil {
				return nil, trimmed, fmt.Errorf("invalid message: %w", perr)
			}
			return m, trimmed, nil
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

// Writer writes one message per line. Safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Write(m *Message) error {
	return w.WriteRaw(m.Raw)
}

// WriteRaw writes an already compact JSON message.
func (w *Writer) WriteRaw(raw []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	buf := make([]byte, 0, len(raw)+1)
	buf = append(buf, raw...)
	buf = append(buf, '\n')
	_, err := w.w.Write(buf)
	return err
}
