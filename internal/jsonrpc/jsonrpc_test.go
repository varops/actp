package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseKinds(t *testing.T) {
	cases := map[string]Kind{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`:        KindRequest,
		`{"jsonrpc":"2.0","method":"session/update","params":{}}`:           KindNotification,
		`{"jsonrpc":"2.0","id":"a","result":{}}`:                            KindResponse,
		`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"x"}}`:    KindResponse,
		`{"jsonrpc":"2.0","id":null,"method":"session/new","params":{}}`:    KindRequest,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`: KindResponse,
	}
	for raw, want := range cases {
		m, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if m.Kind() != want {
			t.Errorf("%s: kind %v, want %v", raw, m.Kind(), want)
		}
	}
	if _, err := Parse([]byte(`{"jsonrpc":"2.0"}`)); err == nil {
		t.Error("expected error for message without method or id")
	}
}

func TestWithParamsKeepsUnknownFields(t *testing.T) {
	m, _ := Parse([]byte(`{"jsonrpc":"2.0","id":7,"method":"x","params":{"a":1},"_meta":{"k":"v"}}`))
	m2, err := m.WithParams(map[string]int{"b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(m2.Raw), `"_meta":{"k":"v"}`) || string(m2.Params) != `{"b":2}` || m2.IDKey() != "7" {
		t.Fatalf("got %s", m2.Raw)
	}
}

func TestReaderWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	_ = w.Write(NewResult(json.RawMessage(`1`), map[string]bool{"ok": true}))
	buf.WriteString("\n   \nnot json\n")
	_ = w.Write(NewError(json.RawMessage(`"x"`), CodeMethodNotFound, "nope", nil))
	r := NewReader(&buf)
	m, _, err := r.Read()
	if err != nil || m.IDKey() != "1" {
		t.Fatalf("first: %v %v", m, err)
	}
	if _, raw, err := r.Read(); err == nil || string(raw) != "not json" {
		t.Fatalf("second: %q %v", raw, err)
	}
	m, _, err = r.Read()
	if err != nil || m.Error == nil || m.Error.Code != CodeMethodNotFound {
		t.Fatalf("third: %v %v", m, err)
	}
}

func TestCheckEnvelopeRefusesAmbiguousKeys(t *testing.T) {
	ok := []string{
		`{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/","Cwd":"x"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{},"_meta":{"id":1}}`,
		`[1,2]`,
		`not json`,
	}
	for _, raw := range ok {
		if err := CheckEnvelope([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	refused := []struct {
		raw     string
		id      string
		request bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"session/new","Method":"session/prompt","params":{}}`, "1", true},
		{`{"jsonrpc":"2.0","id":7,"Id":null,"method":"session/new","params":{}}`, "7", true},
		{`{"jsonrpc":"2.0","id":1,"method":"x","Params":{}}`, "1", true},
		{`{"jsonrpc":"2.0","ID":1,"method":"x"}`, "", true},
		{`{"JSONRPC":"2.0","id":1,"method":"x"}`, "1", true},
		{`{"jsonrpc":"2.0","id":1,"Result":{}}`, "1", false},
		{`{"jsonrpc":"2.0","id":1,"ERROR":{}}`, "1", false},
		{`{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}`, "", true},
		{`{"jsonrpc":"2.0","id":1,"method":"x","method":"y"}`, "1", true},
		{`{"jsonrpc":"2.0","id":1,"method":"x","params":{},"params":{}}`, "1", true},
		{`{"jsonrpc":"2.0","id":1,"method":"x","\u0050arams":{}}`, "1", true},
		{`{"jsonrpc":"2.0","id":1,"method":"x","paramſ":{}}`, "1", true},
	}
	for _, c := range refused {
		err := CheckEnvelope([]byte(c.raw))
		var a *Ambiguous
		if !errors.As(err, &a) {
			t.Errorf("%s: not refused", c.raw)
			continue
		}
		if string(a.ID) != c.id || a.Request != c.request {
			t.Errorf("%s: id %q request %v", c.raw, a.ID, a.Request)
		}
	}
}
