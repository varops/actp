package dashboard

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	maxFailures  = 5 // per failureWindow, for all clients together
	failureDelay = 500 * time.Millisecond
)

var failureWindow = time.Minute

// logins is password mode: a login form and sessions instead of one-time links.
type logins struct {
	hash     [32]byte
	mu       sync.Mutex
	sessions map[string]time.Time // cookie value → expiry
	failures []time.Time
}

func newLogins(password string) *logins {
	return &logins{hash: sha256.Sum256([]byte(password)), sessions: map[string]time.Time{}}
}

var errTooMany = errors.New("too many wrong passwords: wait a minute and try again")

// check returns a new session for the right password.
func (l *logins) check(password string) (string, error) {
	l.mu.Lock()
	now := time.Now()
	kept := l.failures[:0]
	for _, t := range l.failures {
		if now.Sub(t) < failureWindow {
			kept = append(kept, t)
		}
	}
	l.failures = kept
	if len(l.failures) >= maxFailures {
		l.mu.Unlock()
		return "", errTooMany
	}
	l.mu.Unlock()
	got := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(got[:], l.hash[:]) != 1 {
		time.Sleep(failureDelay)
		l.mu.Lock()
		l.failures = append(l.failures, time.Now())
		l.mu.Unlock()
		return "", errors.New("wrong password")
	}
	s := randomHex()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, exp := range l.sessions {
		if now.After(exp) {
			delete(l.sessions, k)
		}
	}
	l.sessions[s] = now.Add(sessionTTL)
	return s, nil
}

func (l *logins) valid(session string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	exp, ok := l.sessions[session]
	return ok && time.Now().Before(exp)
}

func (l *logins) end(session string) {
	l.mu.Lock()
	delete(l.sessions, session)
	l.mu.Unlock()
}

// open paths need no session.
func open(r *http.Request) bool {
	return r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/")
}

// guard lets only the dashboard's own browser in. Without a password: the
// right Host (against DNS rebinding) and the cookie from the one-time link.
// With a password: a session from the login form. Writes must also come from
// the page itself (same Origin and a custom header).
func (d *Dashboard) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		if d.login == nil && r.Host != d.addr {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				http.Error(w, "cross-site request", http.StatusForbidden)
				return
			}
			if r.Header.Get("X-Actp-Dashboard") != "1" {
				http.Error(w, "missing X-Actp-Dashboard header", http.StatusForbidden)
				return
			}
		}
		if open(r) {
			next.ServeHTTP(w, r)
			return
		}
		if d.login != nil {
			c, err := r.Cookie(cookieName)
			if err != nil || !d.login.valid(c.Value) {
				if r.URL.Path == "/" {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
				writeErr(w, http.StatusUnauthorized, errors.New("log in first"))
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" && r.URL.Query().Has("t") {
			d.mu.Lock()
			ok := !d.used && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(d.once)) == 1
			if ok {
				d.used = true
			}
			d.mu.Unlock()
			if !ok {
				http.Error(w, "this link was already used: open the dashboard again from the tray", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: d.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(d.session)) != 1 {
			http.Error(w, "open the dashboard from the tray or the link actp printed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin accepts a request without Origin (not sent by browsers for
// same-origin GETs) or with one naming this host.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// secure reports whether the browser reached us over HTTPS, maybe through a proxy.
func secure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (d *Dashboard) loginPage(w http.ResponseWriter, r *http.Request) {
	if d.login == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(loginHTML)
}

func (d *Dashboard) doLogin(w http.ResponseWriter, r *http.Request) {
	if d.login == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	who := r.RemoteAddr
	if host, _, err := net.SplitHostPort(who); err == nil {
		who = host
	}
	s, err := d.login.check(req.Password)
	if err != nil {
		d.opts.Logger.Warn("dashboard login failed", "from", who)
		status := http.StatusUnauthorized
		if errors.Is(err, errTooMany) {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, err)
		return
	}
	d.opts.Logger.Info("dashboard login", "from", who)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s, Path: "/", HttpOnly: true, Secure: secure(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Dashboard) logout(w http.ResponseWriter, r *http.Request) {
	if d.login != nil {
		if c, err := r.Cookie(cookieName); err == nil {
			d.login.end(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
