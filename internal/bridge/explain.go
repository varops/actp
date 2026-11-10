package bridge

import (
	"net/url"
	"strings"
)

// NoServerHint explains a URL where no actp server answers. Quick tunnel
// addresses change whenever the server restarts, which is the usual cause.
func NoServerHint(base string) string {
	msg := "no actp server answers at " + base
	if u, err := url.Parse(base); err == nil && strings.HasSuffix(u.Hostname(), ".trycloudflare.com") {
		msg += ". Quick tunnel addresses change every time the server restarts: copy the current URL from the server's dashboard and update this remote"
	} else {
		msg += ". Check the URL, and that the server is running"
	}
	return msg
}
