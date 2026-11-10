//go:build !tray

package main

import "context"

// runTray without the tray build tag: no menu bar icon, just the server and the
// dashboard page. Also the fallback on desktops without a tray area.
func runTray(ctx context.Context, cfgPath string, open bool) error {
	return runHost(ctx, hostOptions{configPath: cfgPath, dashboard: true, logFile: true, onReady: func(h *host) {
		if open && h.dash != nil {
			if err := openBrowser(h.dash.URL()); err != nil {
				h.log.Warn("could not open the browser; open the dashboard link above yourself", "error", err)
			}
		}
	}})
}
