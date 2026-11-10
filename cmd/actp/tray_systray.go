//go:build tray

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"runtime"
	"time"

	"fyne.io/systray"

	"github.com/varops/actp/internal/autostart"
)

// runTray shows a menu bar icon. systray.Run must own the main thread (macOS),
// so the server runs in the background.
func runTray(ctx context.Context, cfgPath string, open bool) error {
	ready := make(chan *host, 1)
	done := make(chan error, 1)
	go func() {
		done <- runHost(ctx, hostOptions{configPath: cfgPath, dashboard: true, onReady: func(h *host) { ready <- h }})
		systray.Quit()
	}()
	var h *host
	select {
	case h = <-ready:
	case err := <-done:
		return err
	}
	systray.Run(func() { trayReady(h, open) }, func() { h.Quit() })
	return <-done
}

func trayReady(h *host, open bool) {
	if runtime.GOOS == "darwin" {
		// A template icon follows the menu bar's light or dark look.
		systray.SetTemplateIcon(trayIcon(), trayIcon())
	} else {
		systray.SetIcon(trayIcon())
	}
	systray.SetTooltip("actp")
	status := systray.AddMenuItem("Starting…", "")
	status.Disable()
	tunnelItem := systray.AddMenuItem("", "")
	tunnelItem.Disable()
	tunnelItem.Hide()
	systray.AddSeparator()
	openItem := systray.AddMenuItem("Open dashboard", "Agents, connections, clients and remotes")
	loginItem := systray.AddMenuItemCheckbox("Start at login", "Start actp when you log in", autostart.Enabled())
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit actp", "Stop the server; running turns get 30 s to finish")

	if open {
		_ = openBrowser(h.dash.URL())
	}
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			status.SetTitle(statusLine(h))
			if srv := h.Server(); srv != nil && srv.PublicURL() != "" {
				tunnelItem.SetTitle("Tunnel: " + srv.PublicURL())
				tunnelItem.Show()
			}
			select {
			case <-openItem.ClickedCh:
				_ = openBrowser(h.dash.NewLink())
			case <-loginItem.ClickedCh:
				if loginItem.Checked() {
					_ = autostart.Disable()
				} else if exe, err := os.Executable(); err == nil {
					_ = autostart.Enable(exe)
				}
				if autostart.Enabled() {
					loginItem.Check()
				} else {
					loginItem.Uncheck()
				}
			case <-quit.ClickedCh:
				h.Quit()
				return
			case <-t.C:
			}
		}
	}()
}

func statusLine(h *host) string {
	srv := h.Server()
	if srv == nil {
		return "Not sharing agents (set up in the dashboard)"
	}
	links, working := 0, 0
	for _, l := range srv.Links() {
		links++
		if l.Running {
			working++
		}
	}
	return fmt.Sprintf("%d agents · %d connections · %d working", len(srv.Agents()), links, working)
}

// trayIcon draws a small two-node glyph: PNG on macOS and Linux, ICO on Windows.
func trayIcon() []byte {
	const size = 32
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	ink := color.NRGBA{0, 0, 0, 255}
	if runtime.GOOS == "windows" {
		ink = color.NRGBA{47, 91, 211, 255}
	}
	disc := func(cx, cy, r int) {
		for y := -r; y <= r; y++ {
			for x := -r; x <= r; x++ {
				if x*x+y*y <= r*r {
					img.Set(cx+x, cy+y, ink)
				}
			}
		}
	}
	disc(8, 16, 6)
	disc(24, 16, 6)
	for x := 8; x <= 24; x++ {
		for y := 14; y <= 18; y++ {
			img.Set(x, y, ink)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	if runtime.GOOS != "windows" {
		return buf.Bytes()
	}
	// An ICO file may hold a PNG image directly.
	var ico bytes.Buffer
	_ = binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1})
	ico.Write([]byte{size, size, 0, 0})
	_ = binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})
	_ = binary.Write(&ico, binary.LittleEndian, []uint32{uint32(buf.Len()), 22})
	ico.Write(buf.Bytes())
	return ico.Bytes()
}
