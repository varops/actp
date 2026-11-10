package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/varops/actp/internal/tunnel"
)

func cmdTunnel(args []string) error {
	if len(args) != 1 || args[0] != "install" {
		return errors.New("usage: actp tunnel install")
	}
	if path, err := tunnel.FindBinary(nil); err == nil {
		fmt.Println("cloudflared is already installed:", path)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fmt.Fprintf(os.Stderr, "Downloading cloudflared %s (checksum pinned in actp)…\n", tunnel.CloudflaredVersion)
	path, err := tunnel.Download(ctx)
	if err != nil {
		return err
	}
	fmt.Println("Installed", path)
	return nil
}
