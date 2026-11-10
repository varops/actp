package tunnel

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/varops/actp/internal/config"
)

// CloudflaredVersion is the cloudflared release actp downloads. The hashes below
// are pinned in actp itself, never fetched along with the file.
const CloudflaredVersion = "2026.10.7"

type cloudflaredAsset struct {
	file   string
	sha256 string
	tgz    bool // macOS releases are a .tgz with the binary inside
}

var cloudflaredAssets = map[string]cloudflaredAsset{
	"linux/amd64":   {file: "cloudflared-linux-amd64", sha256: "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872"},
	"linux/arm64":   {file: "cloudflared-linux-arm64", sha256: "3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775"},
	"darwin/amd64":  {file: "cloudflared-darwin-amd64.tgz", sha256: "02f3edfd87684dd5b705607688e4eb4b323f6e777b81e7b3a85af556aa356848", tgz: true},
	"darwin/arm64":  {file: "cloudflared-darwin-arm64.tgz", sha256: "3586ccf397e98e5f437e60e7c307ca6ac463e110580503af8bb8e6f9ebf831bd", tgz: true},
	"windows/amd64": {file: "cloudflared-windows-amd64.exe", sha256: "2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343"},
}

// downloadBase is where release files come from (a variable for tests).
var downloadBase = "https://github.com/cloudflare/cloudflared/releases/download/" + CloudflaredVersion + "/"

// maxDownload bounds the download size.
const maxDownload = 200 << 20

// CanDownload reports whether actp has a pinned cloudflared for this platform.
func CanDownload() bool {
	_, ok := cloudflaredAssets[runtime.GOOS+"/"+runtime.GOARCH]
	return ok
}

// LocalBinary is where Download puts cloudflared.
func LocalBinary() string {
	name := "cloudflared"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(config.Dir(), "bin", name)
}

// Download fetches the pinned cloudflared for this platform into ~/.actp/bin,
// checks its SHA-256, and returns its path.
func Download(ctx context.Context) (string, error) {
	return download(ctx, runtime.GOOS+"/"+runtime.GOARCH, LocalBinary())
}

func download(ctx context.Context, platform, dest string) (string, error) {
	asset, ok := cloudflaredAssets[platform]
	if !ok {
		return "", fmt.Errorf("no pinned cloudflared for %s; install it yourself and put it on PATH", platform)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadBase+asset.file, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: HTTP %d", asset.file, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".cloudflared-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		tmp.Close()
		return "", err
	}
	if n > maxDownload {
		tmp.Close()
		return "", errors.New("download is larger than expected")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != asset.sha256 {
		tmp.Close()
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset.file, got, asset.sha256)
	}
	if asset.tgz {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			return "", err
		}
		extracted, err := os.CreateTemp(filepath.Dir(dest), ".cloudflared-bin-*")
		if err != nil {
			tmp.Close()
			return "", err
		}
		defer os.Remove(extracted.Name())
		err = extractCloudflared(tmp, extracted)
		tmp.Close()
		if cerr := extracted.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", err
		}
		return dest, install(extracted.Name(), dest)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return dest, install(tmp.Name(), dest)
}

func extractCloudflared(src io.Reader, dst io.Writer) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return errors.New("no cloudflared inside the archive")
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == "cloudflared" && hdr.Typeflag == tar.TypeReg {
			_, err := io.Copy(dst, io.LimitReader(tr, maxDownload))
			return err
		}
	}
}

func install(src, dest string) error {
	if err := os.Chmod(src, 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(dest) // Windows cannot rename over an existing file
	}
	return os.Rename(src, dest)
}
