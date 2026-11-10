package tunnel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serveFiles(t *testing.T, files map[string][]byte) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	old, oldAssets := downloadBase, cloudflaredAssets
	downloadBase = srv.URL + "/"
	t.Cleanup(func() { downloadBase, cloudflaredAssets = old, oldAssets })
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestDownloadVerifiesAndInstalls(t *testing.T) {
	bin := []byte("#!fake cloudflared\n")
	serveFiles(t, map[string][]byte{"cf-plain": bin})
	cloudflaredAssets = map[string]cloudflaredAsset{"x/y": {file: "cf-plain", sha256: sum(bin)}}
	dest := filepath.Join(t.TempDir(), "bin", "cloudflared")
	if _, err := download(context.Background(), "x/y", dest); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, bin) {
		t.Fatalf("installed %q", got)
	}
}

func TestDownloadRejectsAWrongChecksum(t *testing.T) {
	serveFiles(t, map[string][]byte{"cf-plain": []byte("tampered")})
	cloudflaredAssets = map[string]cloudflaredAsset{"x/y": {file: "cf-plain", sha256: sum([]byte("original"))}}
	dest := filepath.Join(t.TempDir(), "cloudflared")
	if _, err := download(context.Background(), "x/y", dest); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a tampered file was installed")
	}
}

func TestDownloadExtractsTgz(t *testing.T) {
	bin := []byte("macos cloudflared")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "cloudflared", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(bin)
	_ = tw.Close()
	_ = gz.Close()
	serveFiles(t, map[string][]byte{"cf.tgz": buf.Bytes()})
	cloudflaredAssets = map[string]cloudflaredAsset{"x/y": {file: "cf.tgz", sha256: sum(buf.Bytes()), tgz: true}}
	dest := filepath.Join(t.TempDir(), "cloudflared")
	if _, err := download(context.Background(), "x/y", dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, bin) {
		t.Fatalf("extracted %q", got)
	}
}

func TestPinnedPlatforms(t *testing.T) {
	for _, p := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"} {
		a, ok := cloudflaredAssets[p]
		if !ok || len(a.sha256) != 64 {
			t.Errorf("%s: %+v", p, a)
		}
	}
}
