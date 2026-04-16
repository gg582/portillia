package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const updateCheckTTL = 24 * time.Hour

type updateCache struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

// startUpdateCheck begins a background goroutine that checks for a newer
// release. It returns a buffered channel that will receive the latest version
// string when a newer version exists, or an empty string otherwise. The check
// is skipped when a valid cache entry exists within the TTL.
func startUpdateCheck() <-chan string {
	ch := make(chan string, 1)

	slug := runtime.GOOS + "-" + runtime.GOARCH
	binURL, ok := installer.OfficialAssetURL(slug, false)
	if !ok {
		ch <- ""
		return ch
	}

	go func() {
		ch <- checkForUpdate(binURL)
	}()

	return ch
}

func checkForUpdate(binURL string) string {
	cacheDir, err := updateCacheDir()
	if err != nil {
		return ""
	}
	cachePath := filepath.Join(cacheDir, "update_check.json")

	// Try reading the cache first.
	if cached, err := readUpdateCache(cachePath); err == nil {
		if time.Since(cached.CheckedAt) < updateCheckTTL {
			if cached.LatestVersion != types.ReleaseVersion {
				return cached.LatestVersion
			}
			return ""
		}
	}

	// Cache is missing or stale — check the network.
	latestVersion, err := detectLatestVersion(binURL)
	if err != nil {
		return ""
	}

	// Write cache atomically.
	writeUpdateCache(cachePath, updateCache{
		CheckedAt:     time.Now(),
		LatestVersion: latestVersion,
	})

	if latestVersion != types.ReleaseVersion {
		return latestVersion
	}
	return ""
}

// printUpdateHint collects from the channel with a short timeout and prints
// a hint to stderr if a newer version is available.
func printUpdateHint(ch <-chan string) {
	if ch == nil {
		return
	}
	select {
	case version := <-ch:
		if version != "" {
			fmt.Fprintf(os.Stderr, "\nA new version is available: %s. Run 'portal update' to upgrade.\n", version)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

// detectLatestVersion sends a HEAD request to the GitHub releases latest URL
// and extracts the version tag from the redirect Location header.
func detectLatestVersion(latestURL string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, latestURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD request failed: %w", err)
	}
	_ = resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no redirect location in response (status %d)", resp.StatusCode)
	}

	parsed, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URL: %w", err)
	}

	// Expected path: /gosuda/portal-tunnel/releases/download/v2.2.0/portal-linux-amd64
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	// segments: [gosuda, portal-tunnel, releases, download, v2.2.0, portal-linux-amd64]
	if len(segments) < 6 || segments[3] != "download" {
		return "", fmt.Errorf("unexpected redirect URL format: %s", location)
	}

	version := segments[4]
	if !strings.HasPrefix(version, "v") {
		return "", fmt.Errorf("unexpected version format in redirect URL: %s", version)
	}

	return version, nil
}

func downloadBinary(binURL string, dst *os.File) error {
	client := &http.Client{Timeout: 120 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, binURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	_, err = io.Copy(dst, resp.Body)
	return err
}

func verifyChecksum(filePath, checksumURL string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, checksumURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download checksum: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read checksum response: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return fmt.Errorf("empty checksum response")
	}
	expectedHash := strings.ToLower(fields[0])
	if len(expectedHash) != 64 {
		return fmt.Errorf("invalid checksum format (expected 64 hex chars, got %d)", len(expectedHash))
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".portal-update-check-*")
	if err != nil {
		return fmt.Errorf("directory %s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

func replaceBinary(srcPath, dstPath string) error {
	if runtime.GOOS == "windows" {
		return replaceBinaryWindows(srcPath, dstPath)
	}
	return replaceBinaryUnix(srcPath, dstPath)
}

func replaceBinaryUnix(srcPath, dstPath string) error {
	if err := os.Chmod(srcPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Try atomic rename first (works when src and dst are on the same device).
	if err := os.Rename(srcPath, dstPath); err == nil {
		return nil
	}

	// Cross-device fallback: copy then remove temp.
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to open destination: %w", err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	return nil
}

func replaceBinaryWindows(srcPath, dstPath string) error {
	oldPath := dstPath + ".old"

	// Remove leftover .old file from a previous update.
	_ = os.Remove(oldPath)

	// Rename the running binary out of the way, then move the new one in.
	if err := os.Rename(dstPath, oldPath); err != nil {
		return fmt.Errorf("failed to rename old binary: %w", err)
	}

	if err := os.Rename(srcPath, dstPath); err != nil {
		// Attempt to restore the old binary on failure.
		_ = os.Rename(oldPath, dstPath)
		return fmt.Errorf("failed to place new binary: %w", err)
	}

	// Best-effort cleanup of the old binary.
	_ = os.Remove(oldPath)
	return nil
}

func updateCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "portal-tunnel")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func readUpdateCache(path string) (updateCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return updateCache{}, err
	}
	var c updateCache
	if err := json.Unmarshal(data, &c); err != nil {
		return updateCache{}, err
	}
	return c, nil
}

func writeUpdateCache(path string, c updateCache) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".update_check-*.json")
	if err != nil {
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	_ = tmp.Close()

	_ = os.Rename(tmpName, path)
}
