package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		result := checkForUpdate(binURL)
		ch <- result
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
		tmp.Close()
		os.Remove(tmpName)
		return
	}
	tmp.Close()

	os.Rename(tmpName, path)
}
