package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

const (
	thumbnailViewportWidth  = 1280
	thumbnailViewportHeight = 720
	thumbnailJPEGQuality    = 80
	thumbnailMaxBytes       = 256 << 10 // 256KB
	thumbnailCooldown       = 30 * time.Second
	thumbnailPageTimeout    = 15 * time.Second
	thumbnailQueueSize      = 32
	thumbnailContentType    = "image/jpeg"
)

type thumbEntry struct {
	data      []byte
	fetchedAt time.Time
}

type thumbnailService struct {
	mu               sync.RWMutex
	cache            map[string]*thumbEntry
	pending          map[string]bool
	queue            chan string
	headlessShellURL string
	done             chan struct{}
}

func newThumbnailService(headlessShellURL string) *thumbnailService {
	headlessShellURL = strings.TrimSpace(headlessShellURL)
	if headlessShellURL == "" {
		return nil
	}
	ts := &thumbnailService{
		cache:            make(map[string]*thumbEntry),
		pending:          make(map[string]bool),
		queue:            make(chan string, thumbnailQueueSize),
		headlessShellURL: headlessShellURL,
		done:             make(chan struct{}),
	}
	go ts.worker()
	return ts
}

func (ts *thumbnailService) worker() {
	for hostname := range ts.queue {
		ts.capture(hostname)
		ts.mu.Lock()
		delete(ts.pending, hostname)
		ts.mu.Unlock()
	}
	close(ts.done)
}

func (ts *thumbnailService) Get(hostname string) ([]byte, string, bool) {
	if ts == nil {
		return nil, "", false
	}
	ts.mu.RLock()
	entry, ok := ts.cache[hostname]
	ts.mu.RUnlock()
	if !ok || len(entry.data) == 0 {
		return nil, "", false
	}
	return entry.data, thumbnailContentType, true
}

func (ts *thumbnailService) Has(hostname string) bool {
	if ts == nil {
		return false
	}
	ts.mu.RLock()
	entry, ok := ts.cache[hostname]
	ts.mu.RUnlock()
	return ok && len(entry.data) > 0
}

func (ts *thumbnailService) TriggerAsync(hostname string) {
	if ts == nil || hostname == "" {
		return
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if entry, ok := ts.cache[hostname]; ok {
		if len(entry.data) > 0 || time.Since(entry.fetchedAt) < thumbnailCooldown {
			return
		}
	}
	if ts.pending[hostname] {
		return
	}

	ts.pending[hostname] = true
	select {
	case ts.queue <- hostname:
	default:
		delete(ts.pending, hostname)
	}
}

func (ts *thumbnailService) capture(hostname string) {
	data, err := ts.screenshot(hostname)
	if err != nil {
		log.Warn().Err(err).Str("hostname", hostname).Msg("thumbnail capture failed")
		ts.cacheResult(hostname, nil)
		return
	}
	if len(data) > thumbnailMaxBytes {
		log.Warn().Str("hostname", hostname).Int("size", len(data)).Msg("thumbnail too large, discarding")
		ts.cacheResult(hostname, nil)
		return
	}

	ts.cacheResult(hostname, data)
	log.Info().Str("hostname", hostname).Int("size", len(data)).Msg("thumbnail captured")
}

func (ts *thumbnailService) cacheResult(hostname string, data []byte) {
	ts.mu.Lock()
	ts.cache[hostname] = &thumbEntry{data: data, fetchedAt: time.Now()}
	ts.mu.Unlock()
}

func (ts *thumbnailService) resolveCDPWebSocketURL() (string, error) {
	parsed, err := url.Parse(ts.headlessShellURL)
	if err != nil {
		return "", fmt.Errorf("parse headless shell URL: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://%s/json/version", parsed.Host), nil)
	if err != nil {
		return "", fmt.Errorf("build /json/version request: %w", err)
	}
	req.Host = "127.0.0.1" // headless-shell rejects non-IP Host headers

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("query /json/version: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read /json/version: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/json/version status %d: %s", resp.StatusCode, body)
	}

	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode /json/version: %w", err)
	}
	if info.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("/json/version: empty webSocketDebuggerUrl")
	}

	wsURL, err := url.Parse(info.WebSocketDebuggerURL)
	if err != nil {
		return "", fmt.Errorf("parse debugger URL: %w", err)
	}
	wsURL.Host = parsed.Host // headless-shell returns 0.0.0.0 internally
	return wsURL.String(), nil
}

func (ts *thumbnailService) screenshot(hostname string) ([]byte, error) {
	cdpURL, err := ts.resolveCDPWebSocketURL()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(cdpURL)
	if err := browser.Connect(); err != nil {
		return nil, err
	}

	incognito, err := browser.Incognito()
	if err != nil {
		return nil, err
	}
	defer incognito.Close()

	page, err := incognito.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, err
	}
	defer page.Close()

	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:  thumbnailViewportWidth,
		Height: thumbnailViewportHeight,
	})
	_ = browser.IgnoreCertErrors(true)

	if err := page.Navigate("https://" + hostname); err != nil {
		return nil, err
	}
	if err := page.Timeout(thumbnailPageTimeout).WaitLoad(); err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second)

	quality := thumbnailJPEGQuality
	return page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
}

func (ts *thumbnailService) Remove(hostname string) {
	if ts == nil {
		return
	}
	ts.mu.Lock()
	delete(ts.cache, hostname)
	delete(ts.pending, hostname)
	ts.mu.Unlock()
}

func (ts *thumbnailService) Close() {
	if ts == nil {
		return
	}
	close(ts.queue)
	<-ts.done
	ts.mu.Lock()
	ts.cache = make(map[string]*thumbEntry)
	ts.pending = make(map[string]bool)
	ts.mu.Unlock()
}
