package sdk

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

func RunHTTP(ctx context.Context, relayListener net.Listener, handler http.Handler, localAddr string) error {
	if relayListener == nil && localAddr == "" {
		return errors.New("relay listener or local address is required")
	}

	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveCompressedHTTP(handler, w, r)
	})

	var relaySrv *http.Server
	if relayListener != nil {
		relaySrv = &http.Server{
			Handler:           serverHandler,
			ReadHeaderTimeout: defaultRequestTimeout,
		}
	}

	var localSrv *http.Server
	if localAddr != "" {
		localSrv = &http.Server{
			Addr:              localAddr,
			Handler:           serverHandler,
			ReadHeaderTimeout: defaultRequestTimeout,
		}
	}

	serverCount := 0
	if relaySrv != nil {
		serverCount++
	}
	if localSrv != nil {
		serverCount++
	}

	results := make(chan error, serverCount)
	normalizeServeErr := func(err error, prefix string) error {
		if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("%s: %w", prefix, err)
	}

	var (
		shutdownOnce sync.Once
		shutdownErr  error
	)
	shutdown := func() error {
		shutdownOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultHTTPShutdownTimeout)
			defer cancel()

			var localErr error
			if localSrv != nil {
				localErr = localSrv.Shutdown(shutdownCtx)
				if errors.Is(localErr, http.ErrServerClosed) {
					localErr = nil
				}
			}

			var relayErr error
			if relaySrv != nil {
				relayErr = relaySrv.Shutdown(shutdownCtx)
				if errors.Is(relayErr, http.ErrServerClosed) {
					relayErr = nil
				}
			}

			shutdownErr = errors.Join(localErr, relayErr)
		})
		return shutdownErr
	}

	if localSrv != nil {
		go func() {
			results <- normalizeServeErr(localSrv.ListenAndServe(), "serve local http")
		}()
	}
	if relaySrv != nil {
		go func() {
			results <- normalizeServeErr(relaySrv.Serve(relayListener), "serve relay http")
		}()
	}

	var serveErr error
	remaining := serverCount
	ctxDone := ctx.Done()
	for remaining > 0 {
		select {
		case err := <-results:
			remaining--
			if err != nil {
				serveErr = errors.Join(serveErr, err)
				_ = shutdown()
			}
		case <-ctxDone:
			_ = shutdown()
			ctxDone = nil
		}
	}

	return errors.Join(serveErr, shutdownErr)
}

func serveCompressedHTTP(handler http.Handler, w http.ResponseWriter, r *http.Request) {
	if handler == nil {
		http.NotFound(w, r)
		return
	}

	format := ""
	if r != nil {
		parseQuality := func(params string) float64 {
			for param := range strings.SplitSeq(params, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
					continue
				}

				q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || q < 0 {
					return 0
				}
				if q > 1 {
					return 1
				}
				return q
			}
			return 1
		}

		bestQ := 0.0
		for rawPart := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
			part := strings.TrimSpace(strings.ToLower(rawPart))
			if part == "" {
				continue
			}

			name, params, _ := strings.Cut(part, ";")
			candidate := strings.TrimSpace(name)
			if candidate != "br" && candidate != "gzip" {
				continue
			}

			q := parseQuality(params)
			if q <= 0 {
				continue
			}

			if q > bestQ || (q == bestQ && candidate == "br") {
				format = candidate
				bestQ = q
			}
		}
	}
	if format == "" || strings.TrimSpace(r.Header.Get("Range")) != "" {
		handler.ServeHTTP(w, r)
		return
	}
	if headerContainsToken(r.Header.Values("Connection"), "upgrade") && strings.TrimSpace(r.Header.Get("Upgrade")) != "" {
		handler.ServeHTTP(w, r)
		return
	}

	writer := &compressedResponseWriter{
		ResponseWriter: w,
		format:         format,
	}
	defer func() {
		_ = writer.Close()
	}()

	handler.ServeHTTP(writer, r)
}

func headerContainsToken(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == target {
				return true
			}
		}
	}
	return false
}

type compressedResponseWriter struct {
	http.ResponseWriter
	format      string
	writer      io.WriteCloser
	flushWriter func() error
	wroteHeader bool
	passthrough bool
}

func (w *compressedResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	header := w.Header()
	contentType, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(header.Get("Content-Type"))), ";")
	contentType = strings.TrimSpace(contentType)
	compressible := strings.HasPrefix(contentType, "text/")
	switch contentType {
	case "application/json", "application/javascript", "application/xml", "image/svg+xml":
		compressible = true
	}
	smallResponse := false
	if contentLength := strings.TrimSpace(header.Get("Content-Length")); contentLength != "" {
		if n, err := strconv.ParseInt(contentLength, 10, 64); err == nil && n >= 0 && n <= 1024 {
			smallResponse = true
		}
	}
	switch {
	case statusCode >= 100 && statusCode < 200:
		w.passthrough = true
	case statusCode == http.StatusNoContent || statusCode == http.StatusNotModified:
		w.passthrough = true
	case !compressible:
		w.passthrough = true
	case smallResponse:
		w.passthrough = true
	case strings.TrimSpace(header.Get("Content-Encoding")) != "":
		w.passthrough = true
	case strings.TrimSpace(header.Get("Content-Range")) != "":
		w.passthrough = true
	case strings.HasPrefix(contentType, "text/event-stream"):
		w.passthrough = true
	case headerContainsToken(header.Values("Cache-Control"), "no-transform"):
		w.passthrough = true
	}
	if w.passthrough {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	switch w.format {
	case "br":
		writer := brotli.NewWriter(w.ResponseWriter)
		w.writer = writer
		w.flushWriter = writer.Flush
	case "gzip":
		writer := gzip.NewWriter(w.ResponseWriter)
		w.writer = writer
		w.flushWriter = writer.Flush
	default:
		w.passthrough = true
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	header.Del("Content-Length")
	header.Set("Content-Encoding", w.format)
	if !headerContainsToken(header.Values("Vary"), "accept-encoding") {
		header.Add("Vary", "Accept-Encoding")
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *compressedResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		header := w.Header()
		if strings.TrimSpace(header.Get("Content-Type")) == "" && len(p) > 0 {
			header.Set("Content-Type", http.DetectContentType(p))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.passthrough {
		return w.ResponseWriter.Write(p)
	}
	return w.writer.Write(p)
}

func (w *compressedResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.passthrough && w.flushWriter != nil {
		_ = w.flushWriter()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *compressedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *compressedResponseWriter) Close() error {
	if w.writer == nil {
		return nil
	}
	err := w.writer.Close()
	w.writer = nil
	w.flushWriter = nil
	return err
}
