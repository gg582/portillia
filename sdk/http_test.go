package sdk

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeCompressedHTTPChoosesAcceptedEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		acceptEncoding string
		want           string
	}{
		{name: "missing header", want: ""},
		{name: "unsupported encoding only", acceptEncoding: "deflate", want: ""},
		{name: "gzip accepted", acceptEncoding: "gzip", want: "gzip"},
		{name: "brotli preferred on tie", acceptEncoding: "gzip, br", want: "br"},
		{name: "quality chooses gzip", acceptEncoding: "gzip;q=1, br;q=0.5", want: "gzip"},
		{name: "zero quality disables format", acceptEncoding: "gzip;q=0, br;q=0", want: ""},
		{name: "wildcard ignored", acceptEncoding: "*", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "/", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}
			rec := httptest.NewRecorder()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Content-Length", "2048")
				_, _ = w.Write([]byte("hello world"))
			})

			serveCompressedHTTP(handler, rec, req)

			if got := rec.Header().Get("Content-Encoding"); got != tt.want {
				t.Fatalf("Content-Encoding = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServeCompressedHTTPCompressesTextResponses(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello world"))
	})

	serveCompressedHTTP(handler, rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}

func TestServeCompressedHTTPBypassesBinaryResponses(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("not-really-a-png"))
	})

	serveCompressedHTTP(handler, rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
}

func TestServeCompressedHTTPBypassesSmallResponsesWithContentLength(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "12")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	serveCompressedHTTP(handler, rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
}

func TestServeCompressedHTTPIgnoresSmallThresholdWithoutContentLength(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	serveCompressedHTTP(handler, rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}
