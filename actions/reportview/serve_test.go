package reportview

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestParseServeAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1:0", "127.0.0.1:8080", "[::1]:0"} {
		if _, err := ParseServeAddr(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"0.0.0.0:0", "192.168.1.2:80", "localhost:0", "127.0.0.1", "[::]:0"} {
		if _, err := ParseServeAddr(s); err == nil {
			t.Errorf("%s: no error", s)
		}
	}
}

func TestHandler(t *testing.T) {
	page := []byte("<!doctype html>page")
	h := handler(page, netip.MustParseAddrPort("127.0.0.1:8080"))
	for _, c := range []struct {
		method, url, host string
		code              int
	}{
		{"GET", "/", "127.0.0.1:8080", 200},
		{"GET", "/", "localhost:8080", 200},
		{"HEAD", "/", "127.0.0.1:8080", 200},
		{"GET", "/x", "127.0.0.1:8080", 404},
		{"POST", "/", "127.0.0.1:8080", 405},
		{"GET", "/", "evil.example:8080", 403},
		{"GET", "/", "127.0.0.1:9090", 403},
	} {
		r := httptest.NewRequest(c.method, c.url, nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code {
			t.Errorf("%s %s %s: %d, want %d", c.method, c.url, c.host, w.Code, c.code)
		}
		if c.code == 200 {
			for k, v := range map[string]string{"Content-Security-Policy": policy, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Content-Type": "text/html; charset=utf-8"} {
				if got := w.Header().Get(k); got != v {
					t.Errorf("%s: %q, want %q", k, got, v)
				}
			}
		}
	}
}

func TestServe(t *testing.T) {
	page := []byte("<!doctype html>page")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 1)
	err := Serve(ctx, DefaultServeAddr, page, func(url string) {
		go func() {
			defer cancel()
			resp, err := http.Get(url)
			if err != nil {
				got <- err.Error()
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			got <- string(b)
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != string(page) {
		t.Errorf("got %q", s)
	}
}

func TestServePortInUse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := make(chan netip.AddrPort, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, DefaultServeAddr, nil, func(url string) {
			addr <- netip.MustParseAddrPort(url[len("http://") : len(url)-1])
		})
	}()
	if err := Serve(context.Background(), <-addr, nil, func(string) { t.Error("ready on a port in use") }); err == nil {
		t.Error("no error on a port in use")
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
}
