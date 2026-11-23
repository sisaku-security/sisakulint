package githubapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newClient(t *testing.T, base string) *Client {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Token: "secret", BaseURL: u})
}

func TestGetSendsTokenToBaseHostOnly(t *testing.T) {
	var other string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other = r.Header.Get("Authorization") }))
	defer elsewhere.Close()
	var same []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		same = append(same, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/here":
			http.Redirect(w, r, "/there", http.StatusFound)
		case "/away":
			http.Redirect(w, r, elsewhere.URL+"/x", http.StatusFound)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer api.Close()
	c := newClient(t, api.URL)
	resp, err := c.Get(context.Background(), api.URL+"/here", "application/json", 1<<10)
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" || len(same) != 2 || same[1] != "Bearer secret" {
		t.Errorf("same host: %+v %v %q", resp, err, same)
	}
	resp, err = c.Get(context.Background(), api.URL+"/away", "application/json", 1<<10)
	if err != nil || resp.Status != http.StatusFound || other != "" {
		t.Errorf("another host: status %d, %v, the other host saw %q; want the 302 and no request there", resp.Status, err, other)
	}
}

func TestStreamDropsTokenOnOtherHost(t *testing.T) {
	var got string
	var asked bool
	codeload := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked, got = true, r.Header.Get("Authorization")
		io.WriteString(w, "archive")
	}))
	defer codeload.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("the API host did not get the token")
		}
		http.Redirect(w, r, codeload.URL+"/tar.gz/x", http.StatusFound)
	}))
	defer api.Close()
	u, _ := url.Parse(api.URL)
	c := New(Options{Token: "secret", BaseURL: u, HTTP: api.Client()})
	var body string
	err := c.Stream(context.Background(), api.URL+"/tarball/x", 1<<10, func(r io.Reader) error {
		b, err := io.ReadAll(r)
		body = string(b)
		return err
	})
	if err != nil || body != "archive" || !asked || got != "" {
		t.Errorf("Stream: %v %q asked %v; the other host saw %q, want no token", err, body, asked, got)
	}
}

func TestStreamRefusesHTTPRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "x") }))
	defer plain.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	}))
	defer api.Close()
	u, _ := url.Parse(api.URL)
	c := New(Options{Token: "secret", BaseURL: u, HTTP: api.Client()})
	err := c.Stream(context.Background(), api.URL+"/tarball/x", 1<<10, func(io.Reader) error { return nil })
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusFound {
		t.Errorf("Stream across https to http = %v, want the 302 as a StatusError", err)
	}
}

func TestRateLimited(t *testing.T) {
	for _, c := range []struct {
		status int
		header string
	}{{http.StatusTooManyRequests, ""}, {http.StatusForbidden, "X-RateLimit-Remaining"}, {http.StatusForbidden, "Retry-After"}} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.header == "X-RateLimit-Remaining" {
				w.Header().Set(c.header, "0")
			} else if c.header != "" {
				w.Header().Set(c.header, "60")
			}
			w.WriteHeader(c.status)
		}))
		cl := newClient(t, s.URL)
		if _, err := cl.Get(context.Background(), s.URL+"/x", "application/json", 10); !errors.Is(err, ErrRateLimited) {
			t.Errorf("%d %s: Get = %v, want ErrRateLimited", c.status, c.header, err)
		}
		if err := cl.Stream(context.Background(), s.URL+"/x", 10, func(io.Reader) error { return nil }); !errors.Is(err, ErrRateLimited) {
			t.Errorf("%d %s: Stream = %v, want ErrRateLimited", c.status, c.header, err)
		}
		s.Close()
	}
}

func TestStreamTooLarge(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 100)) }))
	defer s.Close()
	c := newClient(t, s.URL)
	err := c.Stream(context.Background(), s.URL+"/x", 10, func(r io.Reader) error {
		_, err := io.ReadAll(r)
		return err
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("Stream of 100 bytes with a limit of 10 = %v, want ErrTooLarge", err)
	}
}

func TestBase(t *testing.T) {
	if b := New(Options{}).Base(); b != "https://api.github.com" {
		t.Errorf("Base = %q", b)
	}
	u, _ := url.Parse("https://ghe.example/api/v3/")
	if b := New(Options{BaseURL: u}).Base(); b != "https://ghe.example/api/v3" {
		t.Errorf("Base = %q", b)
	}
}

func TestDefaultClientHasATimeout(t *testing.T) {
	if c := New(Options{}); c.api.Timeout == 0 || c.stream.Timeout == 0 {
		t.Error("the default client waits for ever")
	}
}

// TestNoTokenOverHTTPOffLoopback: the token goes over http only to a
// loopback address, where it does not leave the machine; to another host
// over http the requests carry none.
func TestNoTokenOverHTTPOffLoopback(t *testing.T) {
	for base, want := range map[string]bool{
		"https://ghe.example/api/v3": true,
		"http://ghe.example/api/v3":  false,
		"http://127.0.0.1:8080":      true,
		"http://[::1]:8080":          true,
		"http://localhost:8080":      true,
		"http://127.0.0.1.example":   false,
	} {
		if got := newClient(t, base).HasToken(); got != want {
			t.Errorf("%s: HasToken %v, want %v", base, got, want)
		}
	}
}
