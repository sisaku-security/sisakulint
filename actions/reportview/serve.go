package reportview

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// DefaultServeAddr is where Serve listens unless told: 127.0.0.1, on a
// port the system chooses.
var DefaultServeAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)

// ParseServeAddr reads an address to serve on: a loopback IP and a port.
// The page has lines of the workflows, which may be private.
func ParseServeAddr(s string) (netip.AddrPort, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !a.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%s is not a loopback address: the page has lines of the workflows", a.Addr())
	}
	return a, nil
}

// Serve serves page at / on addr until ctx is done. ready gets the URL
// once it listens.
func Serve(ctx context.Context, addr netip.AddrPort, page []byte, ready func(url string)) error {
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	bound := netip.AddrPortFrom(addr.Addr(), uint16(ln.Addr().(*net.TCPAddr).Port))
	srv := &http.Server{Handler: handler(page, bound), ReadHeaderTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	ready("http://" + bound.String() + "/")
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handler serves page at / to a request for the host bound or localhost on
// its port, and nothing else: a page of another site that a name resolves
// to the loopback address (DNS rebinding) asks with its own host.
func handler(page []byte, bound netip.AddrPort) http.Handler {
	hosts := []string{bound.String(), "localhost:" + strconv.Itoa(int(bound.Port()))}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(hosts, r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		w.Write(page)
	})
}
