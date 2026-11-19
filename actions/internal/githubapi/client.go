package githubapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options says how to reach the API.
type Options struct {
	// Token is sent as a bearer token to the host of BaseURL; empty is no
	// token. It is never sent across a redirect to another host, nor over
	// http to a host that is not a loopback address (Loopback).
	Token string
	// BaseURL is the REST API's root; nil is https://api.github.com. Its
	// path is kept (a GitHub Enterprise Server's /api/v3).
	BaseURL *url.URL
	// HTTP makes the requests; nil is a client that gives up on a request
	// after 30 seconds.
	HTTP *http.Client
}

// Client sends the requests of the API. It counts no budget: each of its
// users keeps its own.
type Client struct {
	token  string
	base   string
	api    *http.Client // follows a redirect only to the same host and scheme
	stream *http.Client // follows a redirect to another https host, without the token
}

// New makes the Client.
func New(o Options) *Client {
	base := "https://api.github.com"
	if o.BaseURL != nil {
		base = strings.TrimSuffix(o.BaseURL.String(), "/")
	}
	c := &http.Client{Timeout: 30 * time.Second}
	if o.HTTP != nil {
		c = o.HTTP
	}
	api := *c // the token must not follow a redirect to another host, or to http
	api.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme || len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	stream := *c // an archive is served by another host (codeload.github.com)
	stream.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != via[0].URL.Scheme || len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		if req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}
	token := o.Token
	if o.BaseURL != nil && !strings.EqualFold(o.BaseURL.Scheme, "https") && !Loopback(o.BaseURL) {
		token = "" // over http it would leave the machine in the clear
	}
	return &Client{token: token, base: base, api: &api, stream: &stream}
}

// Loopback is whether the host of u is a loopback address: localhost, or
// an IP address of 127.0.0.0/8 or ::1.
func Loopback(u *url.URL) bool {
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Base is the REST API's root, without a trailing slash.
func (c *Client) Base() string { return c.base }

// HasToken is whether the requests carry a token.
func (c *Client) HasToken() bool { return c.token != "" }

// Response is the status and the first bytes of an answer.
type Response struct {
	Status int
	Body   []byte
	Next   bool // a Link header says there is a next page
}

var (
	// ErrRateLimited is the primary rate limit (429, or 403 with no
	// requests remaining) or the secondary one (403 with Retry-After).
	ErrRateLimited = errors.New("github: rate limited")
	// ErrTooLarge is an answer of Stream larger than its limit.
	ErrTooLarge = errors.New("github: the answer is larger than the limit")
	// ErrRequestFailed is a request that got no answer.
	ErrRequestFailed = errors.New("github: the request failed")
	// ErrUnreadable is an answer that could not be read.
	ErrUnreadable = errors.New("github: the answer could not be read")
)

// StatusError is an answer of Stream whose status is not 200.
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("github: HTTP %d", e.Status) }

func (c *Client) headers(req *http.Request) {
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sisakulint")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func rateLimited(resp *http.Response) bool {
	return resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "")
}

// Do sends req with the headers of the API and reads at most maxBytes
// bytes of the answer. The error wraps the context's error when the
// context is done, or is one of ErrRateLimited, ErrRequestFailed and
// ErrUnreadable.
func (c *Client) Do(req *http.Request, maxBytes int64) (Response, error) {
	c.headers(req)
	resp, err := c.api.Do(req)
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return Response{}, fmt.Errorf("github: not asked: %w", ctxErr)
		}
		return Response{}, ErrRequestFailed
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return Response{}, ErrUnreadable
	}
	if rateLimited(resp) {
		return Response{}, ErrRateLimited
	}
	return Response{Status: resp.StatusCode, Body: b, Next: strings.Contains(resp.Header.Get("Link"), `rel="next"`)}, nil
}

// Get sends a GET of u with the Accept header accept (Do).
func (c *Client) Get(ctx context.Context, u, accept string, maxBytes int64) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Response{}, ErrRequestFailed
	}
	req.Header.Set("Accept", accept)
	return c.Do(req, maxBytes)
}

// Stream sends a GET of u, follows its redirects to another host of the
// same scheme without the token, and gives read the answer of status 200,
// of which read may read at most maxBytes bytes (ErrTooLarge past them).
// Another status is a StatusError, or ErrRateLimited.
func (c *Client) Stream(ctx context.Context, u string, maxBytes int64, read func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ErrRequestFailed
	}
	c.headers(req)
	resp, err := c.stream.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("github: not asked: %w", ctxErr)
		}
		return ErrRequestFailed
	}
	defer resp.Body.Close()
	if rateLimited(resp) {
		return ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Status: resp.StatusCode}
	}
	return read(&limitedReader{r: resp.Body, left: maxBytes})
}

// limitedReader is an io.Reader that fails with ErrTooLarge past its limit.
type limitedReader struct {
	r    io.Reader
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		var one [1]byte
		if n, _ := l.r.Read(one[:]); n > 0 {
			return 0, ErrTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
