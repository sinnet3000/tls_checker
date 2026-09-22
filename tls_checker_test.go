package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDescribeErrorTimeoutWrapped(t *testing.T) {
	err := failure(ErrTLS, context.DeadlineExceeded)
	if got := describeError(err); got != string(ErrTimeout) {
		t.Fatalf("expected %s, got %s", ErrTimeout, got)
	}
}

func TestLoadHosts(t *testing.T) {
	tmp := t.TempDir()
	inputPath := tmp + "/hosts.txt"
	content := `
# Comment line
// Another comment
; Semicolon comment
-- SQL-style comment

example.com
https://example.com
example.com:443
example.com:8443
2001:db8::1
[2001:db8::1]:443
[2001:db8::1]:8443
`
	if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	targets, err := loadHosts(inputPath, "443")
	if err != nil {
		t.Fatalf("unexpected error loading hosts: %v", err)
	}

	expected := []HostSpec{
		{Host: "example.com", Port: "443"},
		{Host: "example.com", Port: "8443"},
		{Host: "2001:db8::1", Port: "443"},
		{Host: "2001:db8::1", Port: "8443"},
	}

	if len(targets) != len(expected) {
		t.Fatalf("expected %d targets, got %d: %+v", len(expected), len(targets), targets)
	}

	for i, exp := range expected {
		if targets[i] != exp {
			t.Errorf("target[%d] = %+v, want %+v", i, targets[i], exp)
		}
	}
}

func TestDialTLS_SelfSignedCert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	chk := &checker{}
	target := HostSpec{Host: u.Hostname(), Port: u.Port()}
	state, _, tlsVer, certOK, err := chk.dialTLS(context.Background(), target, u.Hostname())
	if err != nil {
		t.Fatalf("dialTLS failed on self-signed cert: %v", err)
	}
	if certOK {
		t.Fatalf("expected certOK to be false for self-signed cert without custom CA")
	}
	if tlsVer == "" {
		t.Fatalf("expected non-empty TLS version")
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatalf("expected peer certificates to be present")
	}
}

func TestH2Probe_BoundedRead(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("A", h2ProbeMaxBodyBytes*2)))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block to verify h2Probe does not wait for stream completion
		<-r.Context().Done()
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	chk := &checker{cfg: Config{Timeout: 5 * time.Second}}
	target := HostSpec{Host: u.Hostname(), Port: u.Port()}
	start := time.Now()
	ok := chk.h2Probe(context.Background(), target, u.Hostname(), false)
	elapsed := time.Since(start)

	if !ok {
		t.Fatalf("expected h2Probe to succeed on HTTP/2 server")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected h2Probe to return promptly without waiting for stream, took %v", elapsed)
	}
}

func TestIsRetryable(t *testing.T) {
	if isRetryable(nil) {
		t.Errorf("expected isRetryable(nil) to be false")
	}

	nxDomainErr := &net.DNSError{IsNotFound: true}
	if isRetryable(nxDomainErr) {
		t.Errorf("expected isRetryable(nxDomainErr) to be false")
	}

	wrappedNX := failure(ErrDNS, nxDomainErr)
	if isRetryable(wrappedNX) {
		t.Errorf("expected isRetryable(wrappedNX) to be false")
	}

	timeoutErr := &net.DNSError{IsTimeout: true}
	if !isRetryable(timeoutErr) {
		t.Errorf("expected isRetryable(timeoutErr) to be true")
	}
}

func TestCheckHost_NoRetryOnNXDOMAIN(t *testing.T) {
	chk := newChecker(Config{Retries: 3, Timeout: 1 * time.Second, NoASN: true}, log.Default())
	chk.resolve = func(ctx context.Context, host string) (string, error) {
		return "", &net.DNSError{IsNotFound: true, Name: host}
	}
	target := HostSpec{Host: "nxdomain.example", Port: "443"}
	start := time.Now()
	res := chk.checkHost(context.Background(), target)
	elapsed := time.Since(start)

	if res.Success {
		t.Errorf("expected failure for nonexistent domain")
	}
	if res.RetriesUsed != 0 {
		t.Errorf("expected 0 retries used for NXDOMAIN, got %d", res.RetriesUsed)
	}
	if elapsed > 1*time.Second {
		t.Errorf("expected NXDOMAIN to fail fast without retries, took %v", elapsed)
	}
}
