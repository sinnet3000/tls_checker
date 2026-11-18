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

func TestEscapeTerminal(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "example.com", want: "example.com"},
		{name: "unicode", in: "café.example 日本語.example 😀", want: "café.example 日本語.example 😀"},
		{name: "esc sequence", in: "red\x1b[31m", want: `red\x1b[31m`},
		{name: "control characters", in: "a\x00b\ac\nd\re\tf\x7fg", want: `a\x00b\ac\nd\re\tf\x7fg`},
		{name: "c1 control", in: "a\u0085b", want: `a\u0085b`},
		{name: "bidi override", in: "a\u202eb", want: `a\u202eb`},
		{name: "line separator", in: "a\u2028b", want: `a\u2028b`},
		{name: "invalid utf8", in: "a\xffb", want: `a\xffb`},
		{name: "backslash preserved", in: `a\b`, want: `a\b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeTerminal(tt.in); got != tt.want {
				t.Fatalf("escapeTerminal(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatResultEscapesRemoteText(t *testing.T) {
	h2OK := true
	r := Result{
		Host:       "host.example",
		Port:       "443",
		IP:         "203.0.113.10",
		RTTms:      41,
		ASN:        "13335",
		ASNName:    "CLOUD\x1b[31mFLARE\r\nFAKE",
		CommonName: "*.exa\x1b[2Jmple.com",
		SANs:       []string{"good.example", "bad\a.example", "café.example", "日本語.example"},
		TLSVersion: "TLS1.3",
		ALPN:       "h2",
		H2OK:       &h2OK,
		CertOK:     true,
		Success:    true,
	}

	out := formatResult(r)
	for _, want := range []string{
		`CN:*.exa\x1b[2Jmple.com`,
		`SANs:[good.example, bad\a.example, café.example, ...]`,
		`ASN:13335 (CLOUD\x1b[31mFLARE\r\nFAKE)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected escaped field %q in output %q", want, out)
		}
	}
	if got := strings.Count(out, " | "); got != 7 {
		t.Errorf("expected output layout with 7 field separators, got %d in %q", got, out)
	}
	assertNoTerminalControls(t, out)
}

func TestFormatResultEscapesRemoteError(t *testing.T) {
	r := Result{
		Host:        "broken.example",
		Port:        "443",
		Error:       "dial tcp: \x1b[31mremote\a\nsecond line",
		RetriesUsed: 2,
	}

	out := formatResult(r)
	want := `❌ broken.example:443 - FAILED (Failed after 3 attempts: dial tcp: \x1b[31mremote\a\nsecond line)`
	if out != want {
		t.Fatalf("formatResult() = %q, want %q", out, want)
	}
	assertNoTerminalControls(t, out)
}

func assertNoTerminalControls(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if isTerminalUnsafeRune(r) {
			t.Fatalf("output contains raw unsafe rune %U: %q", r, s)
		}
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
