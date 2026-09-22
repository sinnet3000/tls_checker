package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExtractHostIPv6Literal(t *testing.T) {
	target, ok := extractHost("2001:db8::1", "443")
	if !ok {
		t.Fatalf("expected IPv6 literal to parse")
	}
	if target.Host != "2001:db8::1" {
		t.Fatalf("expected host 2001:db8::1, got %q", target.Host)
	}
	if target.Port != "443" {
		t.Fatalf("expected port 443, got %q", target.Port)
	}
}

func TestDescribeErrorTimeoutWrapped(t *testing.T) {
	err := failure(ErrTLS, context.DeadlineExceeded)
	if got := describeError(err); got != string(ErrTimeout) {
		t.Fatalf("expected %s, got %s", ErrTimeout, got)
	}
}

func TestMain_NoTargets_ExitsNonZero(t *testing.T) {
	tmp := t.TempDir()
	inputPath := tmp + "/empty.txt"
	if err := os.WriteFile(inputPath, []byte("\n# comment\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "-i", inputPath, "--no-asn", "-t", "1", "--timeout", "1s", "--retries", "0")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success. output=%s", string(out))
	}
	if !strings.Contains(string(out), "fatal: no hosts to check") {
		t.Fatalf("expected fatal message, got output=%s", string(out))
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	var appArgs []string
	for i, arg := range os.Args {
		if arg == "--" {
			appArgs = os.Args[i+1:]
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = append([]string{"tls_checker"}, appArgs...)
	main()
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
