// TLS Checker in Go
//
// Purpose
//
//	Concurrent TLS diagnostics for a list of hosts with optional HTTP/2 probe and ASN lookup.
//	Designed to feel idiomatic Go: focused helpers, clear error paths, context timeouts,
//	simple flags, and deterministic output.
//
// Features
//   - DNS resolution, TLS handshake, cert CN/SAN extraction
//   - ALPN detection and HTTP/2 readiness probe
//   - TLS version bucketing with four outcomes:
//     🔵 full     = TLS1.3 + ALPN=h2 + H2 ok
//     🟢 success  = TLS1.3 (ALPN/H2 optional)
//     🟡 partial  = TLS reachable but < TLS1.3
//     ❌ failure  = any error (DNS/timeout/TLS/etc.)
//   - Team Cymru WHOIS (ASN) with in-memory cache (optional)
//   - Retries with exponential backoff + jitter
//   - Text output only to stdout or a file of your choice
//
// Build
//
//	go build -o tlscheck
//
// Examples
//
//	./tlscheck -i urls.txt -t 16 --timeout 5s --retries 2
//	./tlscheck -i urls.txt --no-asn
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
)

// Result captures one host diagnostic row.
type Result struct {
	Host        string
	Port        string
	IP          string
	RTTms       int
	ASN         string
	ASNName     string
	ASNCountry  string
	ASPrefix    string
	CommonName  string
	SANs        []string
	TLSVersion  string
	ALPN        string
	H2OK        *bool
	CertOK      bool
	Success     bool
	Error       string
	RetriesUsed int
}

// ASNInfo represents the WHOIS metadata for an IP address.
type ASNInfo struct {
	Number  string
	Prefix  string
	Country string
	Name    string
}

// Config mirrors the CLI flags.
type Config struct {
	Input   string
	Threads int
	Timeout time.Duration
	Retries int
	OutPath string
	Verbose bool
	NoASN   bool
	Port    string
}

// HostSpec binds a host with the port it should be checked on.
type HostSpec struct {
	Host string
	Port string
}

type checker struct {
	cfg      Config
	logger   *log.Logger
	debug    *log.Logger
	asnCache map[string]ASNInfo
	asnMu    sync.RWMutex
	rng      *rand.Rand
	rngMu    sync.Mutex
}

var defaultALPN = []string{"h2", "http/1.1"}

type ErrorKind string

const (
	ErrDNS     ErrorKind = "DNS_RESOLUTION_FAILED"
	ErrTimeout ErrorKind = "CONNECTION_TIMEOUT"
	ErrRefused ErrorKind = "CONNECTION_REFUSED"
	ErrTLS     ErrorKind = "TLS_HANDSHAKE_FAILED"
	ErrCert    ErrorKind = "CERT_VERIFICATION_FAILED"
	ErrUnknown ErrorKind = "UNKNOWN_ERROR"
)

type checkError struct {
	kind ErrorKind
	err  error
}

func (c *checker) debugf(format string, args ...interface{}) {
	if c == nil || c.debug == nil {
		return
	}
	c.debug.Printf(format, args...)
}

func (e *checkError) Error() string {
	if e.err == nil {
		return string(e.kind)
	}
	return fmt.Sprintf("%s: %v", e.kind, e.err)
}

func (e *checkError) Unwrap() error { return e.err }

func failure(kind ErrorKind, err error) error { return &checkError{kind: kind, err: err} }

func main() {
	cfg := parseFlags()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targets, err := loadHosts(cfg.Input, cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "fatal: no hosts to check")
		os.Exit(1)
	}
	writer := io.Writer(os.Stdout)
	if cfg.OutPath != "" {
		f, err := os.Create(cfg.OutPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fatal: cannot create %s: %v\n", cfg.OutPath, err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}
	logger := log.New(writer, "", 0)
	logger.Printf("🔒 TLS Checker → %d targets, %d workers, timeout=%s, retries=%d, ASN:%t, default port:%s\n",
		len(targets), cfg.Threads, cfg.Timeout, cfg.Retries, !cfg.NoASN, cfg.Port)

	chk := newChecker(cfg, logger)
	results := chk.runChecks(ctx, targets)

	logger.Println("---------------------- RESULTS ----------------------")
	for _, r := range results {
		logger.Println(formatResult(r))
	}
	printSummary(results, len(targets), logger)

	if cfg.OutPath != "" {
		fmt.Fprintf(os.Stdout, "\nResults saved to '%s'.\n", cfg.OutPath)
	}

	for _, r := range results {
		if !r.Success {
			os.Exit(2)
		}
	}
}

func newChecker(cfg Config, logger *log.Logger) *checker {
	var dbg *log.Logger
	if cfg.Verbose {
		dbg = log.New(logger.Writer(), "[DEBUG] ", 0)
	}
	return &checker{
		cfg:      cfg,
		logger:   logger,
		debug:    dbg,
		asnCache: make(map[string]ASNInfo),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.Input, "i", "urls.txt", "input file with hosts/URLs")
	flag.IntVar(&cfg.Threads, "t", 12, "concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-connection timeout")
	flag.IntVar(&cfg.Retries, "retries", 3, "retries per host on failure")
	flag.StringVar(&cfg.OutPath, "o", "", "output file (optional)")
	flag.BoolVar(&cfg.Verbose, "v", false, "verbose/debug output")
	flag.BoolVar(&cfg.NoASN, "no-asn", false, "disable ASN lookups")
	flag.StringVar(&cfg.Port, "port", "443", "TCP port to connect")
	flag.Parse()

	if cfg.Threads <= 0 {
		cfg.Threads = 1
	}
	return cfg
}

func (c *checker) runChecks(ctx context.Context, targets []HostSpec) []Result {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(c.cfg.Threads)
	results := make([]Result, len(targets))
	for idx, target := range targets {
		idx, target := idx, target
		g.Go(func() error {
			c.debugf("host=%s port=%s queued", target.Host, target.Port)
			results[idx] = c.checkHost(ctx, target)
			return nil
		})
	}
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		c.logger.Printf("checks terminated early: %v", err)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host == results[j].Host {
			return results[i].Port < results[j].Port
		}
		return results[i].Host < results[j].Host
	})
	return results
}

func (c *checker) checkHost(ctx context.Context, target HostSpec) Result {
	res := Result{Host: target.Host, Port: target.Port}
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		c.debugf("host=%s port=%s attempt=%d/%d starting", target.Host, target.Port, attempt+1, c.cfg.Retries+1)
		r, err := c.diagnose(ctx, target)
		if err == nil {
			if attempt > 0 {
				r.RetriesUsed = attempt
			}
			status, _ := classify(&r)
			c.debugf("host=%s port=%s status=%s tls=%s alpn=%s h2=%v rtt=%dms",
				target.Host, target.Port, status, r.TLSVersion, r.ALPN, boolPtr(r.H2OK), r.RTTms)
			return r
		}
		res = r
		res.Error = describeError(err)
		res.RetriesUsed = attempt
		res.Success = false
		c.debugf("host=%s port=%s attempt=%d failed err=%v", target.Host, target.Port, attempt+1, err)
		if attempt == c.cfg.Retries {
			break
		}
		backoff := time.Second * time.Duration(1<<attempt)
		jitter := time.Millisecond * time.Duration(c.nextJitter(1000))
		select {
		case <-time.After(backoff + jitter):
		case <-ctx.Done():
			return res
		}
	}
	return res
}

func (c *checker) diagnose(ctx context.Context, target HostSpec) (Result, error) {
	res := Result{Host: target.Host, Port: target.Port}
	attemptCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	ip, err := resolveOne(attemptCtx, target.Host)
	if err != nil {
		return res, failure(ErrDNS, err)
	}
	res.IP = ip
	c.debugf("host=%s port=%s resolved_ip=%s", target.Host, target.Port, ip)

	if !c.cfg.NoASN {
		asn := c.queryASN(attemptCtx, ip)
		res.ASN, res.ASNName, res.ASNCountry, res.ASPrefix = asn.Number, asn.Name, asn.Country, asn.Prefix
	}

	start := time.Now()
	state, alpn, tlsVer, certOK, err := c.dialTLSWithFallback(attemptCtx, target)
	if err != nil {
		return res, failure(ErrTLS, err)
	}
	res.RTTms = int(time.Since(start).Milliseconds())
	c.debugf("host=%s port=%s tls=%s alpn=%s certOK=%t rtt=%dms", target.Host, target.Port, tlsVer, alpn, certOK, res.RTTms)

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res.CommonName = leaf.Subject.CommonName
		res.SANs = append([]string(nil), leaf.DNSNames...)
	}

	res.TLSVersion = tlsVer
	if alpn == "" {
		alpn = "none"
	}
	res.ALPN = alpn
	res.CertOK = certOK

	if alpn == "h2" {
		ok := c.h2Probe(attemptCtx, target, certOK)
		res.H2OK = &ok
		c.debugf("host=%s port=%s h2_probe=%t", target.Host, target.Port, ok)
	}

	res.Success = true
	return res, nil
}

func resolveOne(ctx context.Context, host string) (string, error) {
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", errors.New("no IPs returned")
	}
	return ips[0].String(), nil
}

func (c *checker) dialTLS(ctx context.Context, target HostSpec, strict bool) (tls.ConnectionState, string, string, bool, error) {
	tlsCfg := &tls.Config{
		ServerName:         target.Host,
		NextProtos:         defaultALPN,
		InsecureSkipVerify: !strict,
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, target.Port))
	if err != nil {
		return tls.ConnectionState{}, "", "", false, err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, "", "", false, errors.New("not a TLS connection")
	}
	state := tlsConn.ConnectionState()
	return state, state.NegotiatedProtocol, tlsVersionString(state.Version), strict, nil
}

func (c *checker) dialTLSWithFallback(ctx context.Context, target HostSpec) (tls.ConnectionState, string, string, bool, error) {
	state, alpn, tlsVer, certOK, err := c.dialTLS(ctx, target, true)
	if err == nil {
		return state, alpn, tlsVer, certOK, nil
	}
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) {
		c.debugf("host=%s port=%s strict TLS verify failed: %v (retrying insecure)", target.Host, target.Port, err)
		return c.dialTLS(ctx, target, false)
	}
	return state, alpn, tlsVer, certOK, err
}

func (c *checker) h2Probe(ctx context.Context, target HostSpec, certOK bool) bool {
	tlsCfg := &tls.Config{
		ServerName:         target.Host,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: !certOK,
	}
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: tlsCfg}, Timeout: c.cfg.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(target.Host, target.Port)+"/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.ProtoMajor == 2
}

func (c *checker) queryASN(ctx context.Context, ip string) ASNInfo {
	c.asnMu.RLock()
	if v, ok := c.asnCache[ip]; ok {
		c.asnMu.RUnlock()
		return v
	}
	c.asnMu.RUnlock()

	info := ASNInfo{Number: "N/A", Prefix: "N/A", Country: "N/A", Name: "N/A"}
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "verbose\n%s\nend\n", ip)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "|") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}
		id := strings.TrimSpace(fields[0])
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		info = ASNInfo{
			Number:  id,
			Prefix:  strings.TrimSpace(fields[2]),
			Country: strings.TrimSpace(fields[3]),
			Name:    strings.TrimSpace(fields[6]),
		}
		break
	}
	c.asnMu.Lock()
	c.asnCache[ip] = info
	c.asnMu.Unlock()
	return info
}

func formatResult(r Result) string {
	endpoint := r.Host
	if r.Port != "" {
		endpoint = net.JoinHostPort(r.Host, r.Port)
	}
	val := func(s, fallback string) string {
		if s == "" {
			return fallback
		}
		return s
	}
	rtt := "N/A"
	if r.RTTms > 0 {
		rtt = fmt.Sprintf("%dms", r.RTTms)
	}
	h2 := "n/a"
	if r.H2OK != nil {
		if *r.H2OK {
			h2 = "ok"
		} else {
			h2 = "fail"
		}
	}
	cert := "bad"
	if r.CertOK {
		cert = "ok"
	}
	sans := r.SANs
	if len(sans) > 3 {
		sans = append([]string(nil), sans[:3]...)
		sans = append(sans, "...")
	}
	retry := ""
	if r.Success && r.RetriesUsed > 0 {
		word := "retries"
		if r.RetriesUsed == 1 {
			word = "retry"
		}
		retry = fmt.Sprintf(" (Recovered after %d %s)", r.RetriesUsed, word)
	}
	if r.Success {
		_, icon := classify(&r)
		return fmt.Sprintf("%s %s (%s) - RTT:%s | CN:%s | SANs:[%s] | ASN:%s (%s) | TLS:%s | ALPN:%s | H2:%s | Cert:%s%s",
			icon, endpoint, val(r.IP, "N/A"), rtt, val(r.CommonName, "N/A"), strings.Join(sans, ", "),
			val(r.ASN, "N/A"), val(r.ASNName, "N/A"), val(r.TLSVersion, "N/A"), val(r.ALPN, "none"), h2, cert, retry,
		)
	}
	note := r.Error
	if r.RetriesUsed > 0 {
		note = fmt.Sprintf("Failed after %d attempts: %s", r.RetriesUsed+1, r.Error)
	}
	return fmt.Sprintf("❌ %s - FAILED (%s)", endpoint, note)
}

func printSummary(results []Result, total int, logger *log.Logger) {
	counts := map[string]int{"full": 0, "success": 0, "partial": 0, "failure": 0}
	recovered := 0
	breakdown := map[string]int{}
	for _, r := range results {
		status, _ := classify(&r)
		counts[status]++
		if r.Success && r.RetriesUsed > 0 {
			recovered++
		}
		if status == "failure" {
			breakdown[r.Error]++
		}
	}
	logger.Println("\n-------------------- SUMMARY --------------------")
	logger.Printf("Hosts Checked: %d/%d", len(results), total)
	logger.Printf("🔵 Full: %d | 🟢 Success: %d | 🟡 Partial: %d | ❌ Failure: %d", counts["full"], counts["success"], counts["partial"], counts["failure"])
	if recovered > 0 {
		logger.Printf("Recovered after retry: %d", recovered)
	}
	if len(breakdown) > 0 {
		logger.Println("Failure breakdown:")
		keys := make([]string, 0, len(breakdown))
		for k := range breakdown {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			logger.Printf("  - %s: %d", k, breakdown[k])
		}
	}
	logger.Println(strings.Repeat("-", 49))
}

func classify(r *Result) (string, string) {
	if !r.Success {
		return "failure", "❌"
	}
	if strings.EqualFold(r.TLSVersion, "TLS1.3") && r.ALPN == "h2" && r.H2OK != nil && *r.H2OK {
		return "full", "🔵"
	}
	if strings.EqualFold(r.TLSVersion, "TLS1.3") {
		return "success", "🟢"
	}
	return "partial", "🟡"
}

func loadHosts(path, defaultPort string) ([]HostSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	var targets []HostSpec
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isComment(line) {
			continue
		}
		target, ok := extractHost(line, defaultPort)
		if !ok {
			continue
		}
		key := target.Host + ":" + target.Port
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stdout, "📋 Found %d unique host:port targets to check.\n", len(targets))
	return targets, nil
}

func isComment(s string) bool {
	switch {
	case strings.HasPrefix(s, "#"), strings.HasPrefix(s, "//"), strings.HasPrefix(s, ";"), strings.HasPrefix(s, "--"):
		return true
	default:
		return false
	}
}

func extractHost(line, defaultPort string) (HostSpec, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return HostSpec{}, false
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return HostSpec{}, false
	}
	host := u.Hostname()
	if host == "" {
		return HostSpec{}, false
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return HostSpec{Host: host, Port: port}, true
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return ""
	}
}

func describeError(err error) string {
	if err == nil {
		return string(ErrUnknown)
	}
	var ce *checkError
	if errors.As(err, &ce) {
		return string(ce.kind)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return string(ErrTimeout)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return string(ErrTimeout)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return string(ErrRefused)
	case strings.Contains(msg, "certificate"):
		return string(ErrCert)
	}
	return string(ErrUnknown)
}

func boolPtr(b *bool) string {
	switch {
	case b == nil:
		return "n/a"
	case *b:
		return "true"
	default:
		return "false"
	}
}

func (c *checker) nextJitter(max int) int {
	c.rngMu.Lock()
	defer c.rngMu.Unlock()
	return c.rng.Intn(max)
}
