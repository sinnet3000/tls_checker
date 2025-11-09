// TLS Checker in Go
//
// Purpose
//
//	Concurrent TLS diagnostics for a list of hosts with optional HTTP/2 probe and ASN lookup.
//	Designed to feel like idiomatic Go: small helpers, clear error paths, context timeouts,
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
//   - Text or JSONL output
//
// Build
//
//	go build -o tlscheck
//
// Examples
//
//	./tlscheck -i urls.txt -t 16 --timeout 5s --retries 2 --h2-probe=xnet --jsonl
//	./tlscheck -i urls.txt --min-tls=1.3 --no-asn --alpn=h2,http/1.1
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// ProbeMode controls how we verify HTTP/2 support once ALPN negotiates h2.
type ProbeMode string

const (
	ProbeRaw  ProbeMode = "raw"
	ProbeXNet ProbeMode = "xnet"
)

// Result captures one host diagnostic row.
type Result struct {
	Host        string   `json:"host"`
	IP          string   `json:"ip,omitempty"`
	RTTms       int      `json:"rtt_ms,omitempty"`
	ASN         string   `json:"asn,omitempty"`
	ASNName     string   `json:"asn_name,omitempty"`
	ASNCountry  string   `json:"asn_country,omitempty"`
	ASPrefix    string   `json:"asn_prefix,omitempty"`
	CommonName  string   `json:"common_name,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	ALPN        string   `json:"alpn,omitempty"`
	H2OK        *bool    `json:"http2_ok,omitempty"`
	CertOK      bool     `json:"cert_ok"`
	Success     bool     `json:"success"`
	Error       string   `json:"error,omitempty"`
	RetriesUsed int      `json:"retries_used"`
	Status      string   `json:"status"` // full|success|partial|failure
	Icon        string   `json:"icon"`
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
	Input    string
	Threads  int
	Timeout  time.Duration
	Retries  int
	OutPath  string
	Verbose  bool
	JSONL    bool
	NoASN    bool
	Port     string
	SNI      string
	ALPN     []string
	Probe    ProbeMode
	MinTLS   string
	MaxHosts int
}

var (
	asnMu    sync.Mutex
	asnCache = map[string]ASNInfo{}
)

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
	rand.Seed(time.Now().UnixNano())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hosts, err := loadHosts(cfg.Input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "fatal: no hosts to check")
		os.Exit(1)
	}
	if cfg.MaxHosts > 0 && cfg.MaxHosts < len(hosts) {
		hosts = hosts[:cfg.MaxHosts]
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
	logger.Printf("🔒 TLS Checker → %d hosts, %d workers, timeout=%s, retries=%d, probe=%s\n", len(hosts), cfg.Threads, cfg.Timeout, cfg.Retries, cfg.Probe)

	results := runChecks(ctx, hosts, cfg, logger)

	if cfg.JSONL {
		enc := json.NewEncoder(writer)
		for _, r := range results {
			_ = enc.Encode(r)
		}
	} else {
		logger.Println("---------------------- RESULTS ----------------------")
		for _, r := range results {
			logger.Println(formatResult(r))
		}
		printSummary(results, len(hosts), logger)
	}

	if cfg.OutPath != "" {
		fmt.Fprintf(os.Stdout, "\nResults saved to '%s'.\n", cfg.OutPath)
	}

	for _, r := range results {
		if r.Status == "failure" {
			os.Exit(2)
		}
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
	flag.BoolVar(&cfg.JSONL, "jsonl", false, "emit each result as JSONL")
	flag.BoolVar(&cfg.NoASN, "no-asn", false, "disable ASN lookups")
	flag.StringVar(&cfg.Port, "port", "443", "TCP port to connect")
	flag.StringVar(&cfg.SNI, "sni", "", "override SNI (default host)")
	alpn := flag.String("alpn", "h2,http/1.1", "comma separated ALPN to offer")
	probe := flag.String("h2-probe", string(ProbeRaw), "HTTP/2 probe: raw|xnet")
	flag.StringVar(&cfg.MinTLS, "min-tls", "", "minimum TLS version: 1.2 or 1.3 (empty = default)")
	flag.IntVar(&cfg.MaxHosts, "max-hosts", 0, "limit number of hosts processed (0 = all)")
	flag.Parse()

	cfg.ALPN = splitCSV(*alpn)
	switch ProbeMode(*probe) {
	case ProbeXNet:
		cfg.Probe = ProbeXNet
	default:
		cfg.Probe = ProbeRaw
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 1
	}
	return cfg
}

func runChecks(ctx context.Context, hosts []string, cfg Config, logger *log.Logger) []Result {
	jobs := make(chan string)
	var wg sync.WaitGroup
	results := make([]Result, 0, len(hosts))
	var mu sync.Mutex

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case host, ok := <-jobs:
					if !ok {
						return
					}
					r := checkHost(ctx, host, cfg, logger)
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				return
			case jobs <- host:
			}
		}
	}()

	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Host < results[j].Host })
	return results
}

func checkHost(ctx context.Context, host string, cfg Config, logger *log.Logger) Result {
	res := Result{Host: host}
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		r, err := diagnose(ctx, host, cfg)
		if err == nil {
			return r
		}
		res = r
		res.Error = describeError(err)
		res.RetriesUsed = attempt
		res.Success = false
		res.Status, res.Icon = "failure", "❌"
		if cfg.Verbose {
			logger.Printf("[DEBUG] %s attempt %d failed: %s (%v)", host, attempt+1, res.Error, err)
		}
		if attempt == cfg.Retries {
			break
		}
		backoff := time.Second * time.Duration(1<<attempt)
		jitter := time.Millisecond * time.Duration(rand.Intn(1000))
		select {
		case <-time.After(backoff + jitter):
		case <-ctx.Done():
			return res
		}
	}
	return res
}

func diagnose(ctx context.Context, host string, cfg Config) (Result, error) {
	res := Result{Host: host}
	attemptCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	ip, err := resolveOne(attemptCtx, host)
	if err != nil {
		return res, failure(ErrDNS, err)
	}
	res.IP = ip

	if !cfg.NoASN {
		asn := queryASNCymru(attemptCtx, ip)
		res.ASN, res.ASNName, res.ASNCountry, res.ASPrefix = asn.Number, asn.Name, asn.Country, asn.Prefix
	}

	start := time.Now()
	state, alpn, tlsVer, certOK, err := dialTLS(attemptCtx, host, cfg, true)
	if err != nil {
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			state, alpn, tlsVer, certOK, err = dialTLS(attemptCtx, host, cfg, false)
		}
	}
	if err != nil {
		return res, failure(ErrTLS, err)
	}
	res.RTTms = int(time.Since(start).Milliseconds())

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
		ok := false
		switch cfg.Probe {
		case ProbeXNet:
			ok = h2ProbeXNet(attemptCtx, host, cfg)
		default:
			ok = h2ProbeRaw(attemptCtx, host, cfg)
		}
		res.H2OK = &ok
	}

	res.Success = true
	res.Status, res.Icon = classify(&res)
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

func dialTLS(ctx context.Context, host string, cfg Config, strict bool) (tls.ConnectionState, string, string, bool, error) {
	min := uint16(0)
	switch cfg.MinTLS {
	case "1.3":
		min = tls.VersionTLS13
	case "1.2":
		min = tls.VersionTLS12
	}
	tlsCfg := &tls.Config{
		ServerName:         chooseSNI(cfg, host),
		NextProtos:         cfg.ALPN,
		MinVersion:         min,
		InsecureSkipVerify: !strict,
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, cfg.Port))
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

func h2ProbeRaw(ctx context.Context, host string, cfg Config) bool {
	tlsCfg := &tls.Config{ServerName: chooseSNI(cfg, host), NextProtos: []string{"h2"}}
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, cfg.Port))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
	if _, err := conn.Write(append(preface, settings...)); err != nil {
		return false
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if length > 0 {
		buf := make([]byte, length)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
	}
	return hdr[3] == 0x04
}

func h2ProbeXNet(ctx context.Context, host string, cfg Config) bool {
	tlsCfg := &tls.Config{ServerName: chooseSNI(cfg, host), NextProtos: []string{"h2"}}
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: tlsCfg}, Timeout: cfg.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+net.JoinHostPort(host, cfg.Port)+"/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.ProtoMajor == 2
}

func queryASNCymru(ctx context.Context, ip string) ASNInfo {
	asnMu.Lock()
	if v, ok := asnCache[ip]; ok {
		asnMu.Unlock()
		return v
	}
	asnMu.Unlock()

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
	asnMu.Lock()
	asnCache[ip] = info
	asnMu.Unlock()
	return info
}

func formatResult(r Result) string {
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
		return fmt.Sprintf("%s %s (%s) - RTT:%s | CN:%s | SANs:[%s] | ASN:%s (%s) | TLS:%s | ALPN:%s | H2:%s | Cert:%s%s",
			r.Icon, r.Host, val(r.IP, "N/A"), rtt, val(r.CommonName, "N/A"), strings.Join(sans, ", "),
			val(r.ASN, "N/A"), val(r.ASNName, "N/A"), val(r.TLSVersion, "N/A"), val(r.ALPN, "none"), h2, cert, retry,
		)
	}
	note := r.Error
	if r.RetriesUsed > 0 {
		note = fmt.Sprintf("Failed after %d attempts: %s", r.RetriesUsed+1, r.Error)
	}
	return fmt.Sprintf("❌ %s - FAILED (%s)", r.Host, note)
}

func printSummary(results []Result, total int, logger *log.Logger) {
	counts := map[string]int{"full": 0, "success": 0, "partial": 0, "failure": 0}
	recovered := 0
	breakdown := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
		if r.Success && r.RetriesUsed > 0 {
			recovered++
		}
		if r.Status == "failure" {
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

func loadHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	var hosts []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isComment(line) {
			continue
		}
		host, ok := extractHost(line)
		if !ok {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stdout, "📋 Found %d unique hosts to check.\n", len(hosts))
	return hosts, nil
}

func isComment(s string) bool {
	for _, prefix := range []string{"#", "//", ";", "--"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func extractHost(line string) (string, bool) {
	cand := strings.TrimSpace(line)
	if cand == "" {
		return "", false
	}
	if strings.Contains(cand, "://") {
		parts := strings.SplitN(cand, "://", 2)
		cand = parts[1]
		if idx := strings.Index(cand, "/"); idx >= 0 {
			cand = cand[:idx]
		}
	}
	if strings.HasPrefix(cand, "[") {
		if idx := strings.Index(cand, "]"); idx >= 0 {
			cand = cand[:idx+1]
		}
	} else if idx := strings.LastIndex(cand, ":"); idx >= 0 && !strings.Contains(cand, "]") {
		cand = cand[:idx]
	}
	cand = strings.Trim(cand, "[]")
	if cand == "" {
		return "", false
	}
	return cand, true
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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

func chooseSNI(cfg Config, host string) string {
	if cfg.SNI != "" {
		return cfg.SNI
	}
	return host
}
