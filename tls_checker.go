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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// ProbeMode selects the HTTP/2 probe strategy.
//   raw  = send preface + empty SETTINGS and expect SETTINGS back
//   xnet = use golang.org/x/net/http2 transport
//
// Default is raw to keep behavior close to stdlib-only.

type ProbeMode string

const (
	ProbeRaw  ProbeMode = "raw"
	ProbeXNet ProbeMode = "xnet"
)

// Result captures per-host diagnostics.

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

// Config holds runtime flags.

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
	MinTLS   string // "" | "1.2" | "1.3"
	MaxHosts int
}

// Globals for output and shared state.

var (
	asnMu    sync.Mutex
	asnCache = map[string]map[string]string{}
)

func main() {
	cfg := parseFlags()
	rand.Seed(time.Now().UnixNano())

	ctx, cancel := signalContext()
	defer cancel()

	var out io.Writer
	if cfg.OutPath != "" {
		f, err := os.Create(cfg.OutPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fatal: cannot open output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	writer := out
	if writer == nil {
		writer = os.Stdout
	}
	logger := log.New(writer, "", 0)

	logger.Println("🔒 TLS Checker starting up...")
	logger.Printf("   Threads: %d, Timeout: %s, Retries: %d, Probe: %s, MinTLS: %s, JSONL: %v\n", cfg.Threads, cfg.Timeout, cfg.Retries, cfg.Probe, cfg.MinTLS, cfg.JSONL)

	hosts, err := loadHosts(cfg.Input)
	if err != nil || len(hosts) == 0 {
		os.Exit(1)
	}
	if cfg.MaxHosts > 0 && cfg.MaxHosts < len(hosts) {
		hosts = hosts[:cfg.MaxHosts]
	}

	res := runChecks(ctx, hosts, cfg, logger)

	// Emit results
	if !cfg.JSONL {
		logger.Println("\n---------------------- RESULTS ----------------------")
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Host < res[j].Host })
	for _, r := range res {
		if cfg.JSONL {
			enc := json.NewEncoder(writer)
			_ = enc.Encode(r)
			continue
		}
		logger.Println(formatResult(r))
	}
	if !cfg.JSONL {
		printSummary(res, len(hosts), logger)
	}
	failures := 0
	for _, r := range res {
		if r.Status == "failure" {
			failures++
		}
	}
	if cfg.OutPath != "" {
		fmt.Fprintf(os.Stdout, "\nResults saved to '%s'.\n", cfg.OutPath)
	}
	if failures > 0 {
		os.Exit(2)
	}
}

// parseFlags defines and parses CLI flags into Config.

func parseFlags() Config {
	cfg := Config{}
	flag.StringVar(&cfg.Input, "i", "urls.txt", "input file with hosts/URLs")
	flag.IntVar(&cfg.Threads, "t", 12, "concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-connection timeout")
	flag.IntVar(&cfg.Retries, "retries", 3, "retries per host on failure")
	flag.StringVar(&cfg.OutPath, "o", "", "output file (optional)")
	flag.BoolVar(&cfg.Verbose, "v", false, "verbose/debug output")
	flag.BoolVar(&cfg.JSONL, "jsonl", false, "emit each result as a JSON line")
	flag.BoolVar(&cfg.NoASN, "no-asn", false, "disable ASN lookups")
	flag.StringVar(&cfg.Port, "port", "443", "TCP port to connect")
	flag.StringVar(&cfg.SNI, "sni", "", "override SNI (default: host)")
	alpn := flag.String("alpn", "h2,http/1.1", "comma-separated ALPN to offer")
	probe := flag.String("h2-probe", string(ProbeRaw), "HTTP/2 probe: raw|xnet")
	flag.StringVar(&cfg.MinTLS, "min-tls", "", "minimum TLS version: 1.2 or 1.3 (empty = default)")
	flag.IntVar(&cfg.MaxHosts, "max-hosts", 0, "limit number of hosts processed (0 = all)")
	flag.Parse()
	cfg.ALPN = splitCSV(*alpn)
	switch ProbeMode(*probe) {
	case ProbeRaw, ProbeXNet:
		cfg.Probe = ProbeMode(*probe)
	default:
		cfg.Probe = ProbeRaw
	}
	return cfg
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

// runChecks executes per-host diagnostics with a fixed worker pool.

func runChecks(ctx context.Context, hosts []string, cfg Config, logger *log.Logger) []Result {
	results := make([]Result, 0, len(hosts))
	var mu sync.Mutex
	var checked int32
	progress := shouldShowProgress(cfg)

	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	for _, h := range hosts {
		host := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := checkHost(ctx, host, cfg, logger)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			if progress {
				c := atomic.AddInt32(&checked, 1)
				printProgress(int(c), len(hosts))
			}
		}()
	}
	wg.Wait()
	if progress {
		fmt.Println()
	}
	return results
}

func shouldShowProgress(cfg Config) bool {
	if cfg.OutPath != "" || cfg.Verbose {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// checkHost performs one host check with retries/backoff.

func checkHost(ctx context.Context, host string, cfg Config, logger *log.Logger) Result {
	res := Result{Host: host}
	var lastErr error
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		r, err := attemptOnce(ctx, host, cfg, logger)
		if err == nil {
			return r
		}
		res = r
		res.Error = mapError(err)
		res.RetriesUsed = attempt
		res.Status = "failure"
		res.Icon = "❌"
		lastErr = err
		if cfg.Verbose {
			logger.Printf("[DEBUG] %s attempt %d: %s (%v)", host, attempt+1, res.Error, err)
		}
		if attempt < cfg.Retries {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			jitter := time.Duration(rand.Float64()*1000) * time.Millisecond
			select {
			case <-time.After(backoff + jitter):
			case <-ctx.Done():
				return res
			}
		}
	}
	res.Error = mapError(lastErr)
	return res
}

// attemptOnce runs a single attempt: DNS -> ASN -> TLS -> H2 probe -> cert parse -> classify.

func attemptOnce(ctx context.Context, host string, cfg Config, logger *log.Logger) (Result, error) {
	res := Result{Host: host}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	ip, err := resolveOne(ctx, host)
	if err != nil {
		return res, fmt.Errorf("DNS_RESOLUTION_FAILED: %w", err)
	}
	res.IP = ip

	if !cfg.NoASN {
		asn := queryASNCymru(ctx, ip)
		res.ASN = asn["asn"]
		res.ASNName = asn["asn_name"]
		res.ASNCountry = asn["asn_country"]
		res.ASPrefix = asn["asn_prefix"]
	}

	// TLS strict then insecure (to collect ALPN/TLS on bad certs)
	start := time.Now()
	state, alpn, tlsVer, certOK, err := dialTLS(ctx, host, cfg, true)
	if err != nil {
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			if cfg.Verbose {
				logger.Printf("[DEBUG] cert verify failed for %s, retrying insecurely", host)
			}
			state, alpn, tlsVer, certOK, err = dialTLS(ctx, host, cfg, false)
		}
	}
	if err != nil {
		return res, fmt.Errorf("TLS_HANDSHAKE_FAILED: %w", err)
	}
	res.RTTms = int(time.Since(start).Milliseconds())

	// Optional H2 probe
	var h2ok *bool
	if alpn == "h2" {
		ok := false
		switch cfg.Probe {
		case ProbeXNet:
			ok = h2ProbeXNet(ctx, host, cfg)
		default:
			ok = h2ProbeRaw(ctx, host, cfg)
		}
		h2ok = &ok
	}

	// Cert fields
	cn := "N/A"
	var sans []string
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		cn = leaf.Subject.CommonName
		sans = append(sans, leaf.DNSNames...)
	}

	res.CommonName = cn
	res.SANs = sans
	res.Success = true
	res.TLSVersion = tlsVer
	if alpn == "" {
		alpn = "none"
	}
	res.ALPN = alpn
	res.H2OK = h2ok
	res.CertOK = certOK

	res.Status, res.Icon = classify(&res)
	return res, nil
}

// resolveOne resolves a hostname to one IP (first A/AAAA).

func resolveOne(ctx context.Context, host string) (string, error) {
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", errors.New("no IPs")
	}
	return ips[0].String(), nil
}

// dialTLS performs a TLS handshake and returns state and negotiated features.

func dialTLS(ctx context.Context, host string, cfg Config, strict bool) (tls.ConnectionState, string, string, bool, error) {
	serverName := host
	if cfg.SNI != "" {
		serverName = cfg.SNI
	}
	min := uint16(0)
	switch cfg.MinTLS {
	case "1.3":
		min = tls.VersionTLS13
	case "1.2":
		min = tls.VersionTLS12
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		NextProtos:         cfg.ALPN,
		MinVersion:         min,
		InsecureSkipVerify: !strict,
	}
	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, cfg.Port), tlsCfg)
	if err != nil {
		return tls.ConnectionState{}, "", "", false, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	alpn := state.NegotiatedProtocol
	tlsVer := tlsVersionString(state.Version)
	certOK := strict
	return state, alpn, tlsVer, certOK, nil
}

// h2ProbeRaw sends the HTTP/2 preface + empty SETTINGS and expects a SETTINGS frame back.

func h2ProbeRaw(ctx context.Context, host string, cfg Config) bool {
	tlsCfg := &tls.Config{ServerName: chooseSNI(cfg, host), NextProtos: []string{"h2"}}
	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, cfg.Port), tlsCfg)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(append(preface, settings...)); err != nil {
		return false
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	ftype := hdr[3]
	if length > 0 {
		buf := make([]byte, length)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
	}
	return ftype == 0x04
}

// h2ProbeXNet uses golang.org/x/net/http2 to perform a HEAD / request over H2.

func h2ProbeXNet(ctx context.Context, host string, cfg Config) bool {
	tlsCfg := &tls.Config{ServerName: chooseSNI(cfg, host), NextProtos: []string{"h2"}}
	tr := &http2.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}
	url := "https://" + net.JoinHostPort(host, cfg.Port) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
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

// Team Cymru WHOIS over port 43 with small cache.

func queryASNCymru(ctx context.Context, ip string) map[string]string {
	asnMu.Lock()
	if v, ok := asnCache[ip]; ok {
		asnMu.Unlock()
		return v
	}
	asnMu.Unlock()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return map[string]string{"asn": "N/A", "asn_name": "N/A", "asn_country": "N/A", "asn_prefix": "N/A"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := "verbose\n" + ip + "\nend\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return map[string]string{"asn": "N/A", "asn_name": "N/A", "asn_country": "N/A", "asn_prefix": "N/A"}
	}
	b, err := io.ReadAll(conn)
	if err != nil {
		return map[string]string{"asn": "N/A", "asn_name": "N/A", "asn_country": "N/A", "asn_prefix": "N/A"}
	}
	var asn, prefix, country, name string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || !strings.Contains(ln, "|") {
			continue
		}
		parts := strings.Split(ln, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 7 {
			continue
		}
		id := parts[0]
		if id == "" {
			continue
		}
		digitsOnly := true
		for _, ch := range id {
			if ch < '0' || ch > '9' {
				digitsOnly = false
				break
			}
		}
		if !digitsOnly {
			continue
		}
		asn = id
		prefix = parts[2]
		country = parts[3]
		name = parts[6]
		break
	}
	if asn == "" {
		return map[string]string{"asn": "N/A", "asn_name": "N/A", "asn_country": "N/A", "asn_prefix": "N/A"}
	}
	res := map[string]string{"asn": asn, "asn_prefix": prefix, "asn_country": country, "asn_name": name}
	asnMu.Lock()
	asnCache[ip] = res
	asnMu.Unlock()
	return res
}

// Formatting and summary.

func formatResult(r Result) string {
	ip := r.IP
	if ip == "" {
		ip = "N/A"
	}
	rtt := "N/A"
	if r.RTTms > 0 {
		rtt = fmt.Sprintf("%dms", r.RTTms)
	}
	asn := r.ASN
	if asn == "" {
		asn = "N/A"
	}
	name := r.ASNName
	if name == "" {
		name = "N/A"
	}
	cn := r.CommonName
	if cn == "" {
		cn = "N/A"
	}
	alpn := r.ALPN
	if alpn == "" {
		alpn = "none"
	}
	var h2txt string
	if r.H2OK == nil {
		h2txt = "n/a"
	} else if *r.H2OK {
		h2txt = "ok"
	} else {
		h2txt = "fail"
	}
	sans := r.SANs
	if len(sans) > 3 {
		sans = sans[:3]
	}
	preview := strings.Join(sans, ", ")
	if len(r.SANs) > 3 {
		preview += "..."
	}

	if r.Success {
		recoverNote := ""
		if r.RetriesUsed > 0 {
			label := "retries"
			if r.RetriesUsed == 1 {
				label = "retry"
			}
			recoverNote = fmt.Sprintf(" (Recovered after %d %s)", r.RetriesUsed, label)
		}
		core := fmt.Sprintf("%s %s (%s) - RTT: %s | CN: %s | SANs: [%s] | ASN: %s (%s)%s", r.Icon, r.Host, ip, rtt, cn, preview, asn, name, recoverNote)
		certStatus := "bad"
		if r.CertOK {
			certStatus = "ok"
		}
		extra := fmt.Sprintf(" | TLS: %s | ALPN: %s | H2: %s | Cert: %s", r.TLSVersion, alpn, h2txt, certStatus)
		return core + extra
	}
	failNote := fmt.Sprintf(" (%s)", r.Error)
	if r.RetriesUsed > 0 {
		failNote = fmt.Sprintf(" (Failed after %d attempts: %s)", r.RetriesUsed+1, r.Error)
	}
	return fmt.Sprintf("❌ %s - FAILED%s", r.Host, failNote)
}

func printSummary(results []Result, totalHosts int, logger *log.Logger) {
	totalChecked := len(results)
	counts := map[string]int{"failure": 0, "full": 0, "success": 0, "partial": 0}
	recovered := 0
	errCnt := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
		if r.Success && r.RetriesUsed > 0 {
			recovered++
		}
		if r.Status == "failure" {
			errCnt[r.Error]++
		}
	}
	logger.Println("\n-------------------- SUMMARY --------------------")
	logger.Printf("Hosts Checked: %d/%d", totalChecked, totalHosts)
	logger.Printf("🔵 Full success (TLS 1.3 + HTTP/2 ready): %d", counts["full"])
	logger.Printf("🟢 Success (TLS 1.3, HTTP/2 optional): %d", counts["success"])
	logger.Printf("🟡 Partial success (TLS reachable but < 1.3): %d", counts["partial"])
	logger.Printf("❌ Complete failure (no TLS connection): %d", counts["failure"])
	if recovered > 0 {
		logger.Printf("  ↳ Successes after retry: %d", recovered)
	}
	if counts["failure"] > 0 {
		logger.Println("\nFailure Breakdown:")
		keys := make([]string, 0, len(errCnt))
		for k := range errCnt {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			logger.Printf("  - %s: %d", k, errCnt[k])
		}
	}
	logger.Println(strings.Repeat("-", 49))
}

// classify returns (status, icon) given a successful result.

func classify(r *Result) (string, string) {
	if !r.Success {
		return "failure", "❌"
	}
	if strings.ToUpper(r.TLSVersion) == "TLS1.3" && r.ALPN == "h2" && r.H2OK != nil && *r.H2OK {
		return "full", "🔵"
	}
	if strings.ToUpper(r.TLSVersion) == "TLS1.3" {
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
		h, ok := extractHost(line)
		if !ok {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stdout, "📋 Found %d unique hosts to check.\n", len(hosts))
	return hosts, nil
}

// Utilities

func selectWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}

func isComment(s string) bool {
	for _, p := range []string{"#", "//", ";", "--"} {
		if strings.HasPrefix(s, p) {
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
		rest := parts[1]
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		cand = rest
	}
	// strip port
	if strings.HasPrefix(cand, "[") {
		if i := strings.Index(cand, "]"); i >= 0 {
			cand = cand[:i+1]
		}
	} else if i := strings.LastIndex(cand, ":"); i >= 0 && !strings.Contains(cand, "]") {
		cand = cand[:i]
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

func printProgress(cur, total int) {
	percent := int(100 * float64(cur) / float64(total))
	barLen := 50
	filled := int(float64(barLen) * float64(cur) / float64(total))
	if filled < 0 {
		filled = 0
	}
	if filled > barLen {
		filled = barLen
	}
	bar := bytes.Repeat([]byte("█"), filled)
	bar = append(bar, bytes.Repeat([]byte("-"), barLen-filled)...)
	fmt.Printf("\rProgress: |%s| %d%% (%d/%d) Complete", string(bar), percent, cur, total)
	if cur == total {
		fmt.Println()
	}
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

func mapError(err error) string {
	if err == nil {
		return "UNKNOWN_ERROR"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "DNS_RESOLUTION_FAILED"):
		return "DNS_RESOLUTION_FAILED"
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"), errors.Is(err, context.DeadlineExceeded):
		return "CONNECTION_TIMEOUT"
	case strings.Contains(s, "refused"):
		return "CONNECTION_REFUSED"
	case strings.Contains(s, "TLS_HANDSHAKE_FAILED"):
		return "TLS_HANDSHAKE_FAILED"
	case strings.Contains(s, "certificate"):
		return "CERT_VERIFICATION_FAILED"
	default:
		return "UNKNOWN_ERROR"
	}
}

func chooseSNI(cfg Config, host string) string {
	if cfg.SNI != "" {
		return cfg.SNI
	}
	return host
}
