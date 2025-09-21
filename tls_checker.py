#!/usr/bin/env python3
"""
TLS Checker - Check TLS connectivity, latency, certificate info, ASN, and HTTP/2 readiness.

Adds:
- TLS 1.3 + HTTP/2 validation (pure-stdlib H2 probe).
- Four-way outcome (mutually exclusive, in precedence order):
  🔵 Full success   = TLSv1.3 + ALPN=h2 + H2: ok
  🟢 Success        = TLSv1.3 (ALPN/H2 may be missing or failing)
  🟡 Partial        = Reachable TLS but not TLSv1.3 (e.g., TLSv1.2; any ALPN/H2)
  ❌ Failure        = DNS/timeout/TLS/other error

No "overall" line; summary lists Full success, Success (TLS 1.3), Partial, Complete failure.
"""

import argparse
import random
import re
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, TextIO, Tuple

# --- Globals ---

# Thread locks for clean console output and cache protection
print_lock = threading.Lock()
asn_cache_lock = threading.Lock()

# In-memory cache for ASN lookups
asn_cache: Dict[str, Dict] = {}

# --- Core Functions ---

def timestamp() -> str:
    """Returns the current time in HH:MM:SS format for logging."""
    return datetime.now().strftime("%H:%M:%S")

def write_output(message: str, file_handle: Optional[TextIO] = None):
    """
    Thread-safe and redirected output.
    Writes a message to the specified file handle or to stdout if None.
    """
    with print_lock:
        if file_handle:
            file_handle.write(message + '\n')
        else:
            print(message)

def parse_args():
    """
    Parses and validates command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description='TLS Checker with ASN + HTTP/2 validation.',
        epilog='Example: ./tls_checker.py hosts.txt --threads 10 --timeout 5 --retries 2 --output-file results.txt'
    )
    parser.add_argument(
        '-i', '--input-file',
        default="urls.txt",
        help='Path to the input file containing a list of hosts, one per line. Default: urls.txt'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads to use. Default: 10.'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Per-connection timeout in seconds. Default: 5.'
    )
    parser.add_argument(
        '-r', '--retries',
        type=int,
        default=3,
        help='Number of retries for failed checks. Default: 3.'
    )
    parser.add_argument(
        '-o', '--output-file',
        help='File to write results and summary to. If not provided, output is printed to the console.'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose/debug output for troubleshooting.'
    )
    return parser.parse_args()

def extract_hostname(line: str) -> Optional[str]:
    """
    Extracts the hostname from a domain-like input, stripping any port number.

    This function assumes the input is a domain, subdomain, IP address (IPv4), or 
    localhost, optionally followed by a port, and does not contain a scheme 
    (e.g., http://) or path (e.g., /path).
    """
    if not line:
        return None
    hostname = line.strip()
    return hostname.split(':', 1)[0]

def load_hosts(filename: str, verbose: bool, output_fh: Optional[TextIO]) -> List[str]:
    """
    Loads and validates hostnames from a file, handling comments, empty lines, and URLs.
    This version integrates the logic for skipping comments and blank lines directly.
    """
    hosts: List[str] = []
    comment_prefixes = ('#', '//', ';', '--')
    write_output(f"🔄 Loading hosts from '{filename}'...", output_fh)

    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                cleaned_line = line.strip()
                if not cleaned_line or cleaned_line.startswith(comment_prefixes):
                    continue
                hostname = extract_hostname(cleaned_line)
                if hostname:
                    if hostname not in hosts:
                        hosts.append(hostname)
                else:
                    write_output(f"⚠️  Line {line_num}: Malformed or invalid input skipped: '{line.strip()}'", output_fh)
    except FileNotFoundError:
        write_output(f"❌ Error: Input file '{filename}' not found.", output_fh)
        return []
    except Exception as e:
        write_output(f"❌ Error reading '{filename}': {e}", output_fh)
        return []

    write_output(f"📋 Found {len(hosts)} unique hosts to check.\n", output_fh)
    return hosts

def query_asn_cymru(ip: str, timeout: int, verbose: bool, output_fh: Optional[TextIO]) -> Dict[str, str]:
    """
    Looks up ASN information for an IP via Team Cymru's WHOIS service, with caching.
    """
    with asn_cache_lock:
        if ip in asn_cache:
            if verbose:
                write_output(f"  [DEBUG] ASN cache hit for {ip}", output_fh)
            return asn_cache[ip]

    try:
        with socket.create_connection(('whois.cymru.com', 43), timeout=timeout) as sock:
            query = f"verbose\n{ip}\nend\n".encode()
            sock.sendall(query)
            response = sock.makefile('r').read()

        if verbose:
            write_output(f"  [DEBUG] WHOIS response for {ip}:\n{response.strip()}", output_fh)

        for line in response.splitlines():
            if line.startswith('#') or '|' not in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 7 and parts[0].isdigit():
                result = {
                    'asn': parts[0],
                    'asn_prefix': parts[2],
                    'asn_country': parts[3],
                    'asn_name': parts[6]
                }
                with asn_cache_lock:
                    asn_cache[ip] = result
                return result
        raise ValueError("No valid ASN data line found in response")

    except Exception as e:
        if verbose:
            write_output(f"  [DEBUG] ASN lookup for {ip} failed: {e}", output_fh)
        return {'asn': 'N/A', 'asn_name': 'N/A', 'asn_country': 'N/A', 'asn_prefix': 'N/A'}

# --- Minimal HTTP/2 stdlib probe (no external deps) ---

def _h2_probe_over_tls(ssock: ssl.SSLSocket, timeout: float) -> bool:
    """
    Minimal HTTP/2 probe using only stdlib over an *already-handshaken* TLS socket
    with ALPN 'h2'. We:
      1) send the HTTP/2 client connection preface
      2) send an empty SETTINGS frame
      3) read one frame from the server and check it's SETTINGS (type=0x4)

    Returns True if SETTINGS is seen; False otherwise.
    """
    ssock.settimeout(timeout)

    # HTTP/2 client connection preface (RFC 7540 §3.5)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Empty SETTINGS frame: length=0, type=0x04, flags=0x00, stream_id=0
    # Frame header: length(3) | type(1) | flags(1) | R+stream_id(4)
    settings_frame = b"\x00\x00\x00" + b"\x04" + b"\x00" + b"\x00\x00\x00\x00"

    try:
        ssock.sendall(preface + settings_frame)

        # Read one frame header (9 bytes)
        hdr = b""
        while len(hdr) < 9:
            chunk = ssock.recv(9 - len(hdr))
            if not chunk:
                return False
            hdr += chunk

        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype = hdr[3]  # 0x04 is SETTINGS

        # Drain payload if any to keep the socket clean
        remaining = length
        while remaining > 0:
            chunk = ssock.recv(min(remaining, 65535))
            if not chunk:
                break
            remaining -= len(chunk)

        return ftype == 0x04
    except Exception:
        return False

def classify(result: Dict) -> Tuple[str, str]:
    """
    Decide final status/icon from computed fields.
    Returns (status, icon) where status ∈ {"full","success","partial","failure"}.
    """
    if not result.get('success'):
        return "failure", "❌"
    if result.get('is_full_success'):
        return "full", "🔵"
    if result.get('is_tls13_success'):
        return "success", "🟢"
    return "partial", "🟡"

def check_tls_host(host: str, timeout: int, verbose: bool, output_fh: Optional[TextIO], retries: int) -> Dict:
    """
    Checks TLS connectivity, certificate, and ASN for a single host, with retries.
    This function is designed to be executed in a thread.
    """
    result = {
        'host': host, 
        'success': False, 
        'error': None, 
        'retries_used': 0
    }

    for attempt in range(retries + 1):
        try:
            start_time = time.time()
            # 1. DNS Resolution
            try:
                ip = socket.gethostbyname(host)
                result['ip'] = ip
            except socket.gaierror:
                raise ValueError("DNS_RESOLUTION_FAILED")

            # 2. ASN Lookup
            result.update(query_asn_cymru(ip, timeout, verbose, output_fh))

            # 3. TLS Handshake
            #
            # Policy: try strict (CERT_REQUIRED) first. If that fails with a
            # certificate verification error, retry with an "insecure" context
            # so we can still collect ALPN/TLS version & report cert_ok=false.
            cert_ok = None
            tls_version = None
            alpn_selected = "none"
            cert = None
            last_exc = None

            for mode in ("strict", "insecure"):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = True
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    if mode == "insecure":
                        ctx = ssl._create_unverified_context()
                        # Hostname check disabled implicitly in unverified mode.

                    # Offer HTTP/2 and HTTP/1.1 via ALPN
                    try:
                        ctx.set_alpn_protocols(["h2", "http/1.1"])
                    except Exception:
                        # Older OpenSSL builds might not support ALPN
                        pass

                    with socket.create_connection((host, 443), timeout=timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            result['rtt_ms'] = int((time.time() - start_time) * 1000)
                            cert = ssock.getpeercert()
                            tls_version = getattr(ssock, "version", lambda: None)()
                            alpn_selected = getattr(ssock, "selected_alpn_protocol", lambda: None)() or "none"
                            cert_ok = (mode == "strict")
                    # If we got here, handshake succeeded; break.
                    break
                except ssl.SSLCertVerificationError as e:
                    last_exc = e
                    cert_ok = False
                    if verbose:
                        write_output(f"  [DEBUG] Cert verification failed for {host}, retrying insecurely...", output_fh)
                    continue
                except Exception as e:
                    last_exc = e
                    # Non-cert failures shouldn't switch to insecure mode; bail out.
                    raise

            if tls_version is None:
                if last_exc:
                    raise last_exc
                raise ssl.SSLError("TLS handshake failed unexpectedly")

            # --- HTTP/2 probe (stdlib) ---
            # Rule:
            # - If ALPN != h2 → H2 = n/a
            # - If ALPN == h2 and probe succeeds → H2 = ok
            # - If ALPN == h2 and probe fails → H2 = fail
            http2_ok = None
            if alpn_selected == "h2":
                try:
                    # Use a fresh short-lived TLS session for the probe.
                    _ctx = ssl.create_default_context()
                    _ctx.check_hostname = True
                    _ctx.verify_mode = ssl.CERT_REQUIRED
                    try:
                        _ctx.set_alpn_protocols(["h2"])
                    except Exception:
                        pass
                    with socket.create_connection((host, 443), timeout=timeout) as _sock:
                        with _ctx.wrap_socket(_sock, server_hostname=host) as _ssock:
                            if _ssock.selected_alpn_protocol() == "h2":
                                http2_ok = _h2_probe_over_tls(_ssock, float(timeout))
                            else:
                                http2_ok = False
                except Exception as e:
                    http2_ok = False
                    if verbose:
                        write_output(f"  [DEBUG] HTTP/2 probe failed for {host}: {type(e).__name__}: {e}", output_fh)
            else:
                http2_ok = None  # ALPN wasn't h2 → n/a

            # 4. Certificate Parsing
            cn = 'N/A'
            san_list = []
            try:
                subj = dict(x[0] for x in (cert or {}).get('subject', []))
                cn = subj.get('commonName', 'N/A')
                san_list = [v for t, v in (cert or {}).get('subjectAltName', []) if t == 'DNS']
            except Exception:
                pass

            # Populate result
            result['common_name'] = cn
            result['san_list'] = san_list
            result['success'] = True
            result['retries_used'] = attempt

            # Attach telemetry
            result['tls_version'] = tls_version or 'N/A'
            result['alpn_selected'] = alpn_selected or 'none'
            result['http2_ok'] = http2_ok  # True|False|None (None => n/a)
            result['cert_ok'] = bool(cert_ok)

            # Strict "full success" definition for per-host icon & summary
            tls_v_up = (result['tls_version'] or '').upper()
            result['is_full_success'] = (tls_v_up == 'TLSV1.3' and alpn_selected == 'h2' and http2_ok is True)

            # New: plain TLS 1.3 success (regardless of ALPN/H2)
            result['is_tls13_success'] = (tls_v_up == 'TLSV1.3')

            # New: classify once, store for formatting & summary
            status, icon = classify(result)
            result['status'] = status
            result['icon'] = icon

            return result

        except Exception as e:
            error_type = "UNKNOWN_ERROR"
            if isinstance(e, ValueError) and str(e) == "DNS_RESOLUTION_FAILED":
                error_type = "DNS_RESOLUTION_FAILED"
            elif isinstance(e, ssl.SSLCertVerificationError):
                error_type = "CERT_VERIFICATION_FAILED"
            elif isinstance(e, ssl.SSLError):
                error_type = "TLS_HANDSHAKE_FAILED"
            elif isinstance(e, socket.timeout):
                error_type = "CONNECTION_TIMEOUT"
            elif isinstance(e, ConnectionRefusedError):
                error_type = "CONNECTION_REFUSED"
            
            result['error'] = error_type
            result['retries_used'] = attempt
            
            if verbose:
                write_output(f"  [DEBUG] Error for {host} on attempt {attempt+1}: {error_type} ({type(e).__name__}: {e})", output_fh)
            
            if attempt < retries:
                # Exponential backoff with jitter
                backoff_time = (2 ** attempt) + random.uniform(0, 1)
                if verbose:
                    write_output(f"  [DEBUG] Retrying {host} in {backoff_time:.2f}s...", output_fh)
                time.sleep(backoff_time)
                continue
            else:
                return result

def format_result(result: Dict) -> str:
    """Formats a single result dictionary into a human-readable string."""
    host = result['host']
    ip = result.get('ip', 'N/A')
    rtt = f"{result['rtt_ms']}ms" if 'rtt_ms' in result else 'N/A'
    asn = result.get('asn', 'N/A')
    name = result.get('asn_name', 'N/A')
    cn = result.get('common_name', 'N/A')
    san_list = result.get('san_list', [])
    retries = result.get('retries_used', 0)

    tls_v = result.get('tls_version', 'N/A')
    alpn = result.get('alpn_selected', 'none')
    h2_ok = result.get('http2_ok', None)
    cert_ok = result.get('cert_ok', False)

    # Render H2 field per rule
    if h2_ok is True:
        h2_txt = "ok"
    elif h2_ok is False:
        h2_txt = "fail"
    else:
        h2_txt = "n/a"

    if result['success']:
        # Determine per-host icon from classifier
        icon = result.get('icon', "🟡")

        san_preview = ', '.join(san_list[:3]) + ('...' if len(san_list) > 3 else '')
        retry_note = f" (Recovered after {retries} {'retry' if retries==1 else 'retries'})" if retries > 0 else ""
        core = f"{icon} {host} ({ip}) - RTT: {rtt} | CN: {cn} | SANs: [{san_preview}] | ASN: {asn} ({name}){retry_note}"
        extra = f" | TLS: {tls_v} | ALPN: {alpn} | H2: {h2_txt} | Cert: " + ("ok" if cert_ok else "bad")
        return core + extra
    else:
        prefix = "❌"
        error = result.get('error', 'UNKNOWN')
        retry_note = f" (Failed after {retries+1} attempts: {error})" if retries > 0 else f" ({error})"
        return f"{prefix} {host} - FAILED{retry_note}"

def print_summary(results: List[Dict], total_hosts: int, output_fh: Optional[TextIO]):
    """Prints the final summary with explicit buckets."""
    total_checked = len(results)
    failures = sum(1 for r in results if r.get('status') == 'failure')
    full_success = sum(1 for r in results if r.get('status') == 'full')
    green_success = sum(1 for r in results if r.get('status') == 'success')
    partial_success = sum(1 for r in results if r.get('status') == 'partial')

    recovered = sum(1 for r in results if r.get('success') and r.get('retries_used', 0) > 0)

    summary = [
        "\n" + ("-"*20) + " SUMMARY " + ("-"*20),
        f"Hosts Checked: {total_checked}/{total_hosts}",
        f"🔵 Full success: {full_success}",
        f"🟢 Success (TLS 1.3): {green_success}",
        f"🟡 Partial success: {partial_success}",
        f"❌ Complete failure: {failures}",
        f"  ↳ Successes after retry: {recovered}" if recovered else "",
    ]

    if failures > 0:
        error_counts = Counter(r['error'] for r in results if r.get('status') == 'failure')
        summary.append("\nFailure Breakdown:")
        for error, count in sorted(error_counts.items()):
            summary.append(f"  - {error}: {count}")
    
    summary.append("-"*49)

    for line in summary:
        if line:
            write_output(line, output_fh)

# --- Main Execution ---

def main():
    """Main function to orchestrate the TLS checking process."""
    args = parse_args()
    
    output_fh = None
    if args.output_file:
        try:
            output_fh = open(args.output_file, 'w')
        except IOError as e:
            print(f"❌ Fatal: Could not open output file '{args.output_file}': {e}", file=sys.stderr)
            sys.exit(1)

    write_output(f"🔒 TLS Checker starting up...", output_fh)
    write_output(f"   Threads: {args.threads}, Timeout: {args.timeout}s, Retries: {args.retries}, Verbose: {args.verbose}\n", output_fh)

    hosts = load_hosts(args.input_file, args.verbose, output_fh)
    if not hosts:
        if output_fh:
            output_fh.close()
        sys.exit(1)

    results = []
    checked_count = 0
    total_hosts = len(hosts)

    def print_progress(count, total):
        """A simple, dependency-free progress bar for the console."""
        if args.output_file or args.verbose:
            return
        percent = int(100 * (count / float(total)))
        bar_length = 50
        filled_length = int(bar_length * count // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        sys.stdout.write(f'\rProgress: |{bar}| {percent}% ({count}/{total}) Complete')
        sys.stdout.flush()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_host = {
                executor.submit(check_tls_host, host, args.timeout, args.verbose, output_fh, args.retries): host
                for host in hosts
            }
            
            print_progress(0, total_hosts)

            for future in as_completed(future_to_host):
                res = future.result()
                results.append(res)
                
                checked_count += 1
                print_progress(checked_count, total_hosts)

    except KeyboardInterrupt:
        write_output("\n\n🛑 User interrupted (Ctrl+C). Shutting down gracefully...", output_fh)
    finally:
        # Move to the next line after the progress bar is done
        if not args.output_file and not args.verbose:
            print()

        # Print all results in a sorted block
        write_output("\n" + ("-"*22) + " RESULTS " + ("-"*22), output_fh)
        results.sort(key=lambda x: x['host'])
        for res in results:
            write_output(format_result(res), output_fh)
        
        # Print the final summary
        print_summary(results, len(hosts), output_fh)
        if output_fh:
            write_output(f"\nResults saved to '{args.output_file}'.", None)
            output_fh.close()

if __name__ == "__main__":
    main()
