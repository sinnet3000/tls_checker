#!/usr/bin/env python3
"""
TLS Checker - A robust tool to check TLS connectivity, latency, certificate info, and ASN for multiple hosts.

Features:
- Concurrent checking using a configurable thread pool.
- Graceful shutdown on Ctrl+C, with a summary of partial results.
- Configurable connection timeout.
- Configurable retries for failed checks.
- Flexible input parser that accepts hostnames, IPs, and URLs, while ignoring comments and empty lines.
- Output to a specified file instead of the console.
- Detailed error summary, grouping failures by type (DNS, Timeout, etc.).
- Verbose mode for debugging.
"""

import socket
import ssl
import time
import re
import threading
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, TextIO, Optional
from collections import Counter

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
        description='TLS Checker with ASN lookup.',
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

def is_comment_or_blank(line: str) -> bool:
    """
    Determines if a line is a comment or blank. Accepts #, //, ;, -- (with leading whitespace).
    """
    line_stripped = line.lstrip()
    return (
        not line_stripped or
        line_stripped.startswith('#') or
        line_stripped.startswith('//') or
        line_stripped.startswith(';') or
        line_stripped.startswith('--')
    )

def extract_hostname(line: str) -> Optional[str]:
    """
    Extracts a hostname from a line, handling URLs.
    Assumes the line is already stripped and not a comment/blank.
    """
    line = line.strip()
    # Extract hostname from a URL if present
    match = re.search(r'^(?:https?://)?([^/\s]+)', line)
    if match:
        return match.group(1)
    return None

def load_hosts(filename: str, verbose: bool, output_fh: Optional[TextIO]) -> List[str]:
    """
    Loads and validates hostnames from a file, handling comments, empty lines, and URLs.
    """
    hosts: List[str] = []
    write_output(f"🔄 Loading hosts from '{filename}'...", output_fh)
    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if is_comment_or_blank(line):
                    continue
                hostname = extract_hostname(line)
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

def check_tls_host(host: str, timeout: int, verbose: bool, output_fh: Optional[TextIO], retries: int) -> Dict:
    """
    Checks TLS connectivity, certificate, and ASN for a single host, with retries.
    This function is designed to be executed in a thread.
    """
    result = {
        'host': host, 
        'success': False, 
        'error': None, 
        'retries_used': 0  # For UX output
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
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result['rtt_ms'] = int((time.time() - start_time) * 1000)
                    cert = ssock.getpeercert()

            # 4. Certificate Parsing
            subj = dict(x[0] for x in cert.get('subject', []))
            result['common_name'] = subj.get('commonName', 'N/A')
            result['san_list'] = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
            result['success'] = True
            result['retries_used'] = attempt
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
                continue  # silently try next
            else:
                return result  # failed after all attempts

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
    max_retries = result.get('max_retries', None)  # For future

    if result['success']:
        prefix = "✅"
        san_preview = ', '.join(san_list[:3]) + ('...' if len(san_list) > 3 else '')
        retry_note = f" (Recovered after {retries} {'retry' if retries==1 else 'retries'})" if retries > 0 else ""
        return f"{prefix} {host} ({ip}) - RTT: {rtt} | CN: {cn} | SANs: [{san_preview}] | ASN: {asn} ({name}){retry_note}"
    else:
        prefix = "❌"
        error = result.get('error', 'UNKNOWN')
        retry_note = f" (Failed after {retries+1} attempts: {error})" if retries > 0 else f" ({error})"
        return f"{prefix} {host} - FAILED{retry_note}"

def print_summary(results: List[Dict], total_hosts: int, output_fh: Optional[TextIO]):
    """Prints the final summary of successes, failures, and error types."""
    total_checked = len(results)
    successes = sum(1 for r in results if r['success'])
    failures = total_checked - successes
    recovered = sum(1 for r in results if r['success'] and r.get('retries_used', 0) > 0)

    summary = [
        "\n" + ("-"*20) + " SUMMARY " + ("-"*20),
        f"Hosts Checked: {total_checked}/{total_hosts}",
        f"✅ Successes: {successes}",
        f"  ↳ Successes after retry: {recovered}" if recovered else "",
        f"❌ Failures:  {failures}"
    ]

    if failures > 0:
        error_counts = Counter(r['error'] for r in results if not r['success'])
        summary.append("\nFailure Breakdown:")
        for error, count in sorted(error_counts.items()):
            summary.append(f"  - {error}: {count}")
    
    summary.append("-"*49)

    for line in summary:
        if line:  # avoid blank lines in summary
            write_output(line, output_fh)

# --- Main Execution ---

def main():
    """Main function to orchestrate the TLS checking process."""
    args = parse_args()
    
    # Open output file if specified, otherwise it remains None
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
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_host = {
                executor.submit(check_tls_host, host, args.timeout, args.verbose, output_fh, args.retries): host
                for host in hosts
            }
            for future in as_completed(future_to_host):
                res = future.result()
                # Attach max_retries for format_result if needed later
                res['max_retries'] = args.retries
                write_output(format_result(res), output_fh)
                results.append(res)
    except KeyboardInterrupt:
        write_output("\n\n🛑 User interrupted (Ctrl+C). Shutting down gracefully...", output_fh)
    finally:
        results.sort(key=lambda x: x['host'])
        print_summary(results, len(hosts), output_fh)
        if output_fh:
            write_output(f"\nResults saved to '{args.output_file}'.", None) # Final message to console
            output_fh.close()

if __name__ == "__main__":
    main()