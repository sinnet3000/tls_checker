#!/usr/bin/env python3
"""
TLS Checker - Check TLS connectivity, latency, certificate info, and ASN for multiple hosts
Supports output verbosity modes: brief, standard, full (default: standard).
"""

import socket
import ssl
import time
import re
import threading
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# Default output mode
OUTPUT_MODE = 'standard'  # choices: 'brief', 'standard', 'full'

# Debug flag
DEBUG = False

# Thread locks for clean console output and cache protection
print_lock = threading.Lock()
asn_cache_lock = threading.Lock()

# In-memory cache for ASN lookups
iasn_cache: Dict[str, Dict] = {}

def timestamp() -> str:
    """Get current timestamp in HH:MM:SS format"""
    return datetime.now().strftime("%H:%M:%S")

def safe_print(message: str):
    """Thread-safe printing"""
    with print_lock:
        print(message)

def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='TLS Checker with ASN lookup')
    parser.add_argument('--mode', choices=['brief', 'standard', 'full'],
                        default=OUTPUT_MODE,
                        help='Output verbosity mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    return parser.parse_args()

def format_output(result: Dict, mode: str) -> str:
    """Format a single result dict according to the verbosity mode"""
    host = result['host']
    ip = result.get('ip', 'n/A')
    rtt = f"{result['rtt_ms']}ms" if result.get('rtt_ms') is not None else 'n/A'
    asn = result.get('asn', 'n/A')
    name = result.get('asn_name', '')
    cn = result.get('common_name', '')
    san_list = result.get('san_list', [])

    if mode == 'brief':
        return f"✅ {host} – {ip} – {rtt} – ASN{asn} ({name})"

    if mode == 'standard':
        san_preview = ', '.join(san_list[:3])
        if len(san_list) > 3:
            san_preview += ', ...'
        return (
            f"✅ {host} – {ip} – {rtt} – CN={cn} – ASN{asn} ({name})\n"
            f"    SANs: [{san_preview}]"
        )

    lines = [f"✅ {host} – {ip} – {rtt}"]
    lines.append(f"    CN: {cn}")
    lines.append(f"    SANs: [{', '.join(san_list)}]")
    lines.append(f"    ASN: {asn}")
    lines.append(f"    ASN Name: {name}")
    lines.append(f"    Prefix: {result.get('asn_prefix', '')}")
    lines.append(f"    Country: {result.get('asn_country', '')}")
    return '\n'.join(lines)

def load_hosts(filename: str = 'urls.txt') -> List[str]:
    """Load and validate hostnames from file"""
    hosts: List[str] = []
    try:
        with open(filename, 'r') as f:
            safe_print(f"🔄 Loading hosts from {filename}...")
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                if line.startswith(('http://', 'https://')):
                    safe_print(f"⚠️  Line {line_num}: Skipping URL format: {line}")
                    continue
                if not re.match(r'^[a-zA-Z0-9.-]+$', line):
                    safe_print(f"⚠️  Line {line_num}: Invalid hostname: {line}")
                    continue
                hosts.append(line)
    except FileNotFoundError:
        safe_print(f"❌ Error: {filename} not found")
        return []
    except Exception as e:
        safe_print(f"❌ Error reading {filename}: {e}")
        return []

    safe_print(f"📋 Found {len(hosts)} valid hosts to check\n")
    return hosts

def query_asn_cymru(ip: str) -> Dict[str, str]:
    """Lookup ASN info for an IP via Team Cymru WHOIS service"""
    with asn_cache_lock:
        if ip in iasn_cache:
            if DEBUG:
                safe_print(f"DEBUG: cache hit for {ip} -> {iasn_cache[ip]}")
            return iasn_cache[ip]

    raw_lines = []
    try:
        with socket.create_connection(('whois.cymru.com', 43), timeout=5) as sock:
            file = sock.makefile('rwb', buffering=0)
            query = f"begin\r\nverbose\r\n{ip}\r\nend\r\n"
            file.write(query.encode())
            while True:
                line = file.readline()
                if not line:
                    break
                raw_lines.append(line.decode('utf-8', errors='ignore'))

        if DEBUG:
            safe_print(f"DEBUG WHOIS response for {ip}:")
            for l in raw_lines:
                safe_print(f"  {l.strip()}")

        data_line = None
        for line in raw_lines:
            if '|' not in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 7 or not parts[0].isdigit():
                continue
            data_line = line
            break
        if not data_line:
            raise ValueError("No ASN data found in WHOIS response")

        parts = [p.strip() for p in data_line.split('|')]
        asn, _, prefix, country, *_ , as_name = parts
        result = {'asn': asn, 'asn_name': as_name, 'asn_country': country, 'asn_prefix': prefix}
    except Exception as e:
        if DEBUG:
            safe_print(f"DEBUG ASN lookup error for {ip}: {e}")
        result = {'asn': 'n/A', 'asn_name': 'n/A', 'asn_country': 'n/A', 'asn_prefix': 'n/A'}

    with asn_cache_lock:
        iasn_cache[ip] = result
    return result

def check_tls_host(host: str) -> Dict:
    """Check TLS connectivity, certificate info, and ASN for a single host"""
    safe_print(f"[{timestamp()}] 🔄 Checking {host}...")
    result = {'host': host, 'success': False, 'ip': None, 'rtt_ms': None,
              'common_name': None, 'san_list': [], 'asn': 'n/A', 'asn_name': 'n/A',
              'asn_prefix': '', 'asn_country': '', 'error': None}
    try:
        start = time.time()
        ip = socket.gethostbyname(host)
        result['ip'] = ip
        # ASN lookup remains metadata
        asn_info = query_asn_cymru(ip)
        result.update(asn_info)

        # Create SSL context that accepts any cert (we just care about handshake)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # Accept certificates without verification but still retrieve them
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((ip, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Mark reachability on successful TLS handshake
                result['rtt_ms'] = int((time.time() - start) * 1000)
                result['success'] = True
                # Parse certificate fields, but don’t override success on failure
                try:
                    cert = ssock.getpeercert()
                    subj = dict(x[0] for x in cert.get('subject', []))
                    result['common_name'] = subj.get('commonName', 'N/A')
                    result['san_list'] = [v for t, v in cert.get('subjectAltName', []) if t in ('DNS','IP Address')]
                except Exception as e:
                    if DEBUG:
                        safe_print(f"DEBUG cert parse error for {host}: {e}")
    except Exception as e:
        name = type(e).__name__
        if isinstance(e, ssl.SSLError): err = 'TLS_HANDSHAKE_FAILED'
        elif isinstance(e, socket.gaierror): err = 'DNS_RESOLUTION_FAILED'
        elif isinstance(e, socket.timeout): err = 'CONNECTION_TIMEOUT'
        elif isinstance(e, ConnectionRefusedError): err = 'CONNECTION_REFUSED'
        else: err = 'UNKNOWN_ERROR'
        result['error'] = f"{err}: {name}"
    return result

def main():
    args = parse_args()
    global DEBUG
    DEBUG = args.debug
    mode = args.mode
    print(f"🔒 TLS Checker - Starting in {mode} mode...\n")

    hosts = load_hosts('urls.txt')
    if not hosts:
        return

    max_threads = min(max(len(hosts)//4, 5), 20)
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        for res in ex.map(check_tls_host, hosts):
            results.append(res)

    results.sort(key=lambda x: x['host'])
    safe_print("\n📊 Results:")
    for r in results:
        safe_print(format_output(r, mode))

    total = len(results)
    ok = sum(1 for r in results if r['success'])
    safe_print(f"\n📊 Summary: {total} checked, {ok} successful, {total-ok} failed")

if __name__ == "__main__":
    main()
