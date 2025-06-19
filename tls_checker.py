#!/usr/bin/env python3
"""
TLS Checker - Check TLS connectivity, latency, and certificate info for multiple hosts
Enhanced with Team Cymru ASN lookup (falls back to 'n/A' on failure).
Add DEBUG mode to inspect raw WHOIS responses for troubleshooting.
"""

import socket
import ssl
import time
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional

# Debug flag
debug = True  # Set to False for normal operation

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
    # Check cache first
    with asn_cache_lock:
        if ip in iasn_cache:
            if debug:
                safe_print(f"DEBUG: cache hit for {ip} -> {iasn_cache[ip]}")
            return iasn_cache[ip]

    raw_lines: List[str] = []
    try:
        # Connect to Team Cymru WHOIS
        with socket.create_connection(('whois.cymru.com', 43), timeout=5) as sock:
            file = sock.makefile('rwb', buffering=0)
            query = f"begin\r\nverbose\r\n{ip}\r\nend\r\n"
            file.write(query.encode())
            while True:
                line = file.readline()
                if not line:
                    break
                raw_lines.append(line.decode('utf-8', errors='ignore'))

        if debug:
            safe_print(f"DEBUG WHOIS response for {ip}:")
            for l in raw_lines:
                safe_print(f"  {l.strip()}")

        # Find the first valid data line: must contain '|' and at least 7 columns, starting with digits
        data_line = None
        for line in raw_lines:
            if '|' not in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 7:
                continue
            if not parts[0].isdigit():
                continue
            data_line = line
            break
        if not data_line:
            raise ValueError("No ASN data found in WHOIS response")

        parts = [p.strip() for p in data_line.split('|')]
        # Format: ASN | IP | BGP Prefix | CC | registry | allocated | AS Name
        asn, _, prefix, country, *_ , as_name = parts
        result = {
            'asn': asn,
            'asn_name': as_name,
            'asn_country': country,
            'asn_prefix': prefix
        }
    except Exception as e:
        if debug:
            safe_print(f"DEBUG ASN lookup error for {ip}: {e}")
        result = {
            'asn': 'n/A',
            'asn_name': 'n/A',
            'asn_country': 'n/A',
            'asn_prefix': 'n/A'
        }

    # Cache and return
    with asn_cache_lock:
        iasn_cache[ip] = result
    return result


def check_tls_host(host: str) -> Dict:
    """Check TLS connectivity, certificate info, and ASN for a single host"""
    safe_print(f"[{timestamp()}] 🔄 Checking {host}...")

    result = {'host': host,'success': False,'ip': None,'rtt_ms': None,'common_name': None,'san_list': [],'asn': 'n/A','asn_name': 'n/A','error': None,'formatted_output': None}
    try:
        start_time = time.time()
        ip = socket.gethostbyname(host)
        result['ip'] = ip

        asn_info = query_asn_cymru(ip)
        result['asn'] = asn_info['asn']
        result['asn_name'] = asn_info['asn_name']

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((ip, 443), timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                rtt_ms = int((time.time() - start_time) * 1000)
                result['rtt_ms'] = rtt_ms

                cert = tls_sock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                cn = subject.get('commonName', 'N/A')
                sans = [val for typ, val in cert.get('subjectAltName', []) if typ in ('DNS', 'IP Address')]

                result.update({'common_name': cn,'san_list': sans,'success': True})
                sans_str = ', '.join(sans) if sans else 'None'
                result['formatted_output'] = (
                    f"[{timestamp()}] ✅ {host} – {ip} – {rtt_ms}ms – "
                    f"CN={cn} – SANs=[{sans_str}] – ASN={result['asn']} ({result['asn_name']})"
                )
    except Exception as e:
        err = type(e).__name__
        if isinstance(e, ssl.SSLError):
            err_type = 'TLS_HANDSHAKE_FAILED'
        elif isinstance(e, socket.gaierror):
            err_type = 'DNS_RESOLUTION_FAILED'
        elif isinstance(e, socket.timeout):
            err_type = 'CONNECTION_TIMEOUT'
        elif isinstance(e, ConnectionRefusedError):
            err_type = 'CONNECTION_REFUSED'
        else:
            err_type = 'UNKNOWN_ERROR'
        result['error'] = f"{err_type}: {err}"
        result['formatted_output'] = f"[{timestamp()}] ❌ {host} – {result['error']}"

    return result


def main():
    print("🔒 TLS Checker - Starting...\n")
    hosts = load_hosts('urls.txt')
    if not hosts:
        return
    count = min(max(len(hosts) // 4, 5), 20)
    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=count) as ex:
        for res in ex.map(check_tls_host, hosts):
            results.append(res)
    results.sort(key=lambda x: x['host'])
    safe_print("\n📊 Results (sorted by hostname):")
    for r in results:
        safe_print(r['formatted_output'])
    total, succ = len(results), sum(1 for r in results if r['success'])
    safe_print(f"\n📊 Summary: {total} hosts checked, {succ} successful, {total-succ} failed")

if __name__ == "__main__":
    main()
