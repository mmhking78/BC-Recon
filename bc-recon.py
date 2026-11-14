
#!/usr/bin/env python3

"""
BC-Recon: Mini Reconnaissance Tool

Combines:
Lab 1 - Multi-threaded Port Scanner
Lab 2 - Service Banner Grabber
Lab 3 - HTTP Security Header Auditor

Authorized targets only.
"""

import argparse
import socket
import ssl
import requests
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


# ==================================================
# 1. CONFIGURATION & SCOPE ALLOWLIST
# ==================================================

# Only add targets for which you have explicit permission.
ALLOWED_TARGETS = {
    "bytecapsuleit.com",
}

REQUIRED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

LEAKY = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
]


# ==================================================
# 2. LOGGING
# ==================================================

logging.basicConfig(
    filename="bc-recon.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log(message):
    print(message)
    logging.info(message)


# ==================================================
# 3. ARGPARSE
# ==================================================

def parse_ports(value):

    try:
        start, end = map(int, value.split("-"))

        if not (1 <= start <= end <= 65535):
            raise ValueError

        return start, end

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use a valid range, e.g. 20-443"
        )


parser = argparse.ArgumentParser(
    description="BC-Recon Mini Reconnaissance Tool"
)

parser.add_argument(
    "target",
    help="Target hostname (authorized only)"
)

parser.add_argument(
    "-p", "--ports",
    default="1-1024",
    type=parse_ports,
    help="Port range, e.g. 20-443"
)

parser.add_argument(
    "-o", "--output",
    default="report.json",
    help="JSON report filename"
)

parser.add_argument(
    "-t", "--timeout",
    type=float,
    default=1.0,
    help="Connection timeout"
)

args = parser.parse_args()


# ==================================================
# 4. SCOPE CHECK
# ==================================================

def scope_check(target):

    target = target.lower().rstrip(".")

    if target not in ALLOWED_TARGETS:

        log(f"[-] SCOPE BLOCKED: {target}")

        return False

    log(f"[+] Scope verified: {target}")

    return True


# ==================================================
# 5. PORT RANGE
# ==================================================

start_port, end_port = args.ports

ports = range(start_port, end_port + 1)


# ==================================================
# 6. MULTI-THREADED PORT SCANNER
# LAB 1 - PAGE 21
# ==================================================

def check_port(host, port, timeout):

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            if result == 0:

                log(f"[+] OPEN: {port}")

                return port

    except OSError as error:

        logging.warning(
            "Port %s: %s", port, error
        )

    return None


def scan_ports(host, port_list, timeout):

    log("[*] Starting threaded port scan...")

    with ThreadPoolExecutor(max_workers=50) as pool:

        results = pool.map(
            lambda p: check_port(host, p, timeout),
            port_list
        )

    return sorted(
        port for port in results if port is not None
    )


# ==================================================
# 7. SERVICE BANNER GRABBER
# LAB 2 - PAGE 23
# ==================================================

def grab_banner(host, port, timeout):

    try:

        with socket.create_connection(
            (host, port),
            timeout=timeout
        ) as sock:

            sock.settimeout(timeout)

            if port == 443:

                context = ssl.create_default_context()

                with context.wrap_socket(
                    sock,
                    server_hostname=TARGET
                ) as secure_sock:

                    secure_sock.sendall(
                        b"HEAD / HTTP/1.0\r\n"
                        b"Host: " + TARGET.encode() +
                        b"\r\nConnection: close\r\n\r\n"
                    )

                    data = secure_sock.recv(2048)

            elif port in (80, 8080):

                sock.sendall(
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: " + TARGET.encode() +
                    b"\r\nConnection: close\r\n\r\n"
                )

                data = sock.recv(2048)

            else:

                data = sock.recv(2048)

            return data.decode(
                "utf-8",
                errors="replace"
            ).strip()

    except (OSError, ssl.SSLError) as error:

        return f"Banner unavailable: {type(error).__name__}"


# ==================================================
# 8. HTTP SECURITY HEADER AUDITOR
# LAB 3 - PAGE 24
# ==================================================

def audit_headers(target, port, timeout):

    scheme = "https" if port == 443 else "http"

    url = f"{scheme}://{target}:{port}/"

    result = {
        "url": url,
        "status_code": None,
        "security_headers": {},
        "missing_headers": [],
        "information_leaks": {},
        "error": None
    }

    try:

        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=True
        )

        result["status_code"] = response.status_code

        headers = response.headers

        log(f"[+] HEADER AUDIT: {url}")
        log(f"[i] HTTP Status: {response.status_code}")

        # Check required security headers

        for header in REQUIRED:

            present = header in headers

            result["security_headers"][header] = present

            if present:

                log(f"[+] PRESENT: {header}")

            else:

                log(f"[-] MISSING: {header}")

                result["missing_headers"].append(header)

        # Check information disclosure

        for header in LEAKY:

            if header in headers:

                value = headers[header]

                result["information_leaks"][header] = value

                log(f"[!] INFO LEAK: {header}: {value}")

    except requests.RequestException as error:

        result["error"] = str(error)

        log(f"[-] Header audit failed: {error}")

    return result


# ==================================================
# 9. JSON REPORT GENERATOR
# ==================================================

def save_report(report, filename):

    path = Path(filename)

    path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    log(f"[+] Report saved: {path}")


# ==================================================
# 10. MAIN FUNCTION
# ==================================================

def main():

    global TARGET

    TARGET = args.target.lower().rstrip(".")

    report = {
        "tool": "BC-Recon",
        "target": TARGET,
        "started_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "scope": "not_checked",
        "resolved_ip": None,
        "open_ports": [],
        "banners": {},
        "header_audits": {},
        "status": "started"
    }

    log("=" * 55)
    log("       BC-RECON MINI RECONNAISSANCE TOOL")
    log("=" * 55)

    log(f"[*] Target: {TARGET}")

    # Scope check BEFORE DNS or network activity

    if not scope_check(TARGET):

        report["scope"] = "rejected"
        report["status"] = "blocked"

        report["finished_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        save_report(report, args.output)

        sys.exit(2)

    report["scope"] = "approved"

    try:

        # DNS resolution after scope validation

        ip = socket.gethostbyname(TARGET)

        report["resolved_ip"] = ip

        log(f"[+] Resolved IP: {ip}")

        # Port scanning

        open_ports = scan_ports(
            ip,
            ports,
            args.timeout
        )

        report["open_ports"] = open_ports

        log(f"[*] Open ports found: {len(open_ports)}")

        # Banner grabbing every open port

        for port in open_ports:

            log(f"[*] Grabbing banner: {port}")

            banner = grab_banner(
                ip,
                port,
                args.timeout
            )

            report["banners"][str(port)] = banner

            log(f"[i] Banner: {banner[:100]}")

        # Header audit for HTTP ports

        for port in (80, 443, 8080):

            if port in open_ports:

                audit = audit_headers(
                    TARGET,
                    port,
                    args.timeout
                )

                report["header_audits"][str(port)] = audit

        report["status"] = "completed"

    except OSError as error:

        report["status"] = "error"
        report["error"] = str(error)

        log(f"[-] Scan error: {error}")

    finally:

        report["finished_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        save_report(report, args.output)

        log("=" * 55)
        log("[+] BC-Recon finished")
        log("=" * 55)


if __name__ == "__main__":

    main()
