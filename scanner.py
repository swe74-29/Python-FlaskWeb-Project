import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common service names for a nicer results string — extend as you like
COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 27017: "mongodb", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 5000: "dev-server", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch",
}


def resolve_host(target):
    """Turn a hostname into an IP address (raises socket.gaierror if invalid)."""
    return socket.gethostbyname(target)


def _check_tcp_port(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        return ('open', port) if result == 0 else None


def _check_udp_port(ip, port, timeout):
    # UDP is connectionless, so there's no reliable way to confirm "open" without
    # a reply. A timeout could mean open, or could mean the platform/firewall
    # (Windows in particular) is silently dropping the ICMP unreachable that
    # would normally tell us the port is closed. We report that case separately
    # instead of guessing it's open.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"", (ip, port))
            s.recvfrom(1024)
            return ('open', port)        # got a reply -> definitely open
        except socket.timeout:
            return ('ambiguous', port)   # no response -> can't confirm either way
        except (ConnectionResetError, OSError):
            return None                  # ICMP unreachable -> closed


def scan_ports(target, port_start, port_end, mode="tcp", timeout=1.0, max_threads=100):
    """
    Scan `target` from port_start to port_end (inclusive) using the given mode
    ('tcp', 'udp', or 'full').

    Returns (ip_address, open_ports, ambiguous_ports):
      open_ports      -> confirmed open (TCP connect succeeded, or UDP got a reply)
      ambiguous_ports -> UDP ports with no response — could be open or filtered,
                          genuinely can't be told apart without more probing
    """
    ip = resolve_host(target)
    ports = range(port_start, port_end + 1)
    open_ports = set()
    ambiguous_ports = set()

    check_fns = []
    if mode in ("tcp", "full"):
        check_fns.append(_check_tcp_port)
    if mode in ("udp", "full"):
        check_fns.append(_check_udp_port)

    for check_fn in check_fns:
        with ThreadPoolExecutor(max_workers=max_threads) as pool:
            futures = {pool.submit(check_fn, ip, p, timeout): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                status, port = result
                if status == 'open':
                    open_ports.add(port)
                elif status == 'ambiguous':
                    ambiguous_ports.add(port)

    ambiguous_ports -= open_ports  # don't double-list a port that's also confirmed open
    return ip, sorted(open_ports), sorted(ambiguous_ports)


def classify_ports(open_ports):
    """
    Split a list of open ports into two groups:
      known   -> [(port, service_name), ...]  e.g. [(22, 'ssh'), (80, 'http')]
      unknown -> [port, ...]                  ports not in COMMON_PORTS
    Both lists are sorted by port number.
    """
    known = []
    unknown = []
    for port in sorted(open_ports):
        if port in COMMON_PORTS:
            known.append((port, COMMON_PORTS[port]))
        else:
            unknown.append(port)
    return known, unknown


def format_ports(open_ports):
    """Turn [22, 80, 443] into 'ssh(22), http(80), https(443)' for display/storage."""
    if not open_ports:
        return ""
    return ", ".join(
        f"{COMMON_PORTS.get(p, '?')}({p})" for p in open_ports
    )
