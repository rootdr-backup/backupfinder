#!/usr/bin/env python3
"""
BackupFinder - Ultimate Bug Bounty Recon + Backup File Discovery Tool
=====================================================================

Features
--------
- Deep subdomain enumeration (HTML + JS + CSP recursive extraction)
- Live-host probing (HTTP/HTTPS with status codes)
- High-performance backup file discovery (HEAD + partial GET validation)
- Smart "soft 404" filtering, IP-aware URL generation
- User-tunable concurrency via `-threads`

Modes
-----
  -t   <target>        Full pipeline for a single domain/IP
  -l   <file>          Full pipeline for a list of domains/IPs
  -ld  <file>          Direct backup scan (skip subdomain phase)
  -sub <target|file>   Subdomain enumeration only (no backup phase)

Example
-------
    python exp.py -t example.com -threads 100
    python exp.py -l targets.txt -w wordlist.txt -threads 200
    python exp.py -sub example.com              # subdomains only
    python exp.py -sub targets.txt              # subdomains only (list)
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from colorama import Fore, Style, init as colorama_init
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
from tqdm import tqdm
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------- #
# Global setup
# --------------------------------------------------------------------------- #
colorama_init(autoreset=True)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

try:  # pragma: no cover - depends on urllib3 version
    from urllib3.exceptions import InsecureRequestWarning

    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except Exception:
    pass


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Empty string allows literal filenames like `.env`, `wp-config.php`, `dump.sql`.
BACKUP_EXTENSIONS: List[str] = [
    "",
    ".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".gz", ".bz2",
    ".sql", ".sql.gz", ".sql.zip", ".bak", ".old", ".backup", ".tmp", ".temp",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".txt", ".log",
    ".php.bak", ".php.old", ".php~", ".php.swp",
    ".asp.bak", ".aspx.bak", ".jsp.bak",
    ".env.bak", ".config.bak", ".yaml.bak", ".yml.bak", ".json.bak",
    ".swp", ".swo", ".inc.bak", ".cfm.bak", ".orig", ".save",
]

# Strong built-in wordlist drawn from real HackerOne / bug-bounty reports.
DEFAULT_WORDS: List[str] = [
    "backup", "backups", "bak", "old", "archive", "dump", "sql", "db", "database",
    "config", "conf", "settings", "env", ".env", "wp-config", "wp-config.php",
    "application", "data", "test", "dev", "prod", "admin", "user", "users",
    "payment", "payments", "order", "orders", "source", "code", "support",
    "secret", "secrets", "api", "pass", "passwords", "log", "logs", "report",
    "reports", "export", "exports", "mysql", "www", "php", "asp", "1", "123",
    "index", "index.php", "config.php", "database_backup", "fullbackup",
    "sitebackup", "db_backup", "backup_db", "dump.sql", "backup.sql", "data.sql",
    "users.sql", "admin.sql", "config.bak", "wp-config.bak", "wp-config.php.bak",
    ".env.bak", "core", "install", "setup", "debug", "phpinfo", "info.php",
    "test.php", "debug.log", "error.log", "access.log", "private", "secure",
    "confidential", "testdb", "proddb", "stagingdb", "backup_1", "dump_2024",
    "export_2025", "site.zip", "www.zip", "public", "internal", "temp", "tmpdb",
    "redis", "mongo", "postgres", "gitlab", "jenkins", "confluence", "latest",
    "current", "stage", "backup-latest", "full", "site",
]

BASE_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

PARTIAL_DOWNLOAD_SIZE = 1024
MIN_SIZE_WHEN_KNOWN = 64  # Accept small files like tiny .env; reject empties.

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+(:\d{1,5})?$"
)
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d{1,5})?$"
)


# --------------------------------------------------------------------------- #
# HTTP session
# --------------------------------------------------------------------------- #
def build_session(pool_size: int, timeout: float) -> requests.Session:
    """Build a tuned requests.Session with retries + large connection pool."""
    s = requests.Session()
    s.verify = False
    s.headers.update(BASE_HEADERS)
    retry = Retry(
        total=2,
        connect=2,
        read=1,
        backoff_factor=0.3,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.request_timeout = timeout  # type: ignore[attr-defined]
    return s


# --------------------------------------------------------------------------- #
# Domain helpers
# --------------------------------------------------------------------------- #
def sanitize_domain(domain: str) -> str:
    """Strip scheme, path, whitespace from a user-provided target."""
    domain = (domain or "").strip()
    for prefix in ("https://", "http://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split("/")[0].strip()


def validate_domain(domain: str) -> bool:
    if not domain:
        return False
    return bool(DOMAIN_PATTERN.match(domain) or IP_PATTERN.match(domain))


def is_ip_addr(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.split(":")[0])
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Subdomain enumeration
# --------------------------------------------------------------------------- #
def fetch_url(session: requests.Session, domain: str) -> Tuple[Optional[str], Optional[requests.Response]]:
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{domain}"
            resp = session.get(url, timeout=session.request_timeout, allow_redirects=True)
            if resp.status_code < 500:
                return url, resp
        except RequestException:
            continue
    return None, None


def extract_js_links_and_inline(url: str, html: str) -> Tuple[Set[str], List[str]]:
    soup = BeautifulSoup(html, "html.parser")
    js_links: Set[str] = set()
    inline_scripts: List[str] = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_links.add(urljoin(url, src))
        elif script.string:
            inline_scripts.append(script.string)
    return js_links, inline_scripts


def extract_subdomain_prefixes(content: str, root_domain: str) -> Set[str]:
    """Extract just the subdomain prefix (e.g. `api.v2` from `api.v2.example.com`)."""
    pattern = rf"(?:https?://)?((?:[a-zA-Z0-9\-]+\.)+){re.escape(root_domain)}\b"
    prefixes: Set[str] = set()
    for match in re.findall(pattern, content):
        prefix = match.rstrip(".")
        if prefix and not prefix.startswith("."):
            prefixes.add(prefix)
    return prefixes


def extract_csp_subdomains(headers, root_domain: str) -> Set[str]:
    out: Set[str] = set()
    for header in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
        if header in headers:
            out.update(extract_subdomain_prefixes(headers[header], root_domain))
    return out


def scan_single_js(session: requests.Session, js_url: str, root_domain: str) -> Set[str]:
    try:
        res = session.get(js_url, timeout=session.request_timeout)
        return extract_subdomain_prefixes(res.text, root_domain)
    except RequestException:
        return set()


def harvest_page(
    session: requests.Session,
    url: str,
    response: requests.Response,
    root_domain: str,
    threads: int,
) -> Set[str]:
    """Extract every subdomain prefix from a page's HTML, JS and CSP headers."""
    js_links, inline_scripts = extract_js_links_and_inline(url, response.text)
    found: Set[str] = set()
    found.update(extract_subdomain_prefixes(response.text, root_domain))
    found.update(extract_csp_subdomains(response.headers, root_domain))
    for script in inline_scripts:
        found.update(extract_subdomain_prefixes(script, root_domain))

    if js_links:
        with ThreadPoolExecutor(max_workers=min(threads, max(1, len(js_links)))) as ex:
            futures = [ex.submit(scan_single_js, session, u, root_domain) for u in js_links]
            for fut in as_completed(futures):
                found.update(fut.result())
    return found


def recursive_scan(
    session: requests.Session,
    domain: str,
    threads: int,
    max_depth: int = 3,
    verbose: bool = True,
) -> Set[str]:
    """Fast, bounded recursive subdomain enumeration."""
    visited: Set[str] = set()
    found: Set[str] = set()

    def _walk(host: str, depth: int) -> Set[str]:
        if depth > max_depth or host in visited:
            return set()
        visited.add(host)
        if verbose:
            print(f"  [depth {depth}] {host}")

        url, response = fetch_url(session, host)
        if not response:
            return set()
        return harvest_page(session, url, response, domain, threads)

    root_subs = _walk(domain, 0)
    found.update(root_subs)

    frontier = {f"{prefix}.{domain}" for prefix in root_subs}
    for depth in range(1, max_depth + 1):
        frontier = {h for h in frontier if h not in visited}
        if not frontier:
            break
        next_frontier: Set[str] = set()
        with ThreadPoolExecutor(max_workers=max(1, min(threads, len(frontier)))) as ex:
            futures = {ex.submit(_walk, host, depth): host for host in frontier}
            for fut in as_completed(futures):
                new_prefixes = fut.result()
                found.update(new_prefixes)
                for p in new_prefixes:
                    next_frontier.add(f"{p}.{domain}")
        frontier = next_frontier
    return found


# --------------------------------------------------------------------------- #
# Live-host probing
# --------------------------------------------------------------------------- #
def check_live(session: requests.Session, host: str) -> Optional[Tuple[str, int]]:
    """Return (url, status) for the first scheme that responds with <400."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = session.head(url, timeout=session.request_timeout, allow_redirects=True)
            code = resp.status_code
            if code in (405, 501):
                # Only retry with GET when HEAD itself is unsupported; a normal
                # 4xx response (404/403/...) already means the host is reachable
                # or the path is simply missing - no point in doubling traffic.
                resp = session.get(url, timeout=session.request_timeout,
                                   allow_redirects=True, stream=True)
                code = resp.status_code
                resp.close()
            if code < 400:
                return url, code
        except RequestException:
            continue
    return None


def probe_live_hosts(
    session: requests.Session, hosts: Iterable[str], threads: int,
) -> List[Tuple[str, int]]:
    hosts = list(dict.fromkeys(hosts))
    results: List[Tuple[str, int]] = []
    if not hosts:
        return results
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(hosts)))) as ex:
        futures = [ex.submit(check_live, session, h) for h in hosts]
        for fut in tqdm(as_completed(futures), total=len(futures),
                        desc="Live probe", ncols=100, leave=False):
            r = fut.result()
            if r:
                results.append(r)
    return results


# --------------------------------------------------------------------------- #
# Backup scanner
# --------------------------------------------------------------------------- #
def _looks_like_soft_404(chunk: bytes) -> bool:
    snippet = chunk[:512].lower()
    markers = (b"<html", b"<!doctype", b"not found", b"404", b"error page",
               b"<title>404", b"page not found")
    return any(m in snippet for m in markers)


def is_valid_backup(session: requests.Session, url: str) -> bool:
    """HEAD probe first, fall back to partial GET for final confirmation."""
    try:
        head = session.head(url, timeout=session.request_timeout,
                            allow_redirects=True)
    except RequestException:
        return False

    status = head.status_code
    if status in (405, 501):
        pass  # HEAD unsupported - fall through to GET.
    elif status != 200:
        return False
    else:
        ctype = head.headers.get("Content-Type", "").lower()
        if "text/html" in ctype:
            return False

    try:
        resp = session.get(url, headers={"Range": f"bytes=0-{PARTIAL_DOWNLOAD_SIZE - 1}"},
                           timeout=session.request_timeout, stream=True,
                           allow_redirects=True)
    except RequestException:
        return False

    try:
        if resp.status_code not in (200, 206):
            return False

        ctype = resp.headers.get("Content-Type", "").lower()
        if "text/html" in ctype:
            return False

        try:
            clen = int(resp.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            clen = 0
        if clen and clen < MIN_SIZE_WHEN_KNOWN:
            return False

        chunk = next(resp.iter_content(chunk_size=PARTIAL_DOWNLOAD_SIZE), b"")
        if not chunk:
            return False
        if _looks_like_soft_404(chunk):
            return False
        return True
    finally:
        resp.close()


def generate_backup_urls(base_url: str, words: Iterable[str], exts: Iterable[str]) -> List[str]:
    base_url = base_url.rstrip("/")
    urls: Set[str] = set()
    hostname = base_url.split("://", 1)[-1].split("/", 1)[0]

    if not is_ip_addr(hostname):
        base_name = hostname.split(":")[0].split(".")[0]
        if base_name:
            for ext in exts:
                urls.add(f"{base_url}/{base_name}{ext}")

    for word in words:
        if not word:
            continue
        urls.add(f"{base_url}/{word}")
        for ext in exts:
            urls.add(f"{base_url}/{word}{ext}")

    return sorted(urls)


def _host_slug(live_url: str) -> str:
    host = live_url.split("://", 1)[-1].split("/", 1)[0]
    return host.replace(":", "_").replace(".", "_")


def process_backup_scan(
    session: requests.Session,
    live_url: str,
    words: List[str],
    exts: List[str],
    threads: int,
    output_dir: str,
) -> List[str]:
    """Scan a single live host for backup files."""
    slug = _host_slug(live_url)
    print(Style.BRIGHT + f"[*] Scanning backups -> {live_url}")

    backup_urls = generate_backup_urls(live_url, words, exts)
    valid_links: List[str] = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(is_valid_backup, session, u): u
                       for u in backup_urls}
            progress = tqdm(as_completed(futures), total=len(futures),
                            desc=f"Backups {slug[:24]}", ncols=100, leave=False)
            for fut in progress:
                url = futures[fut]
                try:
                    if fut.result():
                        print(Fore.GREEN + f"[HIT] {url}")
                        valid_links.append(url)
                except Exception:  # noqa: BLE001 - defensive; worker errors shouldn't abort the run
                    continue
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Backup scan interrupted.")

    if valid_links:
        os.makedirs(output_dir, exist_ok=True)
        file_name = os.path.join(output_dir, f"{slug}_valid_backup_links.txt")
        with open(file_name, "w", encoding="utf-8") as f:
            for link in sorted(valid_links):
                f.write(link + "\n")
        print(Fore.YELLOW + f"[*] {len(valid_links)} backups -> {file_name}")
    else:
        print(Fore.RED + f"[-] No backups found for {live_url}")
    return valid_links


# --------------------------------------------------------------------------- #
# Phase 1 orchestration
# --------------------------------------------------------------------------- #
def save_to_file(filepath: str, items: Iterable[str]) -> None:
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        for item in sorted(set(items)):
            f.write(item + "\n")


def do_subdomain_enum(
    session: requests.Session,
    domain: str,
    threads: int,
    output_dir: str,
    max_depth: int,
) -> List[str]:
    """Phase 1: enumerate subdomains for one domain + probe live hosts."""
    folder = os.path.join(output_dir, domain.replace(":", "_"))
    os.makedirs(folder, exist_ok=True)

    print(Fore.CYAN + f"[*] Deep subdomain scan: {domain}")
    prefixes = recursive_scan(session, domain, threads=threads, max_depth=max_depth)

    full_subs = sorted({f"{p}.{domain}" for p in prefixes})
    print(Fore.CYAN + f"[+] Unique subdomains: {len(full_subs)}")

    sub_file = os.path.join(folder, f"{domain}_subdomains.txt")
    save_to_file(sub_file, full_subs)
    print(Fore.CYAN + f"[+] Saved -> {sub_file}")

    print(Fore.CYAN + "[*] Probing live hosts ...")
    live = probe_live_hosts(session, full_subs + [domain], threads)
    live_file = os.path.join(folder, f"{domain}_live_subdomains.txt")
    with open(live_file, "w", encoding="utf-8") as f:
        for url, code in sorted(live):
            f.write(f"{url} - {code}\n")
    print(Fore.CYAN + f"[+] Live hosts: {len(live)} -> {live_file}")

    return [url for url, _ in live]


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #
def _read_targets_from_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.lstrip().startswith("#")]
    except OSError:
        print(Fore.RED + f"[!] Could not read file: {path}")
        sys.exit(1)


def _normalize_targets(raws: Iterable[str]) -> List[str]:
    out: List[str] = []
    for raw in raws:
        d = sanitize_domain(raw)
        if validate_domain(d):
            out.append(d)
        else:
            print(Fore.RED + f"[!] Skipping invalid target: {raw}")
    return list(dict.fromkeys(out))


def _parse_targets(value: str) -> List[str]:
    """Accept either a single domain/IP or a path to a file containing targets."""
    if os.path.isfile(value):
        return _normalize_targets(_read_targets_from_file(value))
    return _normalize_targets([value])


def _load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return DEFAULT_WORDS[:]
    try:
        with open(path, "r", encoding="utf-8") as f:
            user_words = [line.strip() for line in f if line.strip()]
    except OSError:
        print(Fore.RED + f"[!] Wordlist '{path}' not found. Using built-in list.")
        return DEFAULT_WORDS[:]
    return list(dict.fromkeys(user_words + DEFAULT_WORDS))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exp.py",
        description=(
            "BackupFinder - subdomain enumeration + backup file discovery.\n"
            "Use -sub for subdomain-only mode, -ld to skip straight to the "
            "backup scan, or -t/-l for the full pipeline."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--target",
                       help="Single target (domain or IP) - runs Phase 1 + Phase 2")
    group.add_argument("-l", "--list",
                       help="File with domains/IPs - runs Phase 1 + Phase 2")
    group.add_argument("-ld", "--direct-list",
                       help="File with live domains/IPs - direct backup scan only")
    group.add_argument("-sub", "--subdomains",
                       metavar="TARGET",
                       help="Single domain OR a file of domains - SUBDOMAIN enum only")

    parser.add_argument("-w", "--wordlist",
                        help="Custom wordlist (merged with the strong built-in list)")
    parser.add_argument("-T", "-threads", "--threads", type=int, default=50,
                        dest="threads",
                        help="Number of concurrent workers (default: 50)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--max-depth", type=int, default=3,
                        help="Recursive subdomain enumeration depth (default: 3)")
    parser.add_argument("-o", "--output", default=".",
                        help="Output directory for results (default: current dir)")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not (args.target or args.list or args.direct_list or args.subdomains):
        parser.error("Provide one of: -t, -l, -ld, -sub")

    if args.threads < 1:
        parser.error("--threads must be >= 1")

    session = build_session(pool_size=max(args.threads, 10), timeout=args.timeout)
    os.makedirs(args.output, exist_ok=True)

    # --------------------------------------------------------------- -sub mode
    if args.subdomains:
        targets = _parse_targets(args.subdomains)
        if not targets:
            print(Fore.RED + "[!] No valid targets.")
            sys.exit(1)

        print(Fore.YELLOW + "\n" + "=" * 60)
        print("SUBDOMAIN ENUMERATION MODE (-sub)")
        print("=" * 60)
        for tgt in targets:
            if is_ip_addr(tgt):
                print(Fore.YELLOW + f"[!] {tgt} is an IP - skipping (nothing to enumerate).")
                continue
            do_subdomain_enum(session, tgt, threads=args.threads,
                              output_dir=args.output, max_depth=args.max_depth)
        print(Fore.GREEN + "\n[+] Subdomain scan complete.")
        return

    all_words = _load_wordlist(args.wordlist)
    print(Fore.YELLOW + f"[*] Using {len(all_words)} backup words, "
                       f"{len(BACKUP_EXTENSIONS)} extensions, "
                       f"{args.threads} threads.")

    full_targets: List[str] = []
    if args.target:
        full_targets = _normalize_targets([args.target])
    elif args.list:
        full_targets = _normalize_targets(_read_targets_from_file(args.list))

    direct_targets: List[str] = []
    if args.direct_list:
        direct_targets = _normalize_targets(_read_targets_from_file(args.direct_list))

    if not full_targets and not direct_targets:
        print(Fore.RED + "[!] No valid targets!")
        sys.exit(1)

    # --------------------------------------------------------- Phase 1
    print(Fore.YELLOW + "\n" + "=" * 60)
    print("PHASE 1: SUBDOMAIN ENUMERATION")
    print("=" * 60)

    all_live_urls: List[str] = []
    for tgt in full_targets:
        if is_ip_addr(tgt):
            print(Fore.YELLOW + f"[*] IP target {tgt} -> skipping sub enum")
            live = probe_live_hosts(session, [tgt], args.threads)
            all_live_urls.extend(u for u, _ in live)
        else:
            all_live_urls.extend(
                do_subdomain_enum(session, tgt, threads=args.threads,
                                  output_dir=args.output, max_depth=args.max_depth)
            )

    if direct_targets:
        print(Fore.YELLOW + f"[*] {len(direct_targets)} direct targets -> backup only")
        direct_live = probe_live_hosts(session, direct_targets, args.threads)
        all_live_urls.extend(u for u, _ in direct_live)

    all_live_urls = list(dict.fromkeys(all_live_urls))
    print(Fore.GREEN + f"[+] Total live bases for backup scan: {len(all_live_urls)}")

    if not all_live_urls:
        print(Fore.RED + "[!] No live hosts - nothing to scan for backups.")
        return

    # --------------------------------------------------------- Phase 2
    print(Fore.YELLOW + "\n" + "=" * 60)
    print("PHASE 2: BACKUP FILE SCANNING")
    print("=" * 60)

    for live_url in tqdm(all_live_urls, desc="Live hosts", ncols=100):
        process_backup_scan(session, live_url, all_words, BACKUP_EXTENSIONS,
                            threads=args.threads, output_dir=args.output)

    # --------------------------------------------------------- Phase 3
    print(Fore.GREEN + "\n" + "=" * 60)
    print("PHASE 3: DONE - All results saved!")
    print("=" * 60)
    print(Fore.GREEN + "[*] Files created:")
    print(f"   - {args.output}/*_valid_backup_links.txt  (per live host)")
    print(f"   - {args.output}/<domain>/<domain>_subdomains.txt")
    print(f"   - {args.output}/<domain>/<domain>_live_subdomains.txt")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Interrupted by user.")
        sys.exit(130)
