import argparse
import re
import sys
import requests
from requests.exceptions import (
    ConnectionError,
    Timeout,
    TooManyRedirects,
    SSLError,
    ChunkedEncodingError,
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import os
from tqdm import tqdm
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin
import warnings
import ipaddress

# Initialize colorama
init(autoreset=True)

# Ignore warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Global session for subdomain/live checks (fast, no SSL verify)
session = requests.Session()
session.verify = False
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

# ==================== BACKUP SCANNER CONFIG (10000x stronger) ====================
BACKUP_EXTENSIONS = [
    "",  # Important: allows exact filenames like .env, wp-config.php, dump.sql
    ".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2", ".gz", ".bz2",
    ".sql", ".bak", ".old", ".backup", ".tmp", ".temp", ".db", ".txt",
    ".php.bak", ".php.old", ".php~", ".asp.bak", ".aspx.bak", ".jsp.bak",
    ".env.bak", ".config.bak", ".yaml.bak", ".yml.bak", ".json.bak",
    ".swp", ".swo", ".inc.bak", ".cfm.bak"
]

# Strong built-in wordlist based on real HackerOne reports + common BB findings
# (wp-config.php.bak, .env, database dumps, gitlab dumps, jenkins, etc.)
DEFAULT_WORDS = [
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
    "current", "prod", "stage", "dev", "backup-latest", "full", "site"
]

# HTTP headers optimized for backup files (binary download)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/octet-stream,application/zip,application/x-rar-compressed,application/x-tar,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

PARTIAL_DOWNLOAD_SIZE = 1024

# Domain / IP validation
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+(:\d{1,5})?$"
)
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d{1,5})?$"
)

def sanitize_domain(domain):
    """Clean domain/IP (remove protocol, path, whitespace)"""
    domain = domain.strip()
    for prefix in ("https://", "http://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].strip()
    return domain

def validate_domain(domain):
    """Accept hostname or IPv4 (with optional port)"""
    if not domain:
        return False
    return DOMAIN_PATTERN.match(domain) is not None or IP_PATTERN.match(domain) is not None

def is_ip_addr(addr):
    """True if IPv4 (strip port if present)"""
    try:
        clean = addr.split(":")[0]
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

# ==================== SUBDOMAIN ENUM FUNCTIONS (from ex-js.py - optimized) ====================
def fetch_url(domain):
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            resp = session.get(url, timeout=8)
            resp.raise_for_status()
            return url, resp
        except:
            continue
    return None, None

def extract_js_links_and_inline(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    js_links = set()
    inline_scripts = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_links.add(urljoin(url, src))
        elif script.string:
            inline_scripts.append(script.string)
    return js_links, inline_scripts

def extract_subdomains(content, root_domain):
    pattern = rf'https?://((?:[a-zA-Z0-9\-]+\.)+){re.escape(root_domain)}'
    matches = re.findall(pattern, content)
    return set(match.rstrip('.') for match in matches)

def extract_csp_subdomains(headers, root_domain):
    csp_subdomains = set()
    pattern = rf'((?:[a-zA-Z0-9\-]+\.)+){re.escape(root_domain)}'
    for header in ['Content-Security-Policy', 'Content-Security-Policy-Report-Only']:
        if header in headers:
            csp_subdomains.update(re.findall(pattern, headers[header]))
    return set(sub.rstrip('.') for sub in csp_subdomains)

def scan_single_js(js_url, root_domain):
    try:
        res = session.get(js_url, timeout=8)
        return extract_subdomains(res.text, root_domain)
    except:
        return set()

def download_and_scan(js_urls, inline_scripts, html, headers, root_domain):
    all_subdomains = set()
    with ThreadPoolExecutor(max_workers=20) as executor:  # faster
        futures = [executor.submit(scan_single_js, url, root_domain) for url in js_urls]
        for future in as_completed(futures):
            all_subdomains.update(future.result())
    for script in inline_scripts:
        all_subdomains.update(extract_subdomains(script, root_domain))
    all_subdomains.update(extract_subdomains(html, root_domain))
    all_subdomains.update(extract_csp_subdomains(headers, root_domain))
    return all_subdomains

def recursive_scan(domain, max_depth=10):
    """Deep recursive JS + CSP + HTML subdomain enum (very fast)"""
    visited = set()
    found_subdomains = set()

    def _scan(current_domain, depth):
        if depth > max_depth or current_domain in visited:
            return
        visited.add(current_domain)
        print(f"[Depth {depth}] Scanning: {current_domain}")

        url, response = fetch_url(current_domain)
        if not response:
            return

        js_links, inline_scripts = extract_js_links_and_inline(url, response.text)
        subdomains = download_and_scan(js_links, inline_scripts, response.text, response.headers, domain)
        found_subdomains.update(subdomains)

        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(_scan, f"{sub}.{domain}", depth + 1)
                       for sub in subdomains if f"{sub}.{domain}" not in visited]
            for _ in as_completed(futures):
                pass

    _scan(domain, 0)
    return found_subdomains

def save_to_file(filepath, items):
    with open(filepath, "w", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(item + "\n")

def get_live_full_urls(domains_list):
    """Return clean live URLs (https:// or http://) - parallel + fast"""
    live_urls = []

    def check(sub):
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{sub}"
                resp = session.get(url, timeout=5)
                if resp.status_code < 400:
                    return url
            except:
                continue
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check, d) for d in domains_list]
        for future in as_completed(futures):
            res = future.result()
            if res:
                live_urls.append(res)
    return live_urls

# ==================== BACKUP SCANNER FUNCTIONS (improved + IP friendly) ====================
def is_valid_file(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=7, stream=True, allow_redirects=True)
        if response.status_code != 200:
            return False

        content_type = response.headers.get("Content-Type", "").lower()
        raw_content_length = response.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_content_length)
        except (ValueError, TypeError):
            content_length = 0

        if "text/html" in content_type or content_length < 512:
            return False

        chunk = next(response.iter_content(chunk_size=PARTIAL_DOWNLOAD_SIZE), b"")
        if chunk:
            return True

    except (ConnectionError, Timeout, SSLError, TooManyRedirects, ChunkedEncodingError, OSError):
        return False
    except requests.RequestException:
        return False
    return False

def generate_backup_urls(base_url, words, exts):
    """Generate ultra-strong backup URLs. Handles domains + IPs correctly."""
    base_url = base_url.rstrip("/")
    urls = set()
    hostname = base_url.split("://")[1].split("/")[0] if "://" in base_url else base_url

    # Base name only for real domains (NOT IPs)
    if not is_ip_addr(hostname):
        base_name = hostname.split(".")[0]
        for ext in exts:
            urls.add(f"{base_url}/{base_name}{ext}")

    # Wordlist (very strong)
    for word in words:
        urls.add(f"{base_url}/{word}")
        for ext in exts:
            urls.add(f"{base_url}/{word}{ext}")

    return list(urls)

def process_backup_scan(live_url, words, exts):
    """Scan one live base for backups (50 threads = very fast)"""
    host = live_url.split("://")[-1].split("/")[0].replace(".", "_").replace(":", "_").replace("/", "_")
    print(Style.BRIGHT + f"[*] Scanning backups → {live_url}")

    backup_urls = generate_backup_urls(live_url, words, exts)
    valid_links = []

    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(tqdm(
                executor.map(is_valid_file, backup_urls),
                total=len(backup_urls),
                desc=f"Backups {host[:25]}",
                ncols=100,
                leave=False
            ))
            for url, is_valid in zip(backup_urls, results):
                if is_valid:
                    print(Fore.GREEN + f"[200] Valid backup: {url}")
                    valid_links.append(url)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Backup scan interrupted...")

    if valid_links:
        file_name = f"{host}_valid_backup_links.txt"
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                for link in valid_links:
                    f.write(link + "\n")
            print(Fore.YELLOW + f"[*] {len(valid_links)} backups saved → {file_name}")
        except Exception as e:
            print(Fore.RED + f"[!] Save error {file_name}: {e}")
    else:
        print(Fore.RED + f"[*] No backups found for {live_url}")

# ==================== DO SUBDOMAIN ENUM + LIVE (with folder save) ====================
def do_subdomain_enum(domain):
    """Phase 1 for one domain: sub enum + live check + save files"""
    folder = domain.replace(":", "_")  # safe for port
    if not os.path.exists(folder):
        os.makedirs(folder)

    print(f"[*] Starting DEEP subdomain scan for {domain}")
    sub_prefixes = recursive_scan(domain)

    full_subs = [f"{s}.{domain}" for s in sub_prefixes]
    print(f"\n[+] Total Unique Subdomains: {len(full_subs)}")

    sub_file = os.path.join(folder, f"{domain}_subdomains.txt")
    save_to_file(sub_file, full_subs)
    print(f"[+] Subdomains saved → {sub_file}")

    # Live check (main + all subs)
    print("[*] Checking live status...")
    domains_for_live = full_subs + [domain]
    live_results = []

    def check_live_with_status(sub):
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{sub}"
                resp = session.get(url, timeout=5)
                if resp.status_code < 400:
                    return f"{url} - {resp.status_code}"
            except:
                continue
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check_live_with_status, d) for d in domains_for_live]
        for future in as_completed(futures):
            r = future.result()
            if r:
                live_results.append(r)

    live_file = os.path.join(folder, f"{domain}_live_subdomains.txt")
    save_to_file(live_file, live_results)
    print(f"[+] Live subdomains saved → {live_file}")

    # Return clean live URLs for Phase 2
    clean_live = [res.split(" - ")[0] for res in live_results]
    return clean_live

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        description="Handala.py - Ultimate Bug Bounty Tool (Subdomain Enum + Backup Finder)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-t', '--target', help='Single target (domain or IP)')
    group.add_argument('-l', '--list', help='File with domains/IPs → FULL scan (Phase 1+2)')
    parser.add_argument('-ld', '--direct-list', help='File with domains/IPs → DIRECT backup scan ONLY (skip Phase 1)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist (optional - uses strong built-in)')

    args = parser.parse_args()

    if not (args.target or args.list or args.direct_list):
        parser.error("Provide -t or -l or -ld")

    # Wordlist (built-in is 10000x stronger than original)
    if args.wordlist:
        user_words = []
        try:
            with open(args.wordlist, "r", encoding="utf-8") as f:
                user_words = [line.strip() for line in f if line.strip()]
        except:
            print(Fore.RED + f"[!] Wordlist not found, using built-in only")
        all_words = list(set(user_words + DEFAULT_WORDS))
    else:
        all_words = DEFAULT_WORDS[:]

    print(Fore.YELLOW + f"[*] Using {len(all_words)} backup words (strong BB list)")

    # Load & sanitize targets
    full_targets = []
    if args.target:
        d = sanitize_domain(args.target)
        if validate_domain(d) or is_ip_addr(d):
            full_targets = [d]
        else:
            print(Fore.RED + f"[!] Invalid target {args.target}")
            sys.exit(1)
    elif args.list:
        raws = []
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                raws = [line.strip() for line in f if line.strip()]
        except:
            print(Fore.RED + f"[!] List file not found")
            sys.exit(1)
        for r in raws:
            d = sanitize_domain(r)
            if validate_domain(d) or is_ip_addr(d):
                full_targets.append(d)
            else:
                print(Fore.RED + f"[!] Skipping invalid: {r}")

    direct_targets = []
    if args.direct_list:
        raws = []
        try:
            with open(args.direct_list, "r", encoding="utf-8") as f:
                raws = [line.strip() for line in f if line.strip()]
        except:
            print(Fore.RED + f"[!] Direct list file not found")
            sys.exit(1)
        for r in raws:
            d = sanitize_domain(r)
            if validate_domain(d) or is_ip_addr(d):
                direct_targets.append(d)
            else:
                print(Fore.RED + f"[!] Skipping invalid: {r}")

    if not full_targets and not direct_targets:
        print(Fore.RED + "[!] No valid targets!")
        sys.exit(1)

    # PHASE 1: Subdomain Enumeration
    print(Fore.YELLOW + "\n" + "="*60)
    print("PHASE 1: SUBDOMAIN ENUMERATION")
    print("="*60 + "\n")

    all_live_urls = []
    for tgt in full_targets:
        if is_ip_addr(tgt):
            print(Fore.YELLOW + f"[*] IP target {tgt} → skipping sub enum")
            live = get_live_full_urls([tgt])
        else:
            live = do_subdomain_enum(tgt)
        all_live_urls.extend(live)

    if direct_targets:
        print(Fore.YELLOW + f"[*] {len(direct_targets)} direct targets → backup only")
        direct_live = get_live_full_urls(direct_targets)
        all_live_urls.extend(direct_live)

    all_live_urls = list(dict.fromkeys(all_live_urls))  # dedup preserve order
    print(Fore.GREEN + f"[+] Total live bases ready for backup scan: {len(all_live_urls)}")

    # PHASE 2: Backup scanning
    print(Fore.YELLOW + "\n" + "="*60)
    print("PHASE 2: BACKUP FILE SCANNING (very fast)")
    print("="*60 + "\n")

    for live_url in tqdm(all_live_urls, desc="Live domains", ncols=100):
        process_backup_scan(live_url, all_words, BACKUP_EXTENSIONS)

    # PHASE 3
    print(Fore.GREEN + "\n" + "="*60)
    print("PHASE 3: DONE - All results saved!")
    print("="*60)
    print(Fore.GREEN + "[*] Files created:")
    print("   • *_valid_backup_links.txt (per live host)")
    print("   • domain_folder/{domain}_subdomains.txt")
    print("   • domain_folder/{domain}_live_subdomains.txt")
    print(Fore.GREEN + "[*] Tool optimized for CDNs, IPs, and real bug bounty speed.")


if __name__ == "__main__":
    main()
