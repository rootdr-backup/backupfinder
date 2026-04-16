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
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import os
from tqdm import tqdm

# Initialize colorama for colored console output
init(autoreset=True)

# Backup file extensions to check
BACKUP_EXTENSIONS = [
    ".zip", ".rar", ".sql", ".bak",
    ".tar.gz", ".tar", ".7z", ".gz",
    ".backup", ".old", ".db",
    ".txt"  # Commonly used for database dumps
]

# HTTP headers to simulate browser behavior
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/octet-stream,application/zip,application/x-rar-compressed,application/x-tar,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

# Maximum bytes to download for partial file inspection
PARTIAL_DOWNLOAD_SIZE = 1024  # 1 KB

# Simple domain validation pattern (allows subdomains, TLDs, and optional port)
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+(:\d{1,5})?$"
)


def sanitize_domain(domain):
    """Strip protocol prefixes, trailing slashes/whitespace, and return a clean hostname."""
    domain = domain.strip()
    # Remove protocol prefix if present
    for prefix in ("https://", "http://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    # Remove trailing slashes and path components
    domain = domain.split("/")[0].strip()
    return domain


def validate_domain(domain):
    """Return True if *domain* looks like a valid hostname (with optional port)."""
    if not domain:
        return False
    return DOMAIN_PATTERN.match(domain) is not None


# Function to check if a domain is reachable
def is_domain_alive(domain):
    try:
        response = requests.get(f"http://{domain}", headers=HEADERS, timeout=5)
        return response.status_code == 200
    except ConnectionError:
        print(Fore.RED + f"[!] Connection failed for {domain}: could not establish a connection (DNS failure or host unreachable)")
        return False
    except Timeout:
        print(Fore.RED + f"[!] Connection timed out for {domain}: the server did not respond within 5 seconds")
        return False
    except SSLError as e:
        print(Fore.RED + f"[!] SSL error for {domain}: {e}")
        return False
    except TooManyRedirects:
        print(Fore.RED + f"[!] Too many redirects for {domain}: the server redirected too many times")
        return False
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Unexpected request error for {domain}: {e}")
        return False

# Function to generate backup file URLs for a domain
def generate_urls(domain, wordlist):
    base_name = domain.split(".")[0]  # Simplified base name extraction
    urls = []

    # Add URLs based on backup extensions
    for ext in BACKUP_EXTENSIONS:
        urls.append(f"http://{domain}/{base_name}{ext}")

    # Add URLs based on wordlist
    for word in wordlist:
        for ext in BACKUP_EXTENSIONS:
            urls.append(f"http://{domain}/{word}{ext}")

    return urls

# Function to check if a URL contains a valid downloadable file
def is_valid_file(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=7, stream=True)
        if response.status_code != 200:
            return False

        content_type = response.headers.get("Content-Type", "").lower()

        # Safely parse Content-Length — treat malformed values as 0
        raw_content_length = response.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_content_length)
        except (ValueError, TypeError):
            content_length = 0

        # Validate content type and length
        if "text/html" in content_type or content_length < 512:
            return False

        # Partial download for deeper inspection
        try:
            chunk = next(response.iter_content(chunk_size=PARTIAL_DOWNLOAD_SIZE), b"")
        except ChunkedEncodingError as e:
            print(Fore.RED + f"[!] Error reading response stream for {url}: {e}")
            return False
        except OSError as e:
            if isinstance(e, requests.RequestException):
                raise
            print(Fore.RED + f"[!] Error reading response stream for {url}: {e}")
            return False

        if chunk:  # Assume valid if we can read a non-empty chunk
            return True

    except ConnectionError:
        return False
    except Timeout:
        return False
    except SSLError:
        return False
    except TooManyRedirects:
        return False
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Unexpected error checking {url}: {e}")
        return False

    return False

# Function to process a single domain
def process_domain(domain, wordlist):
    if not is_domain_alive(domain):
        print(Fore.RED + f"[!] Domain not reachable: {domain}")
        return

    print(Style.BRIGHT + f"[*] Scanning domain: {domain}")
    urls = generate_urls(domain, wordlist)
    valid_links = []

    try:
        with ThreadPoolExecutor(max_workers=30) as executor:
            for url, is_valid in zip(urls, tqdm(executor.map(is_valid_file, urls), total=len(urls), desc="Scanning", ncols=100)):
                if is_valid:
                    print(Fore.GREEN + f"[200] Valid file: {url}")
                    valid_links.append(url)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user during domain scan. Saving partial results...")
    except RuntimeError as e:
        print(Fore.RED + f"[!] Thread pool error while scanning {domain}: {e}")

    # Save valid links to a file
    if valid_links:
        file_name = f"{domain.replace('.', '_')}_valid_links.txt"
        try:
            with open(file_name, "w") as f:
                f.writelines(f"{link}\n" for link in valid_links)
            print(Fore.YELLOW + f"[*] {len(valid_links)} valid files saved to {file_name}")
        except PermissionError:
            print(Fore.RED + f"[!] Permission denied: cannot write to {file_name}")
        except OSError as e:
            print(Fore.RED + f"[!] Failed to save results to {file_name}: {e}")
    else:
        print(Fore.RED + f"[*] No valid files found for {domain}")

# Function to load domains or wordlists from file
def load_file(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {file_path}")
        return []
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied: cannot read {file_path}")
        return []
    except IsADirectoryError:
        print(Fore.RED + f"[!] Path is a directory, not a file: {file_path}")
        return []
    except UnicodeDecodeError:
        print(Fore.RED + f"[!] File contains invalid characters (not valid UTF-8): {file_path}")
        return []
    except OSError as e:
        print(Fore.RED + f"[!] OS error reading {file_path}: {e}")
        return []

# Main function
def main():
    parser = argparse.ArgumentParser(description="Backup File Finder for Bug Bounty")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target domain (e.g., example.com)")
    group.add_argument("-l", "--list", help="File containing list of domains")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")

    args = parser.parse_args()

    # Load wordlist
    wordlist = load_file(args.wordlist)
    if not wordlist:
        print(Fore.RED + "[!] Wordlist is empty or not found!")
        return

    # Load target domains
    if args.target:
        raw_targets = [args.target]
    else:
        raw_targets = load_file(args.list)

    if not raw_targets:
        print(Fore.RED + "[!] No valid targets provided!")
        return

    # Sanitize and validate all domains up front
    targets = []
    for raw in raw_targets:
        domain = sanitize_domain(raw)
        if not validate_domain(domain):
            print(Fore.RED + f"[!] Skipping invalid domain: {raw!r}")
            continue
        targets.append(domain)

    if not targets:
        print(Fore.RED + "[!] No valid domains remaining after validation!")
        return

    try:
        for domain in targets:
            process_domain(domain, wordlist)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user. Exiting gracefully...")
        sys.exit(130)


if __name__ == "__main__":
    main()
