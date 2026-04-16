import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin
import argparse
import re
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

session = requests.Session()
session.verify = False
session.headers.update({'User-Agent': 'Mozilla/5.0'})

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

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(scan_single_js, url, root_domain) for url in js_urls]
        for future in as_completed(futures):
            all_subdomains.update(future.result())

    for script in inline_scripts:
        all_subdomains.update(extract_subdomains(script, root_domain))

    all_subdomains.update(extract_subdomains(html, root_domain))
    all_subdomains.update(extract_csp_subdomains(headers, root_domain))

    return all_subdomains

def recursive_scan(domain, max_depth=10):
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

        with ThreadPoolExecutor(max_workers=8) as executor:
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

def main():
    parser = argparse.ArgumentParser(description='Ultra-fast deep subdomain scanner (JS + CSP + HTML)')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    args = parser.parse_args()

    domain = args.domain.strip().replace("https://", "").replace("http://", "")
    print(f"[*] Starting deep subdomain scan: {domain}")

    # Create directory named after domain
    if not os.path.exists(domain):
        os.makedirs(domain)

    subdomains = recursive_scan(domain)

    print(f"\n[+] Total Unique Subdomains Found: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(f"{sub}.{domain}")

    # Save subdomains file inside the domain folder
    subdomains_file = os.path.join(domain, f"{domain}_subdomains.txt")
    save_to_file(subdomains_file, [f"{sub}.{domain}" for sub in subdomains])
    print(f"\n[+] Subdomains saved to: {subdomains_file}")

    print("\n[*] Checking live status of subdomains...")

    def check_live(sub):
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{sub}.{domain}"
                resp = session.get(url, timeout=5)
                return f"{url} - {resp.status_code}"
            except:
                continue
        return None

    live_results = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(check_live, sub) for sub in subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_results.append(result)

    live_file = os.path.join(domain, f"{domain}_live_subdomains.txt")
    save_to_file(live_file, live_results)
    print(f"[+] Live subdomains saved to: {live_file}")

if __name__ == "__main__":
    main()
