# BackupFinder

A high-performance, all-in-one Bug Bounty recon tool that combines **deep
subdomain enumeration** with **backup file discovery**.

## Features

- **Deep subdomain enumeration** - recursively harvests subdomains from HTML,
  inline & remote JS, and Content-Security-Policy headers.
- **Live host probing** - quick HTTP/HTTPS check that prefers `HEAD` and falls
  back to `GET` when needed.
- **Backup file discovery** - 100+ word built-in wordlist combined with
  40+ extensions (`.zip`, `.sql`, `.bak`, `.env.bak`, `wp-config.php.bak`,
  etc.). Supports custom wordlists.
- **Smart validation** - rejects soft-404 HTML pages, empty responses and
  short replies; uses Range-requests to validate without downloading whole
  archives.
- **User-tunable concurrency** via `-threads` (default: 50) and a tuned
  `requests.Session` with large connection pool + retries.
- **IP-aware** - skips subdomain enumeration for raw IPs automatically.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```text
usage: exp.py [-h] [-t TARGET | -l LIST | -ld DIRECT_LIST | -sub TARGET]
              [-w WORDLIST] [-T THREADS] [--timeout TIMEOUT]
              [--max-depth MAX_DEPTH] [-o OUTPUT]
```

| Flag              | Description                                                                    |
|-------------------|--------------------------------------------------------------------------------|
| `-t, --target`    | Single target (domain or IP) - full pipeline (Phase 1 + Phase 2).              |
| `-l, --list`      | File with domains/IPs - full pipeline for each entry.                          |
| `-ld, --direct-list` | File with already-live hosts - skips subdomain enumeration.                 |
| `-sub, --subdomains` | **Subdomain enumeration ONLY** (no backup scan). Accepts a domain *or* a file. |
| `-w, --wordlist`  | Custom wordlist (merged with the strong built-in list).                        |
| `-T, -threads, --threads` | Concurrent worker count (default: 50).                                |
| `--timeout`       | Per-request timeout in seconds (default: 8).                                   |
| `--max-depth`     | Recursive subdomain enumeration depth (default: 3).                            |
| `-o, --output`    | Output directory (default: current directory).                                 |

### Examples

Full pipeline on a single target with 100 threads:

```bash
python exp.py -t example.com -threads 100
```

Full pipeline on a list of targets with a custom wordlist and 200 threads:

```bash
python exp.py -l targets.txt -w wordlist.txt -threads 200
```

Skip subdomain enumeration and scan already-live hosts directly:

```bash
python exp.py -ld live_hosts.txt -threads 150
```

**Subdomain enumeration only** (new `-sub` flag):

```bash
# single domain
python exp.py -sub example.com -threads 100

# list of domains
python exp.py -sub targets.txt -threads 100
```

## Output

```
<output-dir>/
  <domain>/
    <domain>_subdomains.txt       # all discovered subdomains
    <domain>_live_subdomains.txt  # live subdomains + HTTP status
  <host>_valid_backup_links.txt   # confirmed backup files per host
```

## Legal

This tool is intended for authorized security testing, bug bounty programs and
educational use only. The authors are not responsible for misuse.
