# ☁️ MEGA.NZ Checker by ThomasHermes

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Asyncio](https://img.shields.io/badge/asyncio-aiohttp-orange.svg)

A high-performance, asynchronous account checker for MEGA.nz with full storage quota capture, optional keyword search, proxy rotation, and dual-file hit exporting (including dedicated export for premium accounts).

## 🚀 Key Features

- **⚡ Asynchronous Concurrency** — Powered by `asyncio` and `aiohttp` for lightweight, non-blocking concurrent checking (supports up to 500 simultaneous accounts).
- **🛡️ Smart Anti-Ban & Auto-Retry** — Built-in exponential backoff retry for temporary errors (`EAGAIN` `-3`, `ETOOMANY` `-6`, `ETEMPUNAVAIL` `-18`, `ETOOMANYCONNECTIONS` `-19`) and rate limit handling (`ERATELIMIT` `-4`) with proxy rotation.
- **🧩 Automatic Hashcash Solver** — Solves MEGA's memory-hard Proof-of-Work (PoW) HTTP 402 challenges seamlessly in background processes.
- **🔌 Standalone API Client** — Native async implementation of the MEGA.nz v1 & v2 cryptographic login protocols (no heavy dependencies like `mega.py` or `tenacity`).
- **🌐 Proxy Rotation** — Seamless round-robin and random rotation supporting HTTP, HTTPS, and SOCKS5 proxies, with direct connection mode when proxies are omitted.
- **📊 Storage Quota Capture** — Accurately captures both used storage and total account capacity (`Used: X.XXGB / Y.YYGB`).
- **🔍 Optional Keyword Search** — Search for specific filenames within accounts. When omitted, keyword status is completely excluded from console logs and hit files (no `Keyword: N/A = FALSE`).
- **🎨 Color-Coded Console Logging** — Instant visual distinction: standard hits appear in **green**, while premium accounts with **total space > 50 GB** are highlighted in **bright pink** (`Fore.LIGHTMAGENTA_EX`). Fails, customs, and retries are color-coded accordingly.
- **💎 Dedicated Premium Export (`Hits_Premium.txt`)** — Accounts with **total space > 50 GB** are automatically saved to `Hits_Premium.txt` in addition to the primary hits output file.
- **📄 Clean Output Format** — Saved hit files contain clean credentials, storage metrics, and keyword results without combo row index markers (no `[100/877]`).
- **🪟 Real-Time Console Title** — Windows console title dynamically reflects real-time progress percentage, checked count, waiting tasks, hits, customs, fails, errors, and output filename.

## 🛠️ Installation

### Requirements
- **Python 3.8+**
- Dependencies listed in `requirements.txt`:
  - `requests`
  - `pycryptodome`
  - `colorama`
  *(Note: `aiohttp` is used for asynchronous network operations)*

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ThomasAHermes/mega-nz-checker-by-thomas-hermes.git
   cd mega-nz-checker-by-thomas-hermes
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   *The script also features an automated dependency check on startup to ensure all prerequisites are satisfied.*

## 📖 Usage

### Quick Start
1. **Prepare your combo list:**
   Add account credentials to `combo.txt` in `email:password` or `email;password` format (one per line). Blank lines and comments starting with `#` are automatically ignored.

2. **(Optional) Prepare your proxy list:**
   Create a text file containing your proxies (e.g., `proxies.txt`). Supported formats:
   ```text
   host:port
   user:password@host:port
   http://host:port
   socks5://user:password@host:port
   ```

3. **Launch the checker:**
   ```bash
   python checker.py
   ```

### Interactive Launch Walkthrough
Upon starting, the tool interactively guides you through configuration:

1. **Combo file confirmation:**
   ```text
   Place mail:pass pairs in combo.txt and press Enter
   ```
   Ensures `combo.txt` is ready before parsing.

2. **Proxy configuration:**
   ```text
   Proxy file path (or Enter to skip):
   ```
   Specify the path to your proxy list, or press `Enter` to run in direct connection mode.

3. **Concurrency limit:**
   ```text
   Concurrent accounts (default 5):
   ```
   Enter the maximum number of simultaneous checking tasks (range: `1` to `500`, default: `5`).

4. **Output filename:**
   ```text
   Output filename (without extension):
   ```
   Enter your preferred base filename (default: `results`). Results will be saved to `hits_<filename>.txt` (e.g., `hits_results.txt`).

5. **Keyword search:**
   ```text
   Keyword to search in files (or Enter to skip):
   ```
   Enter a filename substring to search inside accounts, or press `Enter` to disable keyword searching.

6. **Start checking:**
   Review the configuration summary and press `Enter` to begin checking.

## 📁 Output Files & Format

The checker saves results across two files:
- **Primary Hits File (`hits_<name>.txt`):** Receives all valid accounts.
- **Premium Hits File (`Hits_Premium.txt`):** Automatically receives accounts with **total space > 50 GB**.

> **Note:** Hit files are saved with a clean format. Combo row progress counters (such as `[10/50]`) appear exclusively in the console and are **not** written to disk.

### File Format: Without Keyword (Default)
When keyword search is disabled, the keyword field is completely omitted:
```text
user1@example.com:Password123 | Used: 5.25GB / 20.00GB
user2@example.com:SecurePass456 | Used: 120.00GB / 2048.00GB
```

### File Format: With Keyword
When keyword search is active (e.g., keyword `backup`):
```text
user1@example.com:Password123 | Used: 5.25GB / 20.00GB | Keyword: backup = FALSE
user2@example.com:SecurePass456 | Used: 120.00GB / 2048.00GB | Keyword: backup = TRUE
```

## 🖥️ Console Output Examples

### 1. Launch Without Keyword
```text
[  HIT   ] alex.smith@example.com:Summer2024! | Used: 4.12GB / 20.00GB | [1/4]
[  HIT   ] morgan.dev@example.com:UltraMega#99 | Used: 85.50GB / 2048.00GB | [2/4]
[  FAIL  ] taylor.lee@example.com:WrongPassword1 [3/4]
[ CUSTOM ] sam.jones@example.com:AccountLocked9 — EBLOCKED (user blocked) [4/4]
```
- Line 1 appears in **green** (`[  HIT   ]`) for standard storage (≤ 50 GB).
- Line 2 appears in **bright pink** (`[  HIT   ]`) because total space > 50 GB, and is also written to `Hits_Premium.txt`.
- Note the complete absence of `Keyword: N/A = FALSE`.

### 2. Launch With Keyword (`backup`)
```text
[  HIT   ] alex.smith@example.com:Summer2024! | Used: 4.12GB / 20.00GB | Keyword: backup = FALSE | [1/4]
[  HIT   ] morgan.dev@example.com:UltraMega#99 | Used: 85.50GB / 2048.00GB | Keyword: backup = TRUE | [2/4]
[  FAIL  ] taylor.lee@example.com:WrongPassword1 [3/4]
[ CUSTOM ] sam.jones@example.com:AccountLocked9 — EBLOCKED (user blocked) [4/4]
```

### 3. Completion Summary
```text
════════════════════════════════════════════════════════════

  Results:
  Hits:     2
  Custom:   1
  Fail:     1
  Errors:   0
  Total:    4/4
  Time:     6.2s
  File:     hits_results.txt
```

## ⚙️ Error Codes & Handling

The checker handles MEGA API error codes automatically:

| Code | Status | Meaning | Action Taken |
|:---:|:---|:---|:---|
| `-2` | `EARGS` | Invalid credentials / bad arguments | Marked as **FAIL** |
| `-3` | `EAGAIN` | Temporary error | Exponential backoff retry |
| `-4` | `ERATELIMIT` | Rate limit reached | Waits 15 seconds + retries with proxy switch |
| `-6` | `ETOOMANY` | Too many concurrent connections | Exponential backoff retry |
| `-9` | `ENOENT` | Account not found | Marked as **FAIL** |
| `-16`| `EBLOCKED` | Account blocked or suspended | Marked as **CUSTOM** |
| `-17`| `EOVERQUOTA` | Account over quota | Marked as **CUSTOM** |
| `-18`| `ETEMPUNAVAIL` | Temporarily unavailable | Exponential backoff retry |
| `-19`| `ETOOMANYCONNECTIONS` | Connection limit reached | Exponential backoff retry |

## ⚠️ Disclaimer

This tool is for **educational and security testing purposes only**. The developer is not responsible for any misuse or damage caused by this program. Use it only on accounts you own or have explicit permission to test.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Developed with ❤️ by [ThomasHermes](https://github.com/ThomasAHermes)*
