# ⚡ MEGA.nz Account Checker v3.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Engine-asyncio%20%7C%20aiohttp-2C5BB4.svg?style=flat-square&logo=aiohttp&logoColor=white" alt="Engine">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Maintained-brightgreen.svg?style=flat-square" alt="Maintenance">
</p>

A high-performance, asynchronous MEGA.nz account validator and storage analyzer. Designed for precision, speed, and resilience, it features native API cryptography, automated Proof-of-Work (PoW) challenge solving, intelligent rate-limit handling, multi-tier hit categorization, and clean output formatting.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Project Architecture](#-project-architecture)
- [Project Structure](#-project-structure)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Usage Guide](#-usage-guide)
- [Output Files & Data Formats](#-output-files--data-formats)
- [Console UX & Visual Color Palette](#-console-ux--visual-color-palette)
- [API Error Codes & Automated Handling](#-api-error-codes--automated-handling)
- [Performance & Concurrency Tuning](#-performance--concurrency-tuning)
- [Contributing & License](#-contributing--license)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

Unlike legacy checkers relying on outdated wrappers (such as `mega.py`) or blocking threaded requests, **MEGA.nz Account Checker v3.0** operates entirely on a standalone asynchronous network core (`aiohttp` + `asyncio`). Heavy cryptographic routines (PBKDF2, AES-CBC-128, RSA, and PoW challenges) are offloaded to dedicated worker processes to ensure maximum throughput without locking the event loop.

---

## 🚀 Key Features

- **⚡ Asynchronous Concurrency** — Scalable non-blocking architecture capable of handling from 1 to 500 simultaneous checks via an asynchronous semaphore.
- **🔐 Standalone Zero-Bloat Cryptography** — Native implementation of MEGA v1 and v2 login protocols without heavy dependencies.
- **🧩 Automated Hashcash (PoW) Solver** — Solves MEGA's memory-hard Proof-of-Work (HTTP 402) challenges seamlessly in worker processes via `ProcessPoolExecutor`.
- **🛡️ Smart Anti-Ban & Auto-Retry** — Built-in exponential backoff for temporary server errors (`EAGAIN` `-3`, `ETOOMANY` `-6`, `ETEMPUNAVAIL` `-18`, `ETOOMANYCONNECTIONS` `-19`) and automated 15-second proxy switching on rate limits (`ERATELIMIT` `-4`).
- **🌐 Flexible Proxy Rotation** — Supports HTTP, HTTPS, and SOCKS5 proxies in `host:port` or `user:pass@host:port` format with round-robin and random selection, alongside direct connection fallback.
- **📊 Quota & Storage Analytics** — Captures both used space and total capacity (`Used: X.XXGB / Y.YYGB`).
- **💎 Dual-Tier Export (`Hits_Premium.txt`)** — High-capacity accounts (**total space > 50 GB**) are automatically saved to a dedicated `Hits_Premium.txt` file in addition to the primary hits output.
- **🔍 Optional Keyword Search** — Search for specific filenames within accounts. When omitted, keyword status is completely omitted from both console logs and text exports (no clutter like `Keyword: N/A = FALSE`).
- **📄 Clean Output Format** — All saved hit files are free of combo row indices (`[100/877]`), providing pristine credential lists ready for processing.
- **🎨 Color-Coded Telemetry** — Instant visual distinction in terminal: premium accounts are highlighted in **bright pink** (`Fore.LIGHTMAGENTA_EX`), standard hits in **green**, fails in **red**, and customs in **yellow**.
- **🪟 Real-Time Console Title** — Windows console title dynamically reflects real-time progress percentage, checked count, waiting tasks, hits, customs, fails, errors, and output filename.

---

## 🏛️ Project Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    checker.py (Orchestrator)                │
│  - Input parser (combo.txt, proxies.txt)                    │
│  - Asyncio task runner with Semaphore rate-limiting         │
│  - Dual FileWriter (hits_<name>.txt & Hits_Premium.txt)    │
│  - Win32 live console title updater                         │
└──────────────┬──────────────────────────────▲───────────────┘
               │ async task dispatch          │ storage & files
┌──────────────▼──────────────────────────────┴───────────────┐
│                    mega_api.py (Client Layer)               │
│  - MegaClient (aiohttp.ClientSession)                       │
│  - Protocol v1 & v2 auth (PBKDF2 HMAC-SHA512, AES, RSA)    │
│  - Background ProcessPoolExecutor for CPU-heavy PoW/Crypto  │
│  - Typed exceptions: MegaLoginError, MegaBlockedError, etc. │
└─────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
mega-nz-checker-by-thomas-hermes/
├── checker.py          # Main application: CLI wizard, async worker pool, file writers
├── mega_api.py         # Standalone MEGA API client (crypto engine, PoW solver)
├── requirements.txt    # Production dependencies
├── combo.txt           # Input credentials file (mail:pass or mail;pass)
├── hits_<name>.txt     # Main output file for all valid hits (e.g., hits_results.txt)
├── Hits_Premium.txt    # Dedicated output file for accounts with storage > 50 GB
├── .gitignore          # Git exclusion rules
├── LICENSE             # MIT License
└── README.md           # Comprehensive project documentation
```

---

## 🛠️ Prerequisites & Installation

### Requirements
- **Python 3.8+** (Python 3.10+ recommended)
- OS: Windows, Linux, or macOS

### 1. Clone the repository
```bash
git clone https://github.com/ThomasAHermes/mega-nz-checker-by-thomas-hermes.git
cd mega-nz-checker-by-thomas-hermes
```

### 2. (Recommended) Create and activate a virtual environment
**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

> **Automated Self-Healing:** `checker.py` includes an automated dependency verification routine on startup. If any required library is missing, it will automatically attempt to install prerequisites before initializing.

---

## 📖 Usage Guide

### 1. Prepare Credentials (`combo.txt`)
Place account credentials into `combo.txt` in `email:password` or `email;password` format (one pair per line):
```text
alex.smith@example.com:Summer2024!
jordan.doe@example.com:Password@123
# Comments and blank lines are ignored
taylor.lee@example.com;MySecretPass99
```

### 2. (Optional) Prepare Proxies
Create a proxy list (e.g., `proxies.txt`). The checker supports the following standard formats:
```text
192.168.1.100:8080
user:pass@192.168.1.100:8080
http://192.168.1.100:8080
socks5://user:pass@192.168.1.100:1080
```

### 3. Run the Checker
```bash
python checker.py
```

### Interactive Configuration Wizard
When launched, the checker interactively prompts for settings:
```text
════════════════════════════════════════════════════════════
  Place mail:pass pairs in combo.txt and press Enter
════════════════════════════════════════════════════════════
  Proxy file path (or Enter to skip): proxies.txt
════════════════════════════════════════════════════════════
  Concurrent accounts (default 5): 10
════════════════════════════════════════════════════════════
  Output filename (without extension): results
════════════════════════════════════════════════════════════
  Keyword to search in files (or Enter to skip): backup
════════════════════════════════════════════════════════════
```

---

## 📁 Output Files & Data Formats

The checker saves results across two distinct files:

1. **Primary Hits File (`hits_<name>.txt`)** — Contains every valid account found.
2. **Dedicated Premium Export (`Hits_Premium.txt`)** — Automatically receives accounts where **total capacity exceeds 50 GB**.

> **Clean Formatting Guarantee:** Combo row numbers (such as `[10/50]`) appear exclusively in the console log and are **never** written to output files.

### Output Comparison

| Execution Mode | Primary Hits File (`hits_results.txt`) | Premium File (`Hits_Premium.txt`) |
|:---|:---|:---|
| **Without Keyword** | `user@mail.com:pass \| Used: 2.10GB / 20.00GB`<br>`vip@mail.com:pass \| Used: 15.00GB / 2048.00GB` | `vip@mail.com:pass \| Used: 15.00GB / 2048.00GB` |
| **With Keyword (`backup`)** | `user@mail.com:pass \| Used: 2.10GB / 20.00GB \| Keyword: backup = FALSE`<br>`vip@mail.com:pass \| Used: 15.00GB / 2048.00GB \| Keyword: backup = TRUE` | `vip@mail.com:pass \| Used: 15.00GB / 2048.00GB \| Keyword: backup = TRUE` |

---

## 🖥️ Console UX & Visual Color Palette

Every console log line is color-coded for rapid scanning during large runs:

| Tag | Color | Meaning |
|:---:|:---|:---|
| `[  HIT   ]` | **Bright Pink** (`Fore.LIGHTMAGENTA_EX`) | **Premium Hit:** Valid account with total capacity **> 50 GB**. The entire line is highlighted in bright pink and appended to `Hits_Premium.txt`. |
| `[  HIT   ]` | **Green** (`Fore.GREEN`) | **Standard Hit:** Valid account with total capacity **≤ 50 GB**. Saved to primary hits file. |
| `[  FAIL  ]` | **Red** (`Fore.RED`) | Invalid credentials or account does not exist (`-2`, `-9`). |
| `[ CUSTOM ]` | **Yellow** (`Fore.YELLOW`) | Account blocked or over storage quota (`-16`, `-17`). |
| `[ RETRY  ]` | **Blue** (`Fore.BLUE`) | Temporary server error or rate-limit backoff attempt. |
| `[ ERROR  ]` | **Magenta** (`Fore.MAGENTA`) | Connection failure or maximum retries exceeded. |
| `[  INFO  ]` | **Cyan** (`Fore.CYAN`) | Runtime notifications, configuration summary, and stats. |

### Console Output Example
```text
[  HIT   ] regular.user@example.com:Pass1234 | Used: 1.50GB / 20.00GB | [1/10]
[  HIT   ] pro.account@example.com:Mega2026! | Used: 120.00GB / 2048.00GB | [2/10]
[  FAIL  ] wrong.account@example.com:InvalidPassword [3/10]
[ CUSTOM ] suspended.user@example.com:Pass999 — EBLOCKED (user blocked) [4/10]
[ RETRY  ] busy.server@example.com — rate limited, waiting 15s (attempt 1/3)
```

---

## ⚙️ API Error Codes & Automated Handling

The client maps MEGA's raw error codes to typed exceptions and automated resolution strategies:

| Error Code | Name | Meaning | Checker Action |
|:---:|:---|:---|:---|
| `-2` | `EARGS` | Invalid credentials / invalid arguments | Recorded as **FAIL** |
| `-3` | `EAGAIN` | Temporary server error | Exponential backoff retry (`delay = 5s * attempt`) |
| `-4` | `ERATELIMIT` | IP rate limit exceeded | Waits 15s + switches proxy (if pool is configured) |
| `-6` | `ETOOMANY` | Too many concurrent connections | Exponential backoff retry (`delay = 5s * attempt`) |
| `-9` | `ENOENT` | Account does not exist | Recorded as **FAIL** |
| `-16` | `EBLOCKED` | Account suspended or blocked | Recorded as **CUSTOM** |
| `-17` | `EOVERQUOTA` | Account over storage quota | Recorded as **CUSTOM** |
| `-18` | `ETEMPUNAVAIL` | Resource temporarily unavailable | Exponential backoff retry (`delay = 5s * attempt`) |
| `-19` | `ETOOMANYCONNECTIONS` | Connection threshold exceeded | Exponential backoff retry (`delay = 5s * attempt`) |

---

## ⚡ Performance & Concurrency Tuning

Recommended concurrency settings based on your network and proxy infrastructure:

| Connection Type | Recommended Concurrency | Notes |
|:---|:---:|:---|
| **Direct Connection (No Proxy)** | `3` – `5` | Keeps request volume below MEGA's per-IP rate limit (`-4`). |
| **Datacenter Proxies** | `10` – `25` | Moderate concurrency; rotate proxies periodically. |
| **Rotating Residential Proxies** | `50` – `200+` | High-throughput checking across multiple IP subnets. |

---

## 📄 Contributing & License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete details.

Contributions, bug reports, and suggestions are welcome:
1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add AmazingFeature'`).
4. Push to the Branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

---

## ⚠️ Disclaimer

This tool is created for **authorized security testing and educational research purposes only**. The author assumes no responsibility or liability for unauthorized access, misuse, or violation of service terms resulting from the use of this software. Always test credentials only on accounts you own or have explicit authorization to audit.

---

<p align="center">
  Developed by <a href="https://github.com/ThomasAHermes"><b>ThomasHermes</b></a>
</p>
