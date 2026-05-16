# ☁️ MEGA.NZ m:p Checker by ThomasHermes

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A high-performance, multithreaded account checker for MEGA.nz with full storage capture and proxy support.

## 🚀 Key Features

- **🛡️ Smart Anti-Ban** — Built-in handling for `ERATELIMIT` (-4) and `ETOOMANY` (-6) with automatic retries and proxy rotation.
- **🔌 Standalone API** — Custom implementation of the MEGA.nz API (no heavy dependencies like `mega.py`).
- **🌐 Proxy Support** — Seamless rotation with HTTP, HTTPS, and SOCKS5 support.
- **📊 Used Space and Storage Capacity Capture**
- **🔍 Keyword Search** — (Optional) Search for specific filenames within accounts.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ThomasHermes/MEGA.NZ-Checker.git
   cd MEGA.NZ-Checker
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 📖 Usage

1. **Prepare your combo:** Load your accounts into the `combo.txt` file in `mail:pass` format.
2. **(Optional) Configure proxies:** Create a `proxies.txt` file with your proxy list.
3. **Launch the checker:**
   ```bash
   python checker.py
   ```

## ⚙️ Configuration

The checker handles MEGA's API error codes automatically:

| Code | Status | Action |
|------|--------|--------|
| `-2` | EARGS | Invalid credentials (FAIL) |
| `-4` | ERATELIMIT | Rate limit hit (Wait 15s + Proxy Switch) |
| `-16`| EBLOCKED | Account blocked (CUSTOM) |
| `-17`| EOVERQUOTA | Account over quota (CUSTOM) |

## ⚠️ Disclaimer

This tool is for **educational and security testing purposes only**. The developer is not responsible for any misuse or damage caused by this program. Use it only on accounts you own or have permission to test.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Developed with ❤️ by [ThomasHermes](https://github.com/ThomasHermes)*
