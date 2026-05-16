"""
mega_api.py — Standalone MEGA.nz API client.
No dependency on mega.py, tenacity, or other problematic packages.
Uses only: requests, pycryptodome, hashlib (stdlib).

Supports:
- v1 and v2 MEGA accounts
- Proxy support (HTTP/HTTPS/SOCKS5)
- Storage and file info retrieval
- Retry logic with exponential backoff on error -3/-6/-18
- Typed exceptions for clean error handling
"""

import math
import json
import struct
import base64
import hashlib
import binascii
import random
import codecs
import time
import logging
import multiprocessing
import threading

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

logger = logging.getLogger(__name__)

# ─── CPU Throttling ──────────────────────────────────────────
# Limit concurrent heavy crypto operations (PBKDF2, PoW, Key Prep) 
# to prevent 100% CPU usage. This ensures the UI remains responsive.
_crypto_semaphore = threading.Semaphore(max(1, multiprocessing.cpu_count() // 2))

# ─── Error Codes ──────────────────────────────────────────────

MEGA_ERRORS = {
    -1: "EINTERNAL (internal error)",
    -2: "EARGS (invalid argument / bad credentials)",
    -3: "EAGAIN (temporary error, retry)",
    -4: "ERATELIMIT (rate limited)",
    -5: "EFAILED (failed request)",
    -6: "ETOOMANY (too many concurrent connections)",
    -7: "ERANGE (out of range)",
    -8: "EEXPIRED (expired)",
    -9: "ENOENT (not found)",
    -10: "ECIRCULAR (circular reference)",
    -11: "EACCESS (access denied)",
    -12: "EEXIST (already exists)",
    -13: "EINCOMPLETE (incomplete)",
    -14: "EKEY (crypto error)",
    -15: "ESID (bad session ID)",
    -16: "EBLOCKED (user blocked)",
    -17: "EOVERQUOTA (over quota)",
    -18: "ETEMPUNAVAIL (temporarily unavailable)",
    -19: "ETOOMANYCONNECTIONS (too many connections)",
}


class MegaError(Exception):
    """Base MEGA API error."""
    def __init__(self, code: int, cause: Exception = None):
        self.code = code
        self.message = MEGA_ERRORS.get(code, f"Unknown error ({code})")
        self.cause = cause
        super().__init__(self.message)

    def __str__(self):
        if self.cause:
            return f"{self.message} (Cause: {self.cause})"
        return self.message


class MegaLoginError(MegaError):
    """Auth error (wrong email/password)."""
    pass


class MegaBlockedError(MegaError):
    """Account blocked."""
    pass


class MegaRateLimitError(MegaError):
    """Rate limit — need to wait or rotate proxy."""
    pass


class MegaTempError(MegaError):
    """Temporary error — safe to retry."""
    pass


# ─── Crypto helpers ───────────────────────────────────────────

def _makebyte(x):
    return codecs.latin_1_encode(x)[0]


def _makestring(x):
    return codecs.latin_1_decode(x)[0]


def _aes_cbc_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC, _makebyte('\0' * 16))
    return cipher.encrypt(data)


def _aes_cbc_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC, _makebyte('\0' * 16))
    return cipher.decrypt(data)


def _a32_to_str(a):
    return struct.pack('>%dI' % len(a), *a)


def _str_to_a32(b):
    if isinstance(b, str):
        b = _makebyte(b)
    if len(b) % 4:
        b += b'\0' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) // 4), b)


def _a32_to_base64(a):
    return _base64_url_encode(_a32_to_str(a))


def _base64_to_a32(s):
    return _str_to_a32(_base64_url_decode(s))


def _base64_url_decode(data):
    data += '=' * (-len(data) % 4)
    for search, replace in (('-', '+'), ('_', '/'), (',', '')):
        data = data.replace(search, replace)
    return base64.b64decode(data)


def _base64_url_encode(data):
    data = base64.b64encode(data)
    data = _makestring(data)
    for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
        data = data.replace(search, replace)
    return data


def _aes_cbc_encrypt_a32(data, key):
    return _str_to_a32(_aes_cbc_encrypt(_a32_to_str(data), _a32_to_str(key)))


def _aes_cbc_decrypt_a32(data, key):
    return _str_to_a32(_aes_cbc_decrypt(_a32_to_str(data), _a32_to_str(key)))


def _stringhash(s, aeskey):
    s32 = _str_to_a32(s)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    
    # Optimization: pre-create cipher and use ECB mode for single-block
    cipher = AES.new(_a32_to_str(aeskey), AES.MODE_ECB)
    h_bytes = _a32_to_str(h32)
    
    with _crypto_semaphore:
        for i in range(0x4000):
            h_bytes = cipher.encrypt(h_bytes)
            if i % 512 == 0:
                time.sleep(0)  # Yield CPU
    
    res32 = _str_to_a32(h_bytes)
    return _a32_to_base64((res32[0], res32[2]))


def _prepare_key(arr):
    pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
    pkey_bytes = _a32_to_str(pkey)
    
    # Pre-create ciphers for each password chunk
    ciphers = []
    for j in range(0, len(arr), 4):
        key = [0, 0, 0, 0]
        for i in range(4):
            if i + j < len(arr):
                key[i] = arr[i + j]
        ciphers.append(AES.new(_a32_to_str(key), AES.MODE_ECB))
        
    with _crypto_semaphore:
        for i in range(0x10000):
            for cipher in ciphers:
                pkey_bytes = cipher.encrypt(pkey_bytes)
            if i % 2048 == 0:
                time.sleep(0)  # Yield CPU
            
    return _str_to_a32(pkey_bytes)


def _decrypt_key(a, key):
    return sum((_aes_cbc_decrypt_a32(a[i:i + 4], key)
                for i in range(0, len(a), 4)), ())


def _decrypt_attr(attr, key):
    attr = _aes_cbc_decrypt(attr, _a32_to_str(key))
    # MEGA attributes are typically UTF-8 but might be corrupted or in other encodings
    # First, strip nulls
    attr = attr.rstrip(b'\0')
    if not attr.startswith(b'MEGA{"'):
        return False
    
    try:
        # Try UTF-8 first
        return json.loads(attr[4:].decode('utf-8'))
    except UnicodeDecodeError:
        try:
            # Fallback to latin-1 (original behavior, but safer)
            return json.loads(attr[4:].decode('latin-1'))
        except Exception:
            return False
    except Exception:
        return False


def _mpi_to_int(s):
    return int(binascii.hexlify(s[2:]), 16)


def _extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = _extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)


def _modular_inverse(a, m):
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def _make_id(length=10):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(chars) for _ in range(length))


# ─── Hashcash Solver ──────────────────────────────────────────

NUM_REPLICATIONS = 262144   # 2^18
TOKEN_SLOT_SIZE = 48        # Bytes per token slot in the buffer


def _calc_hashcash_threshold(easiness: int) -> int:
    """Calculate the difficulty threshold from the easiness value."""
    low = easiness & 63
    mant = (low << 1) + 1
    exp = (easiness >> 6) * 7 + 3
    return (mant << exp) & 0xFFFFFFFF


def _solve_hashcash(token: str, easiness: int) -> str:
    """
    Core Hashcash solver logic (Memory-hard PoW).
    Mega's PoW involves hashing a ~12.5MB buffer.
    """
    threshold = _calc_hashcash_threshold(easiness)
    
    # Decode and pad token to 16 bytes
    token_bytes = _base64_url_decode(token)
    if len(token_bytes) % 16 != 0:
        token_bytes += b'\x00' * (16 - (len(token_bytes) % 16))
    
    # Initialize the memory-hard buffer
    # Total size: 4 (prefix) + 2^18 * 48 = 12,582,916 bytes
    # Optimization: Use fast multiplication instead of a 262k iteration loop
    token_padded = token_bytes + b'\x00' * (TOKEN_SLOT_SIZE - len(token_bytes))
    buffer = bytearray(b'\x00' * 4 + token_padded * NUM_REPLICATIONS)

    # Brute-force the 4-byte prefix
    prefix = random.randint(0, 0xFFFFFFFF)
    struct.pack_into('>I', buffer, 0, prefix)

    iterations = 0
    with _crypto_semaphore:
        while True:
            # Increment prefix
            for j in range(4):
                buffer[j] = (buffer[j] + 1) & 0xFF
                if buffer[j] != 0:
                    break
                
            digest = hashlib.sha256(buffer).digest()
            hash_value = struct.unpack('>I', digest[:4])[0]
            if hash_value <= threshold:
                return _base64_url_encode(bytes(buffer[:4]))
            
            # Throttling to prevent 100% CPU usage
            iterations += 1
            if iterations % 50 == 0:
                # Yield control and add a small physical delay
                time.sleep(0.002)
            elif iterations % 10 == 0:
                time.sleep(0)


# ─── MEGA API Client ─────────────────────────────────────────

class MegaClient:
    """
    Standalone MEGA.nz API client.
    Supports authentication, storage info, and file listing.
    Optional proxy support for avoiding rate limits.
    """

    API_URL = "https://g.api.mega.co.nz/cs"
    TIMEOUT = 60
    MAX_RETRIES = 3
    RETRY_BASE_DELAY = 2  # seconds, multiplied by attempt number

    def __init__(self, proxy: str = None):
        """
        Initialize MEGA client.

        Args:
            proxy: Optional proxy string, e.g.:
                   'http://user:pass@host:port'
                   'socks5://user:pass@host:port'
                   'http://host:port'
        """
        self.sid = None
        self.master_key = None
        self.sequence_num = random.randint(100000000, 999999999)
        self.request_id = _make_id(10)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "MEGA/3.0",
            "Content-Type": "application/json",
        })
        # Proxy setup
        if proxy:
            proxy = proxy.strip()
            if proxy:
                self.session.proxies = {
                    "http": proxy,
                    "https": proxy,
                }

    def login(self, email: str, password: str) -> "MegaClient":
        """
        Authenticate with MEGA.nz.
        Supports both v1 (legacy) and v2 (PBKDF2) accounts.
        """
        email = email.lower().strip()

        # Step 1: check for salt (v2) or fall back to v1
        us0_resp = self._api_request({'a': 'us0', 'user': email})

        try:
            user_salt = _base64_to_a32(us0_resp['s'])
            # v2 account — PBKDF2-HMAC-SHA512
            with _crypto_semaphore:
                pbkdf2_key = hashlib.pbkdf2_hmac(
                    hash_name='sha512',
                    password=password.encode('utf-8'),
                    salt=_a32_to_str(user_salt),
                    iterations=100000,
                    dklen=32
                )
            password_aes = _str_to_a32(pbkdf2_key[:16])
            user_hash = _base64_url_encode(pbkdf2_key[-16:])
        except (KeyError, TypeError):
            # v1 account — custom KDF
            password_aes = _prepare_key(_str_to_a32(password))
            user_hash = _stringhash(email, password_aes)

        # Step 2: authenticate
        resp = self._api_request({'a': 'us', 'user': email, 'uh': user_hash})

        if isinstance(resp, int):
            self._handle_error_code(resp)

        # Step 3: decrypt session
        self._process_login(resp, password_aes)
        return self

    def _process_login(self, resp, password_key):
        """Decrypt master key and session ID from auth response."""
        encrypted_master_key = _base64_to_a32(resp['k'])
        self.master_key = _decrypt_key(encrypted_master_key, password_key)

        if 'tsid' in resp:
            tsid = _base64_url_decode(resp['tsid'])
            key_encrypted = _a32_to_str(
                _aes_cbc_encrypt_a32(
                    _str_to_a32(tsid[:16]), self.master_key
                )
            )
            if key_encrypted == tsid[-16:]:
                self.sid = resp['tsid']
        elif 'csid' in resp:
            encrypted_rsa_pk = _base64_to_a32(resp['privk'])
            rsa_pk = _decrypt_key(encrypted_rsa_pk, self.master_key)
            private_key = _a32_to_str(rsa_pk)

            rsa_components_raw = [0, 0, 0, 0]
            for i in range(4):
                bitlength = (private_key[0] * 256) + private_key[1]
                bytelength = math.ceil(bitlength / 8) + 2
                rsa_components_raw[i] = _mpi_to_int(private_key[:bytelength])
                private_key = private_key[bytelength:]

            p, q, d = rsa_components_raw[0], rsa_components_raw[1], rsa_components_raw[2]
            n = p * q
            phi = (p - 1) * (q - 1)
            e = _modular_inverse(d, phi)

            rsa_key = RSA.construct((n, e, d, p, q))
            encrypted_sid = _mpi_to_int(_base64_url_decode(resp['csid']))
            sid = '%x' % rsa_key._decrypt(encrypted_sid)
            sid = binascii.unhexlify('0' + sid if len(sid) % 2 else sid)
            self.sid = _base64_url_encode(sid[:43])

    def get_storage(self) -> dict:
        """
        Get account storage info.
        Returns {'used_gb': float, 'total_gb': float, 'used_bytes': int, 'total_bytes': int}
        """
        resp = self._api_request({'a': 'uq', 'xfer': 1, 'strg': 1})
        used = resp.get('cstrg', 0)
        total = resp.get('mstrg', 0)
        return {
            'used_bytes': used,
            'total_bytes': total,
            'used_gb': round(used / 1073741824, 2),
            'total_gb': round(total / 1073741824, 2),
        }

    def get_user(self) -> dict:
        """Get user info."""
        return self._api_request({'a': 'ug'})

    def get_files(self) -> dict:
        """
        Get file listing for the account.
        Returns dict {handle: file_info}
        """
        files = self._api_request({'a': 'f', 'c': 1, 'r': 1})
        result = {}
        shared_keys = {}

        # Init shared keys
        if 'ok' in files and 's' in files:
            ok_dict = {}
            for ok_item in files.get('ok', []):
                try:
                    sk = _decrypt_key(_base64_to_a32(ok_item['k']), self.master_key)
                    ok_dict[ok_item['h']] = sk
                except Exception:
                    continue
            for s_item in files.get('s', []):
                if s_item['u'] not in shared_keys:
                    shared_keys[s_item['u']] = {}
                if s_item['h'] in ok_dict:
                    shared_keys[s_item['u']][s_item['h']] = ok_dict[s_item['h']]

        for f in files.get('f', []):
            try:
                pf = self._process_file(f, shared_keys)
                if pf.get('a'):
                    result[f['h']] = pf
            except Exception:
                continue

        return result

    def get_file_names(self) -> list[str]:
        """Get list of file names in the account."""
        files = self.get_files()
        names = []
        for _, info in files.items():
            a = info.get('a')
            if isinstance(a, dict) and 'n' in a:
                names.append(a['n'])
        return names

    def _process_file(self, file, shared_keys):
        """Process a file node from the API response."""
        if file['t'] in (0, 1):
            keys = dict(
                kp.split(':', 1) for kp in file['k'].split('/')
                if ':' in kp
            )
            uid = file['u']
            key = None

            if uid in keys:
                key = _decrypt_key(_base64_to_a32(keys[uid]), self.master_key)
            elif 'su' in file and 'sk' in file and ':' in file['k']:
                shared_key = _decrypt_key(_base64_to_a32(file['sk']), self.master_key)
                key = _decrypt_key(_base64_to_a32(keys[file['h']]), shared_key)

            if key is not None:
                if file['t'] == 0:
                    k = (key[0] ^ key[4], key[1] ^ key[5],
                         key[2] ^ key[6], key[3] ^ key[7])
                else:
                    k = key
                file['key'] = key
                file['k'] = k
                attributes = _base64_url_decode(file['a'])
                attributes = _decrypt_attr(attributes, k)
                file['a'] = attributes
        elif file['t'] == 2:
            file['a'] = {'n': 'Cloud Drive'}
        elif file['t'] == 3:
            file['a'] = {'n': 'Inbox'}
        elif file['t'] == 4:
            file['a'] = {'n': 'Rubbish Bin'}

        return file

    def _api_request(self, data):
        """
        Send API request with retry logic.
        Retries on -3 (EAGAIN), -6 (ETOOMANY), -18 (ETEMPUNAVAIL).
        """
        params = {
            'id': self.sequence_num,
            'v': 2,
        }
        self.sequence_num += 1

        if self.sid:
            params['sid'] = self.sid

        if not isinstance(data, list):
            data = [data]

        for attempt in range(1, self.MAX_RETRIES + 1):
            response = None
            try:
                response = self.session.post(
                    self.API_URL,
                    params=params,
                    data=json.dumps(data),
                    timeout=self.TIMEOUT,
                )
                
                # Handle 402 Computational Challenge (Hashcash)
                if response.status_code == 402:
                    challenge = response.headers.get('X-Hashcash')
                    if challenge:
                        logger.debug(f"Solving MEGA Hashcash challenge: {challenge}")
                        parts = challenge.split(':')
                        if len(parts) >= 4:
                            easiness = int(parts[1])
                            token = parts[3]
                            solution = _solve_hashcash(token, easiness)
                            # Add solution to headers and retry immediately
                            self.session.headers['X-Hashcash'] = f"1:{token}:{solution}"
                            # Clear the error and retry this attempt
                            continue
                
                response.raise_for_status()
                json_resp = response.json()
            except Exception as e:
                # If we got a 402 but didn't handle it yet (or it failed again)
                if attempt < self.MAX_RETRIES:
                    # On some errors, we might want to clear the Hashcash header
                    if 'X-Hashcash' in self.session.headers:
                        del self.session.headers['X-Hashcash']
                    time.sleep(self.RETRY_BASE_DELAY * attempt)
                    continue
                
                # Detailed error reporting
                code = 'N/A'
                body = 'N/A'
                if response is not None:
                    code = response.status_code
                    try:
                        body = response.text[:200]
                    except:
                        body = "<unreadable>"
                
                err_msg = f"API Error (Status {code}): {str(e)[:100]}"
                if body and body != 'N/A':
                    err_msg += f" | Response: {body}"
                
                raise MegaError(-1, cause=Exception(err_msg)) from e

            # Parse response
            int_resp = None
            if isinstance(json_resp, list):
                if len(json_resp) > 0 and isinstance(json_resp[0], int):
                    int_resp = json_resp[0]
            elif isinstance(json_resp, int):
                int_resp = json_resp

            if int_resp is not None:
                if int_resp == 0:
                    return int_resp
                if int_resp in (-3, -6, -18, -19):
                    # Retry-able errors
                    if attempt < self.MAX_RETRIES:
                        delay = self.RETRY_BASE_DELAY * attempt
                        logger.debug(f"MEGA API error {int_resp}, retry #{attempt} in {delay}s")
                        time.sleep(delay)
                        continue
                self._handle_error_code(int_resp)

            return json_resp[0]

        raise MegaError(-1)

    def _handle_error_code(self, code: int):
        """Map MEGA error code to typed exception."""
        if code in (-2, -9, -5, -14):
            raise MegaLoginError(code)
        elif code in (-16, -17):
            raise MegaBlockedError(code)
        elif code in (-4,):
            raise MegaRateLimitError(code)
        elif code in (-3, -6, -18, -19):
            raise MegaTempError(code)
        else:
            raise MegaError(code)

    def close(self):
        """Close the HTTP session."""
        try:
            self.session.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
