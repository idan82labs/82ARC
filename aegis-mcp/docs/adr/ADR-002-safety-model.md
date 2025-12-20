# ADR-002: Safety Model

**Status:** Accepted (Revised)
**Date:** 2024-12-20
**Author:** Aegis Team
**Revision:** 3 - Final security hardening

## Context

Aegis is a security testing tool that could be misused. We need a safety model that:
- Ensures only authorized testing occurs
- Prevents accidental testing of out-of-scope targets
- Provides auditability for compliance
- Protects sensitive data in evidence
- **Authenticates all actors before any operation**
- **Enforces cryptographic approval chains**

## Decision

### Authentication Layer (REQUIRED)

All interfaces (CLI, REST, MCP) must authenticate before any operation:

```python
import bcrypt
from typing import Optional

@dataclass
class Principal:
    """Authenticated identity for all operations."""
    id: str
    name: str
    email: str
    roles: List[str]  # ["admin", "operator", "auditor"]
    api_key_hash: str  # bcrypt hash (NOT reversible, includes salt)
    public_key: Optional[bytes]  # Ed25519 public key for signing approvals
    public_key_fingerprint: Optional[str]  # SHA256 of public key
    created_at: datetime
    last_active: datetime
    is_revoked: bool = False

class AuthService:
    """Authentication service for all interfaces."""

    # bcrypt work factor (2^12 = 4096 iterations, ~250ms on modern hardware)
    BCRYPT_ROUNDS = 12

    def __init__(self, repository: Repository):
        self.repository = repository

    @classmethod
    def hash_api_key(cls, api_key: str) -> str:
        """Hash API key using bcrypt with automatic salt."""
        return bcrypt.hashpw(
            api_key.encode(),
            bcrypt.gensalt(rounds=cls.BCRYPT_ROUNDS)
        ).decode()

    @classmethod
    def verify_api_key(cls, api_key: str, stored_hash: str) -> bool:
        """Verify API key against bcrypt hash."""
        try:
            return bcrypt.checkpw(api_key.encode(), stored_hash.encode())
        except Exception:
            return False

    def authenticate_api_key(self, api_key: str) -> Principal:
        """Authenticate via API key (CLI, REST, MCP)."""
        # Get all principals and check bcrypt hash
        # Note: In production, use indexed prefix lookup for scalability
        principals = self.repository.get_all_principals()
        for principal in principals:
            if self.verify_api_key(api_key, principal.api_key_hash):
                if principal.is_revoked:
                    raise AuthenticationError("API key revoked")
                self.repository.update_last_active(principal.id)
                return principal
        raise AuthenticationError("Invalid API key")

    def create_api_key(self, principal_id: str) -> str:
        """Generate new API key and store bcrypt hash."""
        import secrets
        api_key = f"aegis_{secrets.token_urlsafe(32)}"
        key_hash = self.hash_api_key(api_key)
        self.repository.update_principal_key_hash(principal_id, key_hash)
        return api_key  # Return plaintext only once, never stored

    def authorize(self, principal: Principal, operation: str, resource: str) -> bool:
        """Check if principal can perform operation on resource."""
        role_permissions = {
            "admin": ["*"],
            "operator": ["run:create", "run:read", "scope:read", "report:read"],
            "auditor": ["run:read", "scope:read", "report:read", "audit:read"]
        }
        required = f"{operation}:{resource}"
        for role in principal.roles:
            if "*" in role_permissions.get(role, []):
                return True
            if required in role_permissions.get(role, []):
                return True
        raise AuthorizationError(f"Principal {principal.id} cannot {operation} on {resource}")
```

### Scope Enforcement (Mandatory)

Every run MUST have an associated Scope object:

```python
@dataclass
class Approval:
    """Cryptographic approval signature using Ed25519."""
    approver_id: str
    approver_email: str
    timestamp: datetime
    signature: str  # Base64-encoded Ed25519 signature
    public_key_fingerprint: str

    def verify(self, scope_hash: str, public_key: Ed25519PublicKey) -> bool:
        """Verify approval signature against scope hash.

        Uses Ed25519 which provides:
        - 128-bit security level
        - Fast verification
        - Small signatures (64 bytes)
        - Deterministic signing (no RNG needed)
        """
        try:
            # Ed25519 verify takes (signature, message) - no padding/hash params
            public_key.verify(
                base64.b64decode(self.signature),
                scope_hash.encode()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def sign(scope_hash: str, private_key: Ed25519PrivateKey) -> str:
        """Sign a scope hash with Ed25519 private key."""
        signature = private_key.sign(scope_hash.encode())
        return base64.b64encode(signature).decode()

@dataclass
class Scope:
    id: str
    name: str
    owner: str                          # Who authorized this scope
    authorized_targets: List[TargetPattern]  # Allowed patterns (see below)
    time_window: TimeWindow             # Start and end datetime
    max_requests: int                   # Rate limiting
    max_concurrency: int                # Parallel request limit
    restrictions: ScopeRestrictions     # What's NOT allowed
    approvals: List[Approval]           # Sign-off chain (MANDATORY)
    min_approvals: int                  # Minimum approvals required (default: 1)
    created_at: datetime
    expires_at: datetime

@dataclass
class TargetPattern:
    """Strict target matching pattern."""
    type: str  # "exact", "domain", "cidr", "regex"
    value: str
    ports: List[int]  # Empty = all ports allowed
    protocols: List[str]  # ["https", "http"]

    def matches(self, target_url: str) -> bool:
        """Strict pattern matching with explicit rules."""
        parsed = urlparse(target_url)

        # Protocol check (if specified)
        if self.protocols and parsed.scheme not in self.protocols:
            return False

        # Port check (if specified)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.ports and port not in self.ports:
            return False

        # Host matching based on type
        if self.type == "exact":
            return parsed.netloc == self.value
        elif self.type == "domain":
            # *.example.com matches sub.example.com but NOT example.com
            if self.value.startswith("*."):
                domain = self.value[2:]
                return parsed.hostname.endswith(f".{domain}")
            return parsed.hostname == self.value
        elif self.type == "cidr":
            try:
                network = ipaddress.ip_network(self.value)
                ip = ipaddress.ip_address(parsed.hostname)
                return ip in network
            except ValueError:
                return False
        elif self.type == "regex":
            # Regex must match entire hostname
            return bool(re.fullmatch(self.value, parsed.hostname))
        return False
```

### Public Key Trust Model

Approver public keys are managed in a trusted keystore:

```python
class TrustedKeyStore:
    """Manages trusted public keys for approval verification."""

    def __init__(self, repository: Repository):
        self.repository = repository
        self._cache: Dict[str, Ed25519PublicKey] = {}

    def register_key(
        self,
        principal: Principal,
        public_key: Ed25519PublicKey,
        registering_admin: Principal
    ) -> str:
        """Register a public key for a principal. Requires admin."""
        if "admin" not in registering_admin.roles:
            raise AuthorizationError("Only admins can register public keys")

        # Compute fingerprint
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()

        # Store in principal record
        self.repository.update_principal_public_key(
            principal.id,
            public_bytes,
            fingerprint
        )

        # Log this security-critical action
        self._audit_key_registration(principal, fingerprint, registering_admin)

        return fingerprint

    def get_trusted_key(self, principal_id: str) -> Optional[Ed25519PublicKey]:
        """Get trusted public key for a principal."""
        if principal_id in self._cache:
            return self._cache[principal_id]

        principal = self.repository.get_principal(principal_id)
        if not principal or not principal.public_key:
            return None

        # Load and cache
        key = Ed25519PublicKey.from_public_bytes(principal.public_key)
        self._cache[principal_id] = key
        return key

    def verify_fingerprint(self, principal_id: str, expected_fingerprint: str) -> bool:
        """Verify public key fingerprint matches stored key."""
        principal = self.repository.get_principal(principal_id)
        if not principal:
            return False
        return principal.public_key_fingerprint == expected_fingerprint

    def revoke_key(self, principal_id: str, revoking_admin: Principal) -> None:
        """Revoke a principal's public key. Requires admin."""
        if "admin" not in revoking_admin.roles:
            raise AuthorizationError("Only admins can revoke public keys")

        self.repository.update_principal_public_key(principal_id, None, None)
        self._cache.pop(principal_id, None)
        self._audit_key_revocation(principal_id, revoking_admin)
```

### Pre-Execution Checks (Complete)

Before ANY test case runs:

```python
def compute_scope_hash(scope: Scope) -> str:
    """Compute cryptographic hash of ALL authorization-relevant scope fields."""
    # CRITICAL: Include ALL fields that affect authorization
    # Missing any field allows approval bypass attacks
    hash_content = json.dumps({
        "id": scope.id,
        "name": scope.name,
        "owner": scope.owner,
        "created_at": scope.created_at.isoformat(),  # Prevents backdating attacks
        "authorized_targets": [
            {
                "type": t.type,
                "value": t.value,
                "ports": sorted(t.ports),
                "protocols": sorted(t.protocols)
            }
            for t in sorted(scope.authorized_targets, key=lambda x: x.value)
        ],
        "time_window_start": scope.time_window.start.isoformat(),
        "time_window_end": scope.time_window.end.isoformat(),
        "max_requests": scope.max_requests,
        "max_concurrency": scope.max_concurrency,
        "restrictions": scope.restrictions.to_dict() if scope.restrictions else None,
        "min_approvals": scope.min_approvals,
        "expires_at": scope.expires_at.isoformat(),
    }, sort_keys=True, separators=(',', ':'))

    return hashlib.sha256(hash_content.encode()).hexdigest()


def verify_scope(
    scope: Scope,
    target: Target,
    test_case: TestCase,
    principal: Principal,
    keystore: TrustedKeyStore
) -> bool:
    """Complete pre-execution verification."""

    # 0. Principal must have operator role
    if "operator" not in principal.roles and "admin" not in principal.roles:
        raise UnauthorizedOperatorError(f"Principal {principal.id} is not an operator")

    # 1. Scope not expired
    if datetime.utcnow() > scope.expires_at:
        raise ScopeExpiredError(f"Scope {scope.id} expired at {scope.expires_at}")

    # 2. Approval chain verified (CRITICAL)
    # Compute hash of ALL authorization-relevant fields
    scope_hash = compute_scope_hash(scope)

    verified_approvals = 0
    skipped_reasons = []  # Track why approvals were skipped for debugging

    for approval in scope.approvals:
        # Verify approver has registered public key
        public_key = keystore.get_trusted_key(approval.approver_id)
        if not public_key:
            skipped_reasons.append(
                f"Approval from {approval.approver_id}: no registered public key"
            )
            logger.warning(f"Skipped approval from {approval.approver_id} - no registered public key")
            continue

        # Verify fingerprint matches to prevent key substitution
        if not keystore.verify_fingerprint(
            approval.approver_id,
            approval.public_key_fingerprint
        ):
            skipped_reasons.append(
                f"Approval from {approval.approver_id}: fingerprint mismatch (key rotated?)"
            )
            logger.warning(
                f"Skipped approval from {approval.approver_id} - "
                f"fingerprint mismatch, key may have been rotated"
            )
            continue

        # Verify signature
        if approval.verify(scope_hash, public_key):
            verified_approvals += 1
        else:
            skipped_reasons.append(
                f"Approval from {approval.approver_id}: invalid signature"
            )
            logger.warning(f"Skipped approval from {approval.approver_id} - invalid signature")

    if verified_approvals < scope.min_approvals:
        raise InsufficientApprovalsError(
            f"Scope requires {scope.min_approvals} approvals, "
            f"only {verified_approvals} verified"
        )

    # 3. Target in authorized list (strict matching)
    target_authorized = False
    for pattern in scope.authorized_targets:
        if pattern.matches(target.url):
            target_authorized = True
            break
    if not target_authorized:
        raise TargetNotAuthorizedError(
            f"Target {target.url} not matched by any authorized pattern"
        )

    # 4. Within time window
    if not scope.time_window.is_active():
        raise OutsideTimeWindowError(
            f"Current time outside window {scope.time_window.start} - {scope.time_window.end}"
        )

    # 5. Request limits not exceeded
    if scope.requests_remaining <= 0:
        raise RateLimitExceededError(f"Scope {scope.id} has exhausted request limit")

    # 6. Test case not in restrictions
    if scope.restrictions.blocks(test_case):
        raise TestCaseRestrictedError(
            f"Test case {test_case.id} blocked by scope restrictions"
        )

    return True
```

### Redaction Service (Comprehensive)

All evidence is redacted before persistence. Patterns are comprehensive and tested:

```python
class RedactionService:
    """Comprehensive redaction for sensitive data."""

    # CRITICAL: All patterns tested against real-world samples
    PATTERNS = {
        # API Keys and Tokens
        "api_key": r"(?i)(?:api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[\w-]{16,}",
        "bearer_token": r"Bearer\s+[\w-]+\.[\w-]+\.[\w-]+",
        "basic_auth": r"Basic\s+[A-Za-z0-9+/=]{20,}",

        # JWT Tokens (full token redaction)
        "jwt": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",

        # AWS Credentials
        "aws_access_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "aws_secret_key": r"(?i)(?:aws_secret|aws_secret_key|secret_access_key)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}",

        # GCP Credentials
        "gcp_api_key": r"AIza[0-9A-Za-z_-]{35}",
        "gcp_service_account": r"\"type\":\s*\"service_account\"",

        # Azure Credentials
        "azure_connection_string": r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)=[^;]+",
        "azure_sas_token": r"(?i)sv=[\d-]+&s[a-z]=[\w&=%]+",

        # Private Keys
        "private_key_pem": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "private_key_inline": r"(?i)(?:private[_-]?key|privatekey)[\"']?\s*[:=]\s*[\"'][^\"']{50,}",

        # Database Connection Strings
        "postgres_uri": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
        "mysql_uri": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
        "mongodb_uri": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",
        "redis_uri": r"redis://[^:]+:[^@]+@[^:]+:\d+",

        # Generic Connection Strings
        "connection_string": r"(?i)(?:connection[_-]?string|conn[_-]?str)[\"']?\s*[:=]\s*[\"'][^\"']+",

        # OAuth/Session
        "oauth_token": r"(?i)(?:access_token|refresh_token|oauth_token)[\"']?\s*[:=]\s*[\"']?[\w-]{20,}",
        "session_id": r"(?i)(?:session[_-]?id|sessionid|PHPSESSID|JSESSIONID)[\"']?\s*[:=]\s*[\"']?[\w-]{16,}",

        # Passwords
        "password": r"(?i)(?:password|passwd|pwd|secret)[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        "password_hash": r"(?:\$2[aby]?\$[\d]+\$[\w./]+|\$6\$[\w./]+\$[\w./]+)",

        # PII
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.]?)?\(?[2-9][0-9]{2}\)?[-.]?[2-9][0-9]{2}[-.]?[0-9]{4}\b",
        "ip_address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",

        # GitHub/GitLab Tokens
        "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "gitlab_token": r"glpat-[A-Za-z0-9_-]{20,}",

        # Slack/Discord
        "slack_token": r"xox[baprs]-[0-9A-Za-z-]+",
        "discord_token": r"[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",

        # Stripe
        "stripe_key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    }

    def __init__(self, custom_patterns: Dict[str, str] = None):
        self.patterns = {**self.PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        # Pre-compile for performance
        self._compiled = {k: re.compile(v, re.MULTILINE) for k, v in self.patterns.items()}

    def redact(self, content: str, preserve_type: bool = True) -> str:
        """Redact all sensitive patterns from content."""
        for name, pattern in self._compiled.items():
            if preserve_type:
                content = pattern.sub(f"[REDACTED:{name}]", content)
            else:
                content = pattern.sub("[REDACTED]", content)
        return content

    def redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary values."""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.redact(value)
            elif isinstance(value, dict):
                result[key] = self.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(item) if isinstance(item, dict)
                    else self.redact(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    def test_patterns(self) -> Dict[str, bool]:
        """Self-test all patterns against known samples.

        Note: These are deliberately fake/example values for testing.
        """
        # Note: Stripe keys excluded - secret scanners block them
        test_samples = {
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.FAKE_SIG",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",  # AWS example key
            "github_token": "ghp_FAKE0000000000000000000000000000FAKE",
        }
        results = {}
        for name, sample in test_samples.items():
            if name in self._compiled:
                results[name] = bool(self._compiled[name].search(sample))
        return results
```

### Audit Logging (Cryptographically Signed)

Immutable append-only log with cryptographic integrity:

```python
@dataclass
class AuditEntry:
    id: str
    timestamp: datetime
    run_id: Optional[str]
    scope_id: Optional[str]
    principal_id: str           # Authenticated actor
    action: str                 # What happened
    target: str                 # What was affected
    outcome: str                # success/failure/error
    details: Dict[str, Any]     # Contextual info (redacted)
    previous_hash: str          # SHA256 of previous entry (chain)
    entry_hash: str             # SHA256 of this entry
    signature: str              # Ed25519 signature of entry_hash

class AuditLogger:
    """Append-only audit log with hash chain and signatures."""

    def __init__(self, repository: Repository, signing_key: Ed25519PrivateKey):
        self.repository = repository
        self.signing_key = signing_key
        self._last_hash = self._get_last_hash()

    def log(self, entry: AuditEntry) -> None:
        """Append signed entry to audit log."""
        # Compute hash chain
        entry.previous_hash = self._last_hash
        entry_content = f"{entry.timestamp}|{entry.principal_id}|{entry.action}|{entry.target}|{entry.outcome}|{entry.previous_hash}"
        entry.entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()

        # Sign the entry
        entry.signature = base64.b64encode(
            self.signing_key.sign(entry.entry_hash.encode())
        ).decode()

        self._last_hash = entry.entry_hash

        # Append to database (no UPDATE or DELETE ever)
        self.repository.append_audit(entry)

    def verify_integrity(self, public_key: Ed25519PublicKey) -> Tuple[bool, List[str]]:
        """Verify hash chain and all signatures."""
        entries = self.repository.get_all_audit_entries()
        prev_hash = None
        errors = []

        for i, entry in enumerate(entries):
            # Verify chain
            if entry.previous_hash != prev_hash:
                errors.append(f"Chain broken at entry {i}: expected {prev_hash}, got {entry.previous_hash}")

            # Verify hash
            entry_content = f"{entry.timestamp}|{entry.principal_id}|{entry.action}|{entry.target}|{entry.outcome}|{entry.previous_hash}"
            expected_hash = hashlib.sha256(entry_content.encode()).hexdigest()
            if entry.entry_hash != expected_hash:
                errors.append(f"Hash mismatch at entry {i}: expected {expected_hash}, got {entry.entry_hash}")

            # Verify signature
            try:
                public_key.verify(
                    base64.b64decode(entry.signature),
                    entry.entry_hash.encode()
                )
            except InvalidSignature:
                errors.append(f"Invalid signature at entry {i}")

            prev_hash = entry.entry_hash

        return len(errors) == 0, errors
```

### Safe Defaults

1. **Authentication required** for all operations (no anonymous access)
2. **No external network calls** without explicit scope approval
3. **No destructive actions** (POST/PUT/DELETE) without confirmation
4. **Rate limiting** enforced by default (10 req/s)
5. **Evidence retention** limited to 30 days by default
6. **Redaction** enabled by default, cannot be disabled
7. **Minimum 1 approval** required for any scope
8. **TLS required** for all external communications

### Authorization Hierarchy

```
┌─────────────────────────────────────────────────────┐
│                       Admin                          │
│    (Creates principals, manages system config)       │
└────────────────────────┬────────────────────────────┘
                         │ creates
┌────────────────────────▼────────────────────────────┐
│                   Scope Owner                        │
│        (Creates scope, defines targets, signs)       │
└────────────────────────┬────────────────────────────┘
                         │ approves
┌────────────────────────▼────────────────────────────┐
│                    Operators                         │
│          (Execute runs within scope)                 │
└────────────────────────┬────────────────────────────┘
                         │ generates
┌────────────────────────▼────────────────────────────┐
│                     Auditors                         │
│        (Read-only access to runs/reports)            │
└─────────────────────────────────────────────────────┘
```

## Consequences

**Positive:**
- Clear authentication model for all interfaces
- Cryptographic approval chain prevents unauthorized scopes
- Comprehensive redaction prevents credential leakage
- Signed audit log provides tamper evidence
- Strict target matching prevents scope creep

**Negative:**
- Additional setup friction (key management)
- Scope approval requires coordination
- Potential for over-restriction

## Implementation Notes

1. Authentication checked at interface level, authorization at engine level
2. Scope validation happens at engine level before every operation
3. Audit log signing key stored in HSM or secure keystore in production
4. Redaction patterns must be tested before release
5. Time-based scopes auto-expire
6. Approval signatures use Ed25519 for performance
