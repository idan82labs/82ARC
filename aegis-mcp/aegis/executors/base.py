"""Base executor interface for Aegis test execution.

Executors handle the actual sending of test payloads to targets
and collecting responses for analysis.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ExecutorConfig:
    """Configuration for an executor."""

    max_tokens: int = 1024
    temperature: float = 0.7
    timeout_ms: int = 30000
    retry_count: int = 2
    retry_delay_ms: int = 1000
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutorResult:
    """Result from executing a test case."""

    test_id: str
    passed: bool
    response: str
    latency_ms: int
    tokens_used: Optional[int] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "passed": self.passed,
            "response": self.response,
            "latency_ms": self.latency_ms,
            "tokens_used": self.tokens_used,
            "error": self.error,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


class Executor(ABC):
    """Base class for test executors."""

    name: str = "base"

    def __init__(self, config: Optional[ExecutorConfig] = None):
        """Initialize executor.

        Args:
            config: Executor configuration
        """
        self.config = config or ExecutorConfig()

    @abstractmethod
    async def execute(
        self,
        test_case: Dict[str, Any],
        target_config: Dict[str, Any],
    ) -> ExecutorResult:
        """Execute a test case against a target.

        Args:
            test_case: Test case definition from YAML
            target_config: Target configuration

        Returns:
            ExecutorResult with outcome
        """
        ...

    def evaluate_response(
        self,
        response: str,
        expected: Dict[str, Any],
    ) -> tuple:
        """Evaluate response against expected patterns.

        Args:
            response: Response from target
            expected: Expected outcome from test case

        Returns:
            Tuple of (passed: bool, reason: str)
        """
        response_lower = response.lower()

        # Check expected type
        expected_type = expected.get("type", "refusal")

        # Check must_not_contain (failure conditions)
        must_not_contain = expected.get("must_not_contain", [])
        for forbidden in must_not_contain:
            if forbidden.lower() in response_lower:
                return False, f"Response contains forbidden content: '{forbidden}'"

        # Check required patterns
        patterns = expected.get("patterns", [])
        if patterns:
            matched_any = False
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    matched_any = True
                    break

            if expected_type == "refusal" and not matched_any:
                return False, "Response does not contain expected refusal patterns"

        # Check for specific required content
        must_contain = expected.get("must_contain", [])
        for required in must_contain:
            if required.lower() not in response_lower:
                return False, f"Response missing required content: '{required}'"

        return True, "Response matches expected patterns"

    def redact_response(self, response: str, max_length: int = 500) -> str:
        """Redact and truncate response for logging.

        Args:
            response: Full response
            max_length: Maximum length to keep

        Returns:
            Redacted response
        """
        if len(response) > max_length:
            return response[:max_length] + "... [truncated]"
        return response
