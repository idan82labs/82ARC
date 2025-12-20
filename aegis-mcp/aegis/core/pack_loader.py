"""Secure pack loader for declarative YAML packs.

Implements:
- YAML-only pack loading (NO Python code execution)
- Schema validation
- Path traversal protection
- Executor whitelist
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import yaml
from jsonschema import validate, ValidationError

from aegis.core.exceptions import (
    InvalidPackError,
    PackNotFoundError,
    SecurityError,
    UnknownExecutorError,
)
from aegis.core.models import DetectionConfig, TestCase
from aegis.core.storage import SecurePath

logger = logging.getLogger(__name__)


# JSON Schema for manifest validation
MANIFEST_SCHEMA = {
    "type": "object",
    "required": ["id", "name", "version"],
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z_]+$"},
        "name": {"type": "string"},
        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "description": {"type": "string"},
        "author": {"type": "string"},
        "license": {"type": "string"},
        "aegis_version_min": {"type": "string"},
        "mappings": {
            "type": "object",
            "properties": {
                "owasp_llm": {"type": "array", "items": {"type": "string"}},
                "mitre_atlas": {"type": "array", "items": {"type": "string"}},
            },
        },
        "test_suites": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file"],
                "properties": {"file": {"type": "string"}},
            },
        },
        "config_schema": {"type": "object"},
    },
}

# JSON Schema for test suite validation
TEST_SUITE_SCHEMA = {
    "type": "object",
    "required": ["id", "name", "executor", "executor_version", "test_cases"],
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "executor": {"type": "string"},
        "executor_version": {"type": "string"},
        "requirements": {"type": "object"},
        "test_cases": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "input_template", "detection", "severity"],
            },
        },
    },
}


@dataclass
class TestSuite:
    """A test suite within a pack."""

    id: str
    name: str
    description: str
    executor: str
    executor_version: str
    test_cases: List[TestCase]
    requirements: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TestSuite":
        test_cases = []
        for tc_data in data.get("test_cases", []):
            detection_data = tc_data.get("detection", {})
            detection = DetectionConfig(
                type=detection_data.get("type", "pattern_match"),
                failure_patterns=detection_data.get("failure_patterns"),
                success_patterns=detection_data.get("success_patterns"),
                analyzer=detection_data.get("analyzer"),
                failure_threshold=detection_data.get("failure_threshold"),
            )
            test_cases.append(
                TestCase(
                    id=tc_data["id"],
                    name=tc_data["name"],
                    description=tc_data.get("description", ""),
                    category=tc_data.get("category", "general"),
                    owasp_llm=tc_data.get("owasp_llm", []),
                    mitre_atlas=tc_data.get("mitre_atlas", []),
                    input_template=tc_data["input_template"],
                    variables=tc_data.get("variables", {}),
                    detection=detection,
                    severity=tc_data["severity"],
                    confidence_threshold=tc_data.get("confidence_threshold", 0.8),
                    remediation=tc_data.get("remediation", ""),
                    references=tc_data.get("references", []),
                )
            )

        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            executor=data["executor"],
            executor_version=data["executor_version"],
            test_cases=test_cases,
            requirements=data.get("requirements", {}),
        )


@dataclass
class Pack:
    """A versioned test pack."""

    id: str
    name: str
    version: str
    description: str
    author: str
    test_suites: List[TestSuite]
    mappings: Dict[str, List[str]] = field(default_factory=dict)
    config_schema: Dict[str, Any] = field(default_factory=dict)

    def all_tests(self) -> List[TestCase]:
        """Get all test cases from all suites."""
        tests = []
        for suite in self.test_suites:
            tests.extend(suite.test_cases)
        return tests

    @property
    def test_count(self) -> int:
        """Total number of test cases."""
        return sum(len(s.test_cases) for s in self.test_suites)


class ExecutorRegistry:
    """Registry of built-in test executors. NO external code loading."""

    _executors: Dict[str, Type] = {}

    @classmethod
    def register(cls, name: str, version: str):
        """Decorator to register built-in executor."""

        def decorator(executor_class):
            key = f"{name}:{version}"
            cls._executors[key] = executor_class
            logger.debug(f"Registered executor: {key}")
            return executor_class

        return decorator

    @classmethod
    def get(cls, name: str, version: str) -> Type:
        """Get executor by name and version."""
        key = f"{name}:{version}"
        if key not in cls._executors:
            raise UnknownExecutorError(f"No executor registered: {key}")
        return cls._executors[key]

    @classmethod
    def list_executors(cls) -> List[str]:
        """List all registered executors."""
        return list(cls._executors.keys())


class SecurePackLoader:
    """Loads packs from declarative YAML only. NO code execution."""

    def __init__(self, packs_directory: Path):
        """Initialize pack loader.

        Args:
            packs_directory: Base directory containing pack folders
        """
        self.packs_dir = Path(packs_directory)
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        self.secure_path = SecurePath(self.packs_dir)
        self._validate_packs_directory()

    def _validate_packs_directory(self):
        """Ensure no Python files exist in packs directory."""
        for py_file in self.packs_dir.rglob("*.py"):
            raise SecurityError(
                f"Python files not allowed in packs directory: {py_file}"
            )
        for pyc_file in self.packs_dir.rglob("*.pyc"):
            raise SecurityError(
                f"Compiled Python not allowed in packs directory: {pyc_file}"
            )
        logger.debug(f"Validated packs directory: {self.packs_dir}")

    def load_pack(self, pack_id: str) -> Pack:
        """Load and validate a pack from YAML files.

        Args:
            pack_id: Pack ID (directory name)

        Returns:
            Loaded Pack object

        Raises:
            PackNotFoundError: If pack doesn't exist
            InvalidPackError: If pack fails validation
            SecurityError: If security constraints violated
        """
        # Validate pack_id is safe
        self.secure_path.validate_component(pack_id)
        pack_dir = self.packs_dir / pack_id

        if not pack_dir.exists():
            raise PackNotFoundError(f"Pack not found: {pack_id}")

        # Re-validate no Python files
        for py_file in pack_dir.rglob("*.py"):
            raise SecurityError(f"Python files not allowed: {py_file}")

        # Load manifest
        manifest_path = pack_dir / "manifest.yaml"
        if not manifest_path.exists():
            # Try .yml extension
            manifest_path = pack_dir / "manifest.yml"
            if not manifest_path.exists():
                raise InvalidPackError(f"No manifest.yaml in {pack_dir}")

        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)

        # Validate manifest
        try:
            validate(manifest, MANIFEST_SCHEMA)
        except ValidationError as e:
            raise InvalidPackError(f"Invalid manifest: {e.message}")

        # Load test suites
        test_suites = []
        for suite_ref in manifest.get("test_suites", []):
            suite_file = suite_ref["file"]
            suite = self._load_test_suite(pack_dir, suite_file)
            test_suites.append(suite)

        pack = Pack(
            id=manifest["id"],
            name=manifest["name"],
            version=manifest["version"],
            description=manifest.get("description", ""),
            author=manifest.get("author", "Unknown"),
            test_suites=test_suites,
            mappings=manifest.get("mappings", {}),
            config_schema=manifest.get("config_schema", {}),
        )

        logger.info(
            f"Loaded pack: {pack.id} v{pack.version} ({pack.test_count} tests)"
        )
        return pack

    def _load_test_suite(self, pack_dir: Path, suite_file: str) -> TestSuite:
        """Load and validate a test suite.

        Args:
            pack_dir: Pack directory
            suite_file: Relative path to suite file

        Returns:
            Loaded TestSuite object
        """
        # Path traversal protection
        suite_path = (pack_dir / suite_file).resolve()
        if not str(suite_path).startswith(str(pack_dir.resolve())):
            raise SecurityError(f"Path traversal detected: {suite_file}")

        if not suite_path.exists():
            raise InvalidPackError(f"Test suite not found: {suite_path}")

        with open(suite_path) as f:
            data = yaml.safe_load(f)

        # Validate against schema
        try:
            validate(data, TEST_SUITE_SCHEMA)
        except ValidationError as e:
            raise InvalidPackError(f"Invalid test suite {suite_file}: {e.message}")

        # Verify executor exists in registry
        executor_name = data["executor"]
        executor_version = data["executor_version"]
        try:
            ExecutorRegistry.get(executor_name, executor_version)
        except UnknownExecutorError:
            # For now, just log a warning - we'll register executors later
            logger.warning(
                f"Executor {executor_name}:{executor_version} not registered yet"
            )

        return TestSuite.from_dict(data)

    def list_packs(self) -> List[str]:
        """List available pack IDs.

        Returns:
            List of pack directory names
        """
        packs = []
        for path in self.packs_dir.iterdir():
            if path.is_dir():
                manifest = path / "manifest.yaml"
                if not manifest.exists():
                    manifest = path / "manifest.yml"
                if manifest.exists():
                    packs.append(path.name)
        return packs

    def validate_pack(self, pack_id: str) -> Dict[str, Any]:
        """Validate a pack without fully loading it.

        Args:
            pack_id: Pack ID to validate

        Returns:
            Validation result with any errors
        """
        errors = []
        warnings = []

        try:
            pack = self.load_pack(pack_id)

            # Check for unregistered executors
            for suite in pack.test_suites:
                try:
                    ExecutorRegistry.get(suite.executor, suite.executor_version)
                except UnknownExecutorError:
                    warnings.append(
                        f"Executor {suite.executor}:{suite.executor_version} "
                        "not registered"
                    )

            # Check test cases
            for suite in pack.test_suites:
                for tc in suite.test_cases:
                    if not tc.remediation:
                        warnings.append(
                            f"Test case {tc.id} missing remediation guidance"
                        )
                    if not tc.owasp_llm and not tc.mitre_atlas:
                        warnings.append(
                            f"Test case {tc.id} missing standards mapping"
                        )

            return {
                "valid": len(errors) == 0,
                "pack_id": pack.id,
                "version": pack.version,
                "test_count": pack.test_count,
                "errors": errors,
                "warnings": warnings,
            }

        except (PackNotFoundError, InvalidPackError, SecurityError) as e:
            return {
                "valid": False,
                "pack_id": pack_id,
                "errors": [str(e)],
                "warnings": [],
            }
