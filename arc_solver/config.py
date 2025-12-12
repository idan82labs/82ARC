"""
Unified configuration system with YAML + environment variable support.
Supports multiple LLM providers and flexible strategy profiles.
"""
import os
from pathlib import Path
from functools import lru_cache
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
import yaml

# ============================================================================
# PATHS
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_PATH = os.environ.get("ARC_SOLVER_CONFIG", str(PROJECT_ROOT / "configs" / "default.yaml"))
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"

DATA_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# ============================================================================
# ENUMS
# ============================================================================

class Provider(str, Enum):
    TOGETHER = "together"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    FIREWORKS = "fireworks"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

# ============================================================================
# CONFIG MODELS
# ============================================================================

class AppConfig(BaseModel):
    env: str = "local"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

class ProviderConfig(BaseModel):
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    enabled: bool = True

class ModelSpec(BaseModel):
    provider: Provider
    model_id: str
    max_tokens: int = 4096
    temperature: float = 0.7
    cost_per_million_input: float = 0.0
    cost_per_million_output: float = 0.0

class ModelsConfig(BaseModel):
    # Role assignments - ALL SMALL MODELS (7B-32B)
    solver: str = "qwen3-coder-32b-groq"      # 32B - code generation
    reasoner: str = "qwen3-8b-groq"            # 8B - reasoning
    critic: str = "deepseek-r1-32b"            # 32B - critique/review
    verifier: str = "llama4-scout-8b-groq"     # 8B - verification
    mcts_solver: str = "qwen3-7b-together"     # 7B - MCTS tactic generation
    
    # Model definitions
    definitions: Dict[str, ModelSpec] = Field(default_factory=dict)

class MCTSConfig(BaseModel):
    max_iterations: int = 10
    exploration_weight: float = 1.41
    max_depth: int = 3
    parallel_expansions: int = 3

class SolverConfig(BaseModel):
    max_iterations: int = 10
    max_hypotheses_per_iteration: int = 5
    max_revision_attempts: int = 5
    max_cost_per_task: float = 10.0
    max_tokens_per_task: int = 500_000
    parallel_hypotheses: bool = True
    stop_on_solved: bool = True

class AugmentationConfig(BaseModel):
    enable_rotation: bool = True
    enable_flip: bool = True
    enable_color_permutation: bool = False
    rotation_angles: List[int] = [90, 180, 270]

class StrategyProfile(BaseModel):
    cost_budget_usd: float = 5.0
    solver: SolverConfig = Field(default_factory=SolverConfig)
    mcts: MCTSConfig = Field(default_factory=MCTSConfig)
    augmentation: AugmentationConfig = Field(default_factory=AugmentationConfig)

class ToolsConfig(BaseModel):
    execution_timeout: float = 5.0
    max_memory_mb: int = 256
    sandbox_mode: str = "subprocess"  # "subprocess" or "inprocess"

class Config(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    providers: Dict[str, ProviderConfig] = Field(default_factory=dict)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    strategies: Dict[str, StrategyProfile] = Field(default_factory=lambda: {"default": StrategyProfile()})
    default_strategy: str = "default"
    tools: ToolsConfig = Field(default_factory=ToolsConfig)

# ============================================================================
# ENVIRONMENT SUBSTITUTION
# ============================================================================

def _apply_env_substitution(raw: Any) -> Any:
    """Replace ${VAR:default} patterns with environment values."""
    if isinstance(raw, str):
        if raw.startswith("${") and ":" in raw and raw.endswith("}"):
            body = raw[2:-1]
            if ":" in body:
                env_name, default = body.split(":", 1)
                return os.environ.get(env_name.strip(), default.strip())
            return os.environ.get(body.strip(), "")
        # Also handle simple $VAR patterns
        if raw.startswith("$") and not raw.startswith("${"):
            env_name = raw[1:]
            return os.environ.get(env_name, "")
    if isinstance(raw, dict):
        return {k: _apply_env_substitution(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return [_apply_env_substitution(v) for v in raw]
    return raw

# ============================================================================
# CONFIG LOADING
# ============================================================================

def _load_from_env() -> Dict[str, ProviderConfig]:
    """Load provider configs from environment variables."""
    providers = {}
    
    env_mappings = {
        "together": ("TOGETHER_API_KEY", "https://api.together.xyz/v1"),
        "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1"),
        "openrouter": ("OPENROUTER_API_KEY", "https://openrouter.ai/api/v1"),
        "fireworks": ("FIREWORKS_API_KEY", "https://api.fireworks.ai/inference/v1"),
        "openai": ("OPENAI_API_KEY", "https://api.openai.com/v1"),
        "anthropic": ("ANTHROPIC_API_KEY", "https://api.anthropic.com/v1"),
    }
    
    for provider, (env_key, base_url) in env_mappings.items():
        api_key = os.environ.get(env_key)
        providers[provider] = ProviderConfig(
            api_key=api_key,
            base_url=base_url,
            enabled=bool(api_key)
        )
    
    return providers

def _default_model_definitions() -> Dict[str, ModelSpec]:
    """Default model definitions (December 2025)."""
    return {
        # =====================================================================
        # SMALL MODELS (7B-32B) - Core of our approach
        # =====================================================================

        # Qwen 3 Coder 32B on Groq (fastest inference)
        "qwen3-coder-32b-groq": ModelSpec(
            provider=Provider.GROQ,
            model_id="qwen-3-coder-32b",
            max_tokens=8192,
            temperature=0.7,
            cost_per_million_input=0.29,
            cost_per_million_output=0.59,
        ),

        # Qwen 3 8B on Groq (small, fast reasoning)
        "qwen3-8b-groq": ModelSpec(
            provider=Provider.GROQ,
            model_id="qwen-3-8b",
            max_tokens=4096,
            temperature=0.7,
            cost_per_million_input=0.05,
            cost_per_million_output=0.10,
        ),

        # Llama 4 Scout 8B on Groq (verification)
        "llama4-scout-8b-groq": ModelSpec(
            provider=Provider.GROQ,
            model_id="llama-4-scout-8b",
            max_tokens=2048,
            temperature=0.2,
            cost_per_million_input=0.05,
            cost_per_million_output=0.08,
        ),

        # Qwen 3 7B on Together AI (MCTS tactic generation)
        "qwen3-7b-together": ModelSpec(
            provider=Provider.TOGETHER,
            model_id="Qwen/Qwen3-7B-Instruct",
            max_tokens=8192,
            temperature=0.7,
            cost_per_million_input=0.20,
            cost_per_million_output=0.20,
        ),

        # Qwen 3 Coder 7B on OpenRouter (alternative small coder)
        "qwen3-coder-7b-openrouter": ModelSpec(
            provider=Provider.OPENROUTER,
            model_id="qwen/qwen-3-coder-7b-instruct",
            max_tokens=8192,
            temperature=0.7,
            cost_per_million_input=0.15,
            cost_per_million_output=0.15,
        ),

        # DeepSeek R1 Distill 32B (reasoning, stays within small model range)
        "deepseek-r1-32b": ModelSpec(
            provider=Provider.TOGETHER,
            model_id="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
            max_tokens=8192,
            temperature=0.7,
            cost_per_million_input=0.89,
            cost_per_million_output=0.89,
        ),

        # =====================================================================
        # FRONTIER FALLBACKS (for comparison only, not default)
        # =====================================================================

        "gpt-5.2-mini": ModelSpec(
            provider=Provider.OPENAI,
            model_id="gpt-5.2-mini",
            max_tokens=4096,
            temperature=0.7,
            cost_per_million_input=3.00,
            cost_per_million_output=12.00,
        ),
        "claude-sonnet": ModelSpec(
            provider=Provider.ANTHROPIC,
            model_id="claude-sonnet-4-20250514",
            max_tokens=4096,
            temperature=0.7,
            cost_per_million_input=3.00,
            cost_per_million_output=15.00,
        ),
    }

@lru_cache
def load_config() -> Config:
    """Load configuration from YAML file and environment."""
    # Try to load from YAML
    config_data = {}
    if Path(CONFIG_PATH).exists():
        with open(CONFIG_PATH, "r") as f:
            raw = yaml.safe_load(f) or {}
        config_data = _apply_env_substitution(raw)
    
    # Load providers from environment
    providers = _load_from_env()
    if "providers" in config_data:
        for name, prov_data in config_data["providers"].items():
            if name in providers:
                providers[name] = ProviderConfig(**{**providers[name].model_dump(), **prov_data})
    config_data["providers"] = {k: v.model_dump() for k, v in providers.items()}
    
    # Add default model definitions
    if "models" not in config_data:
        config_data["models"] = {}
    if "definitions" not in config_data["models"]:
        config_data["models"]["definitions"] = {}
    
    defaults = _default_model_definitions()
    for name, spec in defaults.items():
        if name not in config_data["models"]["definitions"]:
            config_data["models"]["definitions"][name] = spec.model_dump()
    
    return Config.model_validate(config_data)

# ============================================================================
# HELPERS
# ============================================================================

def get_model_spec(name: str) -> ModelSpec:
    """Get model specification by name."""
    cfg = load_config()
    if name not in cfg.models.definitions:
        raise ValueError(f"Unknown model: {name}. Available: {list(cfg.models.definitions.keys())}")
    return cfg.models.definitions[name]

def get_provider_config(provider: Provider) -> ProviderConfig:
    """Get provider configuration."""
    cfg = load_config()
    return cfg.providers.get(provider.value, ProviderConfig())

def get_available_providers() -> List[Provider]:
    """Get list of providers with valid API keys."""
    cfg = load_config()
    return [
        Provider(name) for name, prov in cfg.providers.items()
        if prov.enabled and prov.api_key
    ]

def get_strategy(name: str = None) -> StrategyProfile:
    """Get strategy profile by name."""
    cfg = load_config()
    name = name or cfg.default_strategy
    if name not in cfg.strategies:
        return cfg.strategies.get("default", StrategyProfile())
    return cfg.strategies[name]

def validate_config() -> bool:
    """Validate configuration and check for required API keys."""
    available = get_available_providers()
    if not available:
        raise ValueError(
            "No API keys configured! Please set at least one of: "
            "TOGETHER_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, etc."
        )
    return True
