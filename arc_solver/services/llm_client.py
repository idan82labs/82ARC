"""
Multi-provider LLM API client.
Supports: Together, Groq, OpenRouter, Fireworks, OpenAI, Anthropic
"""
import asyncio
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from loguru import logger

from ..config import (
    Provider, get_model_spec, get_provider_config, 
    get_available_providers, ModelSpec, ProviderConfig
)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Message:
    """A chat message."""
    role: str  # "system", "user", "assistant"
    content: str

@dataclass
class LLMResponse:
    """Response from an LLM API call."""
    content: str
    model: str
    provider: Provider
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost: float = 0.0

@dataclass
class TokenUsage:
    """Cumulative token usage tracker."""
    input_tokens: int = 0
    output_tokens: int = 0
    total_cost: float = 0.0
    api_calls: int = 0
    
    def add(self, response: LLMResponse):
        self.input_tokens += response.input_tokens
        self.output_tokens += response.output_tokens
        self.total_cost += response.cost
        self.api_calls += 1

# ============================================================================
# BASE PROVIDER
# ============================================================================

class BaseProvider(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=120.0)
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    @abstractmethod
    async def complete(
        self,
        messages: List[Message],
        model_spec: ModelSpec,
        **kwargs
    ) -> LLMResponse:
        pass
    
    def _calculate_cost(
        self, 
        input_tokens: int, 
        output_tokens: int,
        model_spec: ModelSpec
    ) -> float:
        input_cost = (input_tokens / 1_000_000) * model_spec.cost_per_million_input
        output_cost = (output_tokens / 1_000_000) * model_spec.cost_per_million_output
        return input_cost + output_cost

# ============================================================================
# OPENAI-COMPATIBLE PROVIDERS (Together, Groq, OpenRouter, Fireworks, OpenAI)
# ============================================================================

class OpenAICompatibleProvider(BaseProvider):
    """Provider using OpenAI-compatible API."""
    
    provider_type: Provider = Provider.OPENAI
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException))
    )
    async def complete(
        self,
        messages: List[Message],
        model_spec: ModelSpec,
        **kwargs
    ) -> LLMResponse:
        start_time = time.time()
        
        payload = {
            "model": model_spec.model_id,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": model_spec.max_tokens,
            "temperature": model_spec.temperature,
        }
        
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }
        
        # Add provider-specific headers
        if self.provider_type == Provider.OPENROUTER:
            headers["HTTP-Referer"] = "https://github.com/arc-solver"
            headers["X-Title"] = "ARC-AGI Solver"
        
        url = f"{self.config.base_url}/chat/completions"
        
        response = await self.client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        latency = (time.time() - start_time) * 1000
        
        usage = data.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        
        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=model_spec.model_id,
            provider=self.provider_type,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency,
            cost=self._calculate_cost(input_tokens, output_tokens, model_spec)
        )

class TogetherProvider(OpenAICompatibleProvider):
    provider_type = Provider.TOGETHER

class GroqProvider(OpenAICompatibleProvider):
    provider_type = Provider.GROQ

class OpenRouterProvider(OpenAICompatibleProvider):
    provider_type = Provider.OPENROUTER

class FireworksProvider(OpenAICompatibleProvider):
    provider_type = Provider.FIREWORKS
    
    async def complete(self, messages: List[Message], model_spec: ModelSpec, **kwargs) -> LLMResponse:
        # Fireworks uses a different model path format
        original_id = model_spec.model_id
        if not model_spec.model_id.startswith("accounts/"):
            model_spec = ModelSpec(
                **{**model_spec.model_dump(), "model_id": f"accounts/fireworks/models/{model_spec.model_id}"}
            )
        result = await super().complete(messages, model_spec, **kwargs)
        return result

class OpenAIProvider(OpenAICompatibleProvider):
    provider_type = Provider.OPENAI

# ============================================================================
# ANTHROPIC PROVIDER
# ============================================================================

class AnthropicProvider(BaseProvider):
    """Anthropic Claude API provider."""
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException))
    )
    async def complete(
        self,
        messages: List[Message],
        model_spec: ModelSpec,
        **kwargs
    ) -> LLMResponse:
        start_time = time.time()
        
        # Separate system message
        system_msg = None
        chat_messages = []
        for m in messages:
            if m.role == "system":
                system_msg = m.content
            else:
                chat_messages.append({"role": m.role, "content": m.content})
        
        payload = {
            "model": model_spec.model_id,
            "messages": chat_messages,
            "max_tokens": model_spec.max_tokens,
        }
        if system_msg:
            payload["system"] = system_msg
        
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        response = await self.client.post(
            f"{self.config.base_url}/messages",
            json=payload,
            headers=headers
        )
        response.raise_for_status()
        data = response.json()
        
        latency = (time.time() - start_time) * 1000
        
        usage = data.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        
        return LLMResponse(
            content=data["content"][0]["text"],
            model=model_spec.model_id,
            provider=Provider.ANTHROPIC,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency,
            cost=self._calculate_cost(input_tokens, output_tokens, model_spec)
        )

# ============================================================================
# UNIFIED CLIENT
# ============================================================================

class LLMClient:
    """
    Unified LLM client that routes requests to appropriate providers.
    Tracks usage and supports parallel requests.
    """
    
    def __init__(self):
        self.providers: Dict[Provider, BaseProvider] = {}
        self.usage = TokenUsage()
        self._initialized = False
    
    async def __aenter__(self):
        await self._init_providers()
        return self
    
    async def __aexit__(self, *args):
        for provider in self.providers.values():
            await provider.__aexit__(*args)
    
    async def _init_providers(self):
        """Initialize available providers."""
        if self._initialized:
            return
        
        provider_classes = {
            Provider.TOGETHER: TogetherProvider,
            Provider.GROQ: GroqProvider,
            Provider.OPENROUTER: OpenRouterProvider,
            Provider.FIREWORKS: FireworksProvider,
            Provider.OPENAI: OpenAIProvider,
            Provider.ANTHROPIC: AnthropicProvider,
        }
        
        for provider_type in get_available_providers():
            config = get_provider_config(provider_type)
            if config.api_key:
                provider_class = provider_classes[provider_type]
                provider = provider_class(config)
                await provider.__aenter__()
                self.providers[provider_type] = provider
                logger.debug(f"Initialized provider: {provider_type.value}")
        
        self._initialized = True
    
    async def complete(
        self,
        messages: List[Message],
        model_name: str,
        **kwargs
    ) -> LLMResponse:
        """
        Generate a completion using the specified model.
        
        Args:
            messages: List of chat messages
            model_name: Name of the model (from config)
            **kwargs: Additional arguments
            
        Returns:
            LLMResponse
        """
        await self._init_providers()
        
        model_spec = get_model_spec(model_name)
        
        if model_spec.provider not in self.providers:
            raise ValueError(
                f"Provider {model_spec.provider.value} not available. "
                f"Available: {[p.value for p in self.providers.keys()]}"
            )
        
        provider = self.providers[model_spec.provider]
        response = await provider.complete(messages, model_spec, **kwargs)
        self.usage.add(response)
        
        return response
    
    async def complete_parallel(
        self,
        prompts: List[List[Message]],
        model_name: str,
        **kwargs
    ) -> List[LLMResponse]:
        """Generate multiple completions in parallel."""
        tasks = [
            self.complete(messages, model_name, **kwargs)
            for messages in prompts
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get usage summary."""
        return {
            "input_tokens": self.usage.input_tokens,
            "output_tokens": self.usage.output_tokens,
            "total_tokens": self.usage.input_tokens + self.usage.output_tokens,
            "total_cost": round(self.usage.total_cost, 4),
            "api_calls": self.usage.api_calls,
        }
    
    def reset_usage(self):
        """Reset usage tracking."""
        self.usage = TokenUsage()

# ============================================================================
# SINGLETON
# ============================================================================

_client: Optional[LLMClient] = None

async def get_llm_client() -> LLMClient:
    """Get or create the global LLM client."""
    global _client
    if _client is None:
        _client = LLMClient()
        await _client._init_providers()
    return _client
