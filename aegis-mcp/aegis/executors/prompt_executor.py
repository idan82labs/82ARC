"""Prompt executor for LLM API testing.

Sends prompts to LLM APIs and evaluates responses.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from aegis.executors.base import Executor, ExecutorConfig, ExecutorResult

logger = logging.getLogger(__name__)


class PromptExecutor(Executor):
    """Executor for testing LLM prompt injection vulnerabilities."""

    name = "prompt-executor"

    def __init__(self, config: Optional[ExecutorConfig] = None):
        """Initialize prompt executor.

        Args:
            config: Executor configuration
        """
        super().__init__(config)
        self._client = None

    async def execute(
        self,
        test_case: Dict[str, Any],
        target_config: Dict[str, Any],
    ) -> ExecutorResult:
        """Execute a prompt injection test case.

        Args:
            test_case: Test case with input and expected output
            target_config: Target LLM configuration

        Returns:
            ExecutorResult with pass/fail and response
        """
        test_id = test_case.get("id", "unknown")
        input_spec = test_case.get("input", {})
        expected = test_case.get("expected", {})

        start_time = time.time()

        try:
            # Build the request based on input type
            request = self._build_request(input_spec, target_config)

            # Send request to target
            response, tokens = await self._send_request(request, target_config)

            latency_ms = int((time.time() - start_time) * 1000)

            # Evaluate response
            passed, reason = self.evaluate_response(response, expected)

            return ExecutorResult(
                test_id=test_id,
                passed=passed,
                response=self.redact_response(response),
                latency_ms=latency_ms,
                tokens_used=tokens,
                metadata={
                    "reason": reason,
                    "input_type": input_spec.get("type", "user_message"),
                    "expected_type": expected.get("type", "refusal"),
                },
            )

        except asyncio.TimeoutError:
            latency_ms = int((time.time() - start_time) * 1000)
            return ExecutorResult(
                test_id=test_id,
                passed=False,
                response="",
                latency_ms=latency_ms,
                error="Request timed out",
            )

        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            logger.exception(f"Error executing test {test_id}")
            return ExecutorResult(
                test_id=test_id,
                passed=False,
                response="",
                latency_ms=latency_ms,
                error=str(e),
            )

    def _build_request(
        self,
        input_spec: Dict[str, Any],
        target_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build API request from test input specification.

        Args:
            input_spec: Input specification from test case
            target_config: Target configuration

        Returns:
            Request payload
        """
        input_type = input_spec.get("type", "user_message")
        messages = []

        # Add system message if target has one
        system_prompt = target_config.get("system_prompt")
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if input_type == "user_message":
            # Simple user message
            messages.append({
                "role": "user",
                "content": input_spec.get("content", ""),
            })

        elif input_type == "multi_turn":
            # Multi-turn conversation
            for msg in input_spec.get("messages", []):
                messages.append({
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", ""),
                })

        elif input_type == "document_analysis":
            # Document analysis request
            doc = input_spec.get("document", {})
            query = input_spec.get("query", "")
            content = f"Document ({doc.get('type', 'text')}):\n{doc.get('content', '')}\n\nQuery: {query}"
            messages.append({"role": "user", "content": content})

        elif input_type == "web_fetch":
            # Simulated web fetch
            content = input_spec.get("simulated_content", "")
            query = input_spec.get("query", "")
            messages.append({
                "role": "user",
                "content": f"Webpage content:\n{content}\n\nQuery: {query}",
            })

        elif input_type == "rag_context":
            # RAG with retrieved context
            chunks = input_spec.get("retrieved_chunks", [])
            context = "\n\n".join(
                f"[Source: {c.get('source', 'unknown')}]\n{c.get('content', '')}"
                for c in chunks
            )
            query = input_spec.get("query", "")
            messages.append({
                "role": "user",
                "content": f"Context:\n{context}\n\nQuestion: {query}",
            })

        elif input_type == "tool_output":
            # Tool/function output injection
            tool_name = input_spec.get("tool_name", "tool")
            output = input_spec.get("output", "")
            query = input_spec.get("query", "")
            messages.append({
                "role": "user",
                "content": f"Tool '{tool_name}' returned:\n{output}\n\nQuery: {query}",
            })

        else:
            # Fallback to treating as user message
            messages.append({
                "role": "user",
                "content": input_spec.get("content", str(input_spec)),
            })

        return {
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

    async def _send_request(
        self,
        request: Dict[str, Any],
        target_config: Dict[str, Any],
    ) -> tuple:
        """Send request to target API.

        Args:
            request: Request payload
            target_config: Target configuration

        Returns:
            Tuple of (response_text, tokens_used)
        """
        api_type = target_config.get("api_type", "openai")
        timeout = self.config.timeout_ms / 1000

        if api_type == "openai":
            return await self._send_openai(request, target_config, timeout)
        elif api_type == "anthropic":
            return await self._send_anthropic(request, target_config, timeout)
        elif api_type == "mock":
            return await self._send_mock(request, target_config)
        else:
            raise ValueError(f"Unsupported API type: {api_type}")

    async def _send_openai(
        self,
        request: Dict[str, Any],
        target_config: Dict[str, Any],
        timeout: float,
    ) -> tuple:
        """Send request to OpenAI-compatible API."""
        import httpx

        base_url = target_config.get("base_url", "https://api.openai.com/v1")
        api_key = target_config.get("api_key", "")
        model = target_config.get("model", "gpt-4")

        payload = {
            "model": model,
            "messages": request["messages"],
            "max_tokens": request.get("max_tokens", 1024),
            "temperature": request.get("temperature", 0.7),
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens")

        return content, tokens

    async def _send_anthropic(
        self,
        request: Dict[str, Any],
        target_config: Dict[str, Any],
        timeout: float,
    ) -> tuple:
        """Send request to Anthropic API."""
        import httpx

        base_url = target_config.get("base_url", "https://api.anthropic.com")
        api_key = target_config.get("api_key", "")
        model = target_config.get("model", "claude-3-opus-20240229")

        # Convert messages format
        messages = request["messages"]
        system = None
        converted = []

        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                converted.append(msg)

        payload = {
            "model": model,
            "messages": converted,
            "max_tokens": request.get("max_tokens", 1024),
        }
        if system:
            payload["system"] = system

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{base_url}/v1/messages",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        content = data["content"][0]["text"]
        tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)

        return content, tokens

    async def _send_mock(
        self,
        request: Dict[str, Any],
        target_config: Dict[str, Any],
    ) -> tuple:
        """Mock API for testing without real API calls.

        Returns predefined responses based on target configuration.
        """
        mock_responses = target_config.get("mock_responses", {})
        default_response = target_config.get(
            "default_response",
            "I cannot help with that request."
        )

        # Check if any message content matches a mock response
        for msg in request.get("messages", []):
            content = msg.get("content", "")
            for pattern, response in mock_responses.items():
                if pattern.lower() in content.lower():
                    return response, 100

        # Check behavior mode
        behavior = target_config.get("behavior", "safe")
        if behavior == "vulnerable":
            # Simulate vulnerable model that complies
            return "Sure, I'll help with that. Here's how...", 100
        elif behavior == "partial":
            # Simulate partially safe model
            return "I shouldn't help with that, but here's some general info...", 100

        return default_response, 100


class BatchPromptExecutor(PromptExecutor):
    """Executor that runs multiple test cases in parallel."""

    name = "batch-prompt-executor"

    async def execute_batch(
        self,
        test_cases: List[Dict[str, Any]],
        target_config: Dict[str, Any],
        max_concurrency: int = 5,
    ) -> List[ExecutorResult]:
        """Execute multiple test cases with concurrency control.

        Args:
            test_cases: List of test cases
            target_config: Target configuration
            max_concurrency: Maximum parallel requests

        Returns:
            List of ExecutorResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrency)

        async def execute_with_semaphore(test_case: Dict[str, Any]) -> ExecutorResult:
            async with semaphore:
                return await self.execute(test_case, target_config)

        tasks = [execute_with_semaphore(tc) for tc in test_cases]
        return await asyncio.gather(*tasks)
