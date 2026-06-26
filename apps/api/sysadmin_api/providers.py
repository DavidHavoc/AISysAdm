from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from .config import Settings
from .models import AgentIdentity, AgentName, ModelTier


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderCompletion:
    data: Dict[str, Any]
    prompt_tokens: int = 0
    completion_tokens: int = 0


class AiProvider(ABC):
    name: str

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @property
    def external(self) -> bool:
        return self.name in ("openai", "anthropic")

    @abstractmethod
    async def complete_json(
        self,
        system: str,
        prompt: str,
        max_output_tokens: int,
    ) -> ProviderCompletion:
        raise NotImplementedError

    @staticmethod
    def parse_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end < start:
            raise ProviderError("Provider did not return a JSON object")
        return json.loads(cleaned[start : end + 1])


class OpenAiProvider(AiProvider):
    name = "openai"

    async def complete_json(
        self,
        system: str,
        prompt: str,
        max_output_tokens: int,
    ) -> ProviderCompletion:
        headers = {"Authorization": "Bearer %s" % self.api_key}
        body = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "max_tokens": max_output_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                "%s/chat/completions" % self.base_url,
                headers=headers,
                json=body,
            )
            response.raise_for_status()
        payload = response.json()
        usage = payload.get("usage", {})
        content = payload["choices"][0]["message"]["content"]
        return ProviderCompletion(
            data=self.parse_json(content),
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
        )


class AnthropicProvider(AiProvider):
    name = "anthropic"

    async def complete_json(
        self,
        system: str,
        prompt: str,
        max_output_tokens: int,
    ) -> ProviderCompletion:
        headers = {
            "x-api-key": str(self.api_key),
            "anthropic-version": "2023-06-01",
        }
        body = {
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                "%s/messages" % self.base_url,
                headers=headers,
                json=body,
            )
            response.raise_for_status()
        payload = response.json()
        usage = payload.get("usage", {})
        return ProviderCompletion(
            data=self.parse_json(payload["content"][0]["text"]),
            prompt_tokens=int(usage.get("input_tokens", 0)),
            completion_tokens=int(usage.get("output_tokens", 0)),
        )


class OllamaProvider(AiProvider):
    name = "ollama"

    async def complete_json(
        self,
        system: str,
        prompt: str,
        max_output_tokens: int,
    ) -> ProviderCompletion:
        body = {
            "model": self.model,
            "format": "json",
            "stream": False,
            "options": {"num_predict": max_output_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post("%s/api/chat" % self.base_url, json=body)
            response.raise_for_status()
        payload = response.json()
        return ProviderCompletion(
            data=self.parse_json(payload["message"]["content"]),
            prompt_tokens=int(payload.get("prompt_eval_count", 0)),
            completion_tokens=int(payload.get("eval_count", 0)),
        )


@dataclass
class RoutedModel:
    identity: AgentIdentity
    provider: Optional[AiProvider]


class ModelRouter:
    """Routes one capable orchestrator and two economy specialists."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def route(
        self,
        agent: AgentName,
        contract_version: int = 1,
        contract_hash: str = "",
    ) -> RoutedModel:
        tier = ModelTier.CAPABLE if agent == AgentName.ORCHESTRATOR else ModelTier.ECONOMY
        requested = (
            self.settings.ai_orchestrator_provider
            if agent == AgentName.ORCHESTRATOR
            else self.settings.ai_specialist_provider
        )
        candidates = self.settings.provider_order if requested == "auto" else [requested]
        for provider_name in candidates:
            provider = self._build(provider_name, tier)
            if provider:
                return RoutedModel(
                    identity=self._identity(
                        agent,
                        tier,
                        provider.name,
                        provider.model,
                        contract_version,
                        contract_hash,
                    ),
                    provider=provider,
                )

        return RoutedModel(
            identity=self._identity(
                agent,
                ModelTier.DETERMINISTIC,
                "local",
                "policy-engine",
                contract_version,
                contract_hash,
            ),
            provider=None,
        )

    def _build(self, name: str, tier: ModelTier) -> Optional[AiProvider]:
        strong = tier == ModelTier.CAPABLE
        if name == "openai":
            model = self.settings.openai_strong_model if strong else self.settings.openai_economy_model
            if self.settings.openai_api_key and model:
                return OpenAiProvider(
                    self.settings.openai_base_url,
                    model,
                    self.settings.openai_api_key,
                )
        if name == "anthropic":
            model = (
                self.settings.anthropic_strong_model
                if strong
                else self.settings.anthropic_economy_model
            )
            if self.settings.anthropic_api_key and model:
                return AnthropicProvider(
                    self.settings.anthropic_base_url,
                    model,
                    self.settings.anthropic_api_key,
                )
        if name == "ollama":
            model = self.settings.ollama_strong_model if strong else self.settings.ollama_economy_model
            if model:
                return OllamaProvider(self.settings.ollama_base_url, model)
        return None

    @staticmethod
    def _identity(
        agent: AgentName,
        tier: ModelTier,
        provider: str,
        model: str,
        contract_version: int,
        contract_hash: str,
    ) -> AgentIdentity:
        responsibilities = {
            AgentName.ORCHESTRATOR: (
                "Synthesizes verified specialist reports and creates approval-gated plans."
            ),
            AgentName.LOG_ANALYST: (
                "Analyzes bounded structured system, authentication, kernel, boot, and package logs."
            ),
            AgentName.LINUX_STATE_ANALYST: (
                "Analyzes packages, resources, services, kernel state, and reboot indicators."
            ),
        }
        reason = (
            "Capable model selected for cross-agent decisions and operator explanations."
            if tier == ModelTier.CAPABLE
            else "Economy model selected for bounded specialist analysis and review."
        )
        if tier == ModelTier.DETERMINISTIC:
            reason = "No configured provider was available; verified local policy was used."
        return AgentIdentity(
            name=agent,
            responsibility=responsibilities[agent],
            model_tier=tier,
            provider=provider,
            model=model,
            selection_reason=reason,
            contract_version=contract_version,
            contract_hash=contract_hash,
        )
