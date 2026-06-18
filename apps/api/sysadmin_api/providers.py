from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from .config import Settings
from .models import AgentIdentity, AgentName, ModelTier


class ProviderError(RuntimeError):
    pass


class AiProvider(ABC):
    name: str

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @abstractmethod
    async def complete_json(self, system: str, prompt: str) -> Dict[str, Any]:
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

    async def complete_json(self, system: str, prompt: str) -> Dict[str, Any]:
        headers = {"Authorization": "Bearer %s" % self.api_key}
        body = {
            "model": self.model,
            "response_format": {"type": "json_object"},
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
        content = response.json()["choices"][0]["message"]["content"]
        return self.parse_json(content)


class AnthropicProvider(AiProvider):
    name = "anthropic"

    async def complete_json(self, system: str, prompt: str) -> Dict[str, Any]:
        headers = {
            "x-api-key": str(self.api_key),
            "anthropic-version": "2023-06-01",
        }
        body = {
            "model": self.model,
            "max_tokens": 1200,
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
        content = response.json()["content"][0]["text"]
        return self.parse_json(content)


class OllamaProvider(AiProvider):
    name = "ollama"

    async def complete_json(self, system: str, prompt: str) -> Dict[str, Any]:
        body = {
            "model": self.model,
            "format": "json",
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post("%s/api/chat" % self.base_url, json=body)
            response.raise_for_status()
        return self.parse_json(response.json()["message"]["content"])


@dataclass
class RoutedModel:
    identity: AgentIdentity
    provider: Optional[AiProvider]


class ModelRouter:
    """Routes one capable orchestrator and two economy specialists."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def route(self, agent: AgentName) -> RoutedModel:
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
                    identity=self._identity(agent, tier, provider.name, provider.model),
                    provider=provider,
                )

        return RoutedModel(
            identity=self._identity(agent, ModelTier.DETERMINISTIC, "local", "policy-engine"),
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
    ) -> AgentIdentity:
        responsibilities = {
            AgentName.ORCHESTRATOR: (
                "Synthesizes specialist reports, chooses patch scope, explains risk, "
                "and creates an approval-gated rollout plan."
            ),
            AgentName.LOG_ANALYST: (
                "Reads system, authentication, kernel, boot, service, and package logs."
            ),
            AgentName.LINUX_STATE_ANALYST: (
                "Reads packages, resources, services, kernel state, and reboot indicators."
            ),
        }
        reason = (
            "Capable model selected for cross-agent decisions and operator explanations."
            if tier == ModelTier.CAPABLE
            else "Economy model selected for bounded specialist analysis."
        )
        if tier == ModelTier.DETERMINISTIC:
            reason = "No configured AI provider was available, so policy-safe local analysis was used."
        return AgentIdentity(
            name=agent,
            responsibility=responsibilities[agent],
            model_tier=tier,
            provider=provider,
            model=model,
            selection_reason=reason,
        )
