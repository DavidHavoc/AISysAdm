from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from .models import AgentName


@dataclass(frozen=True)
class AgentContract:
    agent: AgentName
    version: int
    model_tier: str
    max_input_tokens: int
    max_output_tokens: int
    max_conversation_rounds: int
    content: str
    content_hash: str
    path: Path


class AgentContractLoader:
    filenames: Dict[AgentName, str] = {
        AgentName.ORCHESTRATOR: "orchestrator.md",
        AgentName.LINUX_STATE_ANALYST: "linux-state.md",
        AgentName.LOG_ANALYST: "log-analysis.md",
    }

    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self, agent: AgentName) -> AgentContract:
        path = self.root / self.filenames[agent]
        if not path.exists():
            raise RuntimeError("Agent contract is missing: %s" % path)
        content = path.read_text(encoding="utf-8")
        metadata = parse_front_matter(content)
        if metadata.get("id") != agent.value:
            raise RuntimeError("Agent contract id does not match %s" % agent.value)
        rounds = int(metadata.get("max_conversation_rounds", "0"))
        if rounds > 1:
            raise RuntimeError("Alpha agent contracts may allow at most one review round")
        return AgentContract(
            agent=agent,
            version=int(metadata.get("version", "1")),
            model_tier=metadata.get("model_tier", "economy"),
            max_input_tokens=int(metadata.get("max_input_tokens", "7000")),
            max_output_tokens=int(metadata.get("max_output_tokens", "1200")),
            max_conversation_rounds=rounds,
            content=content,
            content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            path=path,
        )

    def load_all(self) -> Dict[AgentName, AgentContract]:
        return {agent: self.load(agent) for agent in self.filenames}


def parse_front_matter(content: str) -> Dict[str, str]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        raise RuntimeError("Agent contract requires YAML-style front matter")
    metadata: Dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return metadata
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()
    raise RuntimeError("Agent contract front matter is not closed")
