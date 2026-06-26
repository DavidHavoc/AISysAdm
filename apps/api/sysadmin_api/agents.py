from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .contracts import AgentContract, AgentContractLoader
from .memory import AgentMemory
from .models import (
    AgentMessage,
    AgentName,
    AgentReport,
    AgentRun,
    AiDecision,
    Evidence,
    Finding,
    Host,
    HostSnapshot,
    RecommendedAction,
    RebootAssessment,
    Remediation,
    RolloutPolicy,
    Severity,
    utc_now,
)
from .providers import ModelRouter, ProviderCompletion, ProviderError, RoutedModel
from .redaction import compact_json, redact_payload, redact_text
from .verifier import DeterministicVerifier


def new_id(prefix: str) -> str:
    return "%s-%s" % (prefix, uuid4().hex[:12])


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def severity_value(value: Any) -> str:
    return value.value if isinstance(value, Severity) else str(value)


def remediation_plan_hash(remediation: Remediation) -> str:
    reboot = remediation.reboot_assessment.model_dump(mode="json")
    reboot.pop("approved_if_required", None)
    return stable_hash(
        {
            "plan_version": remediation.plan_version,
            "host_id": remediation.host_id,
            "scan_id": remediation.scan_id,
            "action_type": remediation.action_type,
            "update_scope": remediation.update_scope,
            "risk_level": severity_value(remediation.risk_level),
            "decision": remediation.ai_decision.model_dump(mode="json"),
            "reboot": reboot,
            "rollout": remediation.rollout_policy.model_dump(mode="json"),
            "failure_policy": remediation.failure_policy.model_dump(mode="json"),
            "timing": remediation.execution_timing,
            "maintenance_window": (
                remediation.maintenance_window.model_dump(mode="json")
                if remediation.maintenance_window
                else None
            ),
            "approval_scope": remediation.approval_scope,
            "pre_change_protection": remediation.pre_change_protection,
        }
    )


@dataclass
class WorkflowResult:
    findings: List[Finding]
    remediation: Optional[Remediation]
    reports: List[AgentReport]
    runs: List[AgentRun]
    messages: List[AgentMessage]
    rejected_claims: List[str]


class SpecialistAgent:
    name: AgentName

    def __init__(
        self,
        router: ModelRouter,
        memory: AgentMemory,
        contract: AgentContract,
    ) -> None:
        self.contract = contract
        self.routed = router.route(
            self.name,
            contract.version,
            contract.content_hash,
        )
        self.memory = memory

    async def analyze(
        self,
        scan_id: str,
        host: Host,
        snapshot: HostSnapshot,
    ) -> Tuple[AgentReport, AgentRun, AgentMessage]:
        findings = self.policy_findings(host, snapshot)
        overview = self.fallback_overview(findings)
        fallback_reason: Optional[str] = None
        completion = ProviderCompletion(data={})
        cache_hit = False
        payload = {
            "host": host.model_dump(mode="json"),
            "snapshot": snapshot.model_dump(mode="json"),
            "policy_findings": [item.model_dump(mode="json") for item in findings],
            "required_output": {"overview": "string"},
        }
        prompt, input_hash, cache_key = self._prepare_prompt(host, payload, "analysis")
        started = time.perf_counter()
        cached = self.memory.get(cache_key)
        if cached:
            cache_hit = True
            cached_payload = json.loads(cached)
            overview = str(cached_payload.get("overview") or overview)
            completion = ProviderCompletion(data=cached_payload)
        elif self.routed.provider:
            try:
                completion = await self.routed.provider.complete_json(
                    self.contract.content,
                    prompt,
                    self.contract.max_output_tokens,
                )
                overview = str(completion.data.get("overview") or overview)
                self.memory.put(cache_key, json.dumps({"overview": overview}))
            except Exception as error:
                fallback_reason = safe_provider_error(error)
                overview = "%s Provider enrichment was unavailable; verified policy output was retained." % overview
        else:
            fallback_reason = "No AI provider configured; deterministic specialist analysis used."

        report = AgentReport(
            agent=self.routed.identity,
            overview=overview,
            findings=findings,
        )
        run = AgentRun(
            id=new_id("agent-run"),
            scan_id=scan_id,
            agent=self.routed.identity,
            status="succeeded",
            input_hash=input_hash,
            output=report.model_dump(mode="json"),
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            cache_hit=cache_hit,
            fallback_reason=fallback_reason,
            externally_processed=bool(
                self.routed.provider and self.routed.provider.external
            ),
            created_at=utc_now(),
        )
        message = AgentMessage(
            id=new_id("agent-message"),
            scan_id=scan_id,
            from_agent=self.name,
            to_agent=AgentName.ORCHESTRATOR,
            response="report",
            claim_ids=[item.id for item in findings],
            reasoning=overview,
            citations=[
                evidence.citation
                for item in findings
                for evidence in item.evidence
            ],
            created_at=utc_now(),
        )
        return report, run, message

    async def peer_review(
        self,
        scan_id: str,
        host: Host,
        own_report: AgentReport,
        other_report: AgentReport,
    ) -> Tuple[AgentMessage, Optional[AgentRun]]:
        relevant = self.relevant_claims(own_report, other_report)
        other_agent = other_report.agent.name
        if not relevant:
            return (
                AgentMessage(
                    id=new_id("agent-message"),
                    scan_id=scan_id,
                    from_agent=self.name,
                    to_agent=other_agent,
                    response="not_applicable",
                    reasoning="The other specialist produced no claims relevant to this agent's evidence domain.",
                    created_at=utc_now(),
                ),
                None,
            )

        deterministic = self.deterministic_review(relevant)
        response_data = deterministic
        fallback_reason: Optional[str] = None
        completion = ProviderCompletion(data={})
        cache_hit = False
        payload = {
            "own_findings": [
                item.model_dump(mode="json") for item in own_report.findings
            ],
            "claims_to_review": [
                item.model_dump(mode="json") for item in relevant
            ],
            "required_output": {
                "response": "confirm|challenge|request_evidence|not_applicable",
                "claim_ids": ["string"],
                "reasoning": "string",
                "citations": ["string"],
            },
        }
        prompt, input_hash, cache_key = self._prepare_prompt(host, payload, "peer-review")
        started = time.perf_counter()
        cached = self.memory.get(cache_key)
        if cached:
            cache_hit = True
            response_data = json.loads(cached)
        elif self.routed.provider:
            try:
                completion = await self.routed.provider.complete_json(
                    self.contract.content,
                    prompt,
                    min(self.contract.max_output_tokens, 600),
                )
                response_data = validate_review_response(
                    completion.data,
                    relevant,
                    deterministic,
                )
                self.memory.put(cache_key, json.dumps(response_data))
            except Exception as error:
                fallback_reason = safe_provider_error(error)
        else:
            fallback_reason = "No AI provider configured; deterministic peer review used."

        message = AgentMessage(
            id=new_id("agent-message"),
            scan_id=scan_id,
            from_agent=self.name,
            to_agent=other_agent,
            response=response_data["response"],
            claim_ids=response_data["claim_ids"],
            reasoning=response_data["reasoning"],
            citations=response_data["citations"],
            created_at=utc_now(),
        )
        run = AgentRun(
            id=new_id("agent-run"),
            scan_id=scan_id,
            agent=self.routed.identity,
            status="succeeded",
            input_hash=input_hash,
            output=response_data,
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            cache_hit=cache_hit,
            fallback_reason=fallback_reason,
            externally_processed=bool(
                self.routed.provider and self.routed.provider.external
            ),
            created_at=utc_now(),
        )
        return message, run

    def _prepare_prompt(
        self,
        host: Host,
        payload: Dict[str, Any],
        purpose: str,
    ) -> Tuple[str, str, str]:
        provider_payload = (
            redact_payload(payload, host)
            if self.routed.provider and self.routed.provider.external
            else payload
        )
        prompt = compact_json(provider_payload, self.contract.max_input_tokens)
        input_hash = stable_hash(
            {
                "purpose": purpose,
                "contract": self.contract.content_hash,
                "provider": self.routed.identity.provider,
                "model": self.routed.identity.model,
                "prompt": prompt,
            }
        )
        return prompt, input_hash, "agent-cache:%s" % input_hash

    def relevant_claims(
        self,
        own_report: AgentReport,
        other_report: AgentReport,
    ) -> List[Finding]:
        if not own_report.findings or not other_report.findings:
            return []
        own_high = any(
            severity_value(item.severity) in ("high", "critical")
            for item in own_report.findings
        )
        return [
            item
            for item in other_report.findings
            if own_high
            or severity_value(item.severity) in ("high", "critical")
            or item.category in {own.category for own in own_report.findings}
        ]

    def deterministic_review(self, claims: List[Finding]) -> Dict[str, Any]:
        citations = [
            evidence.citation for claim in claims for evidence in claim.evidence
        ]
        missing = [claim.id for claim in claims if not claim.evidence]
        return {
            "response": "request_evidence" if missing else "confirm",
            "claim_ids": missing or [claim.id for claim in claims],
            "reasoning": (
                "One or more claims have no cited evidence."
                if missing
                else "The claims are consistent with the supplied evidence and do not contradict this specialist's report."
            ),
            "citations": citations,
        }

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        raise NotImplementedError

    def fallback_overview(self, findings: List[Finding]) -> str:
        return "%s produced %s evidence-backed finding(s)." % (
            self.name.value,
            len(findings),
        )


class LogAnalysisAgent(SpecialistAgent):
    name = AgentName.LOG_ANALYST

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        findings: List[Finding] = []
        if snapshot.service_summary.failed_units:
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "service_health",
                    Severity.HIGH,
                    "%s failed service unit(s) detected."
                    % len(snapshot.service_summary.failed_units),
                    "Journal evidence and systemd state agree that service health requires review.",
                    [
                        Evidence(
                            source="systemctl --failed",
                            excerpt=", ".join(snapshot.service_summary.failed_units),
                            citation="serviceSummary.failedUnits",
                        ),
                        Evidence(
                            source="journalctl",
                            excerpt=snapshot.logs.journal[:400],
                            citation="logs.journal",
                        ),
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Review failed services",
                        rationale="A pre-existing failure makes post-patch validation ambiguous.",
                    ),
                    0.96,
                )
            )
        if "authentication failure" in snapshot.logs.auth.lower():
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "authentication",
                    Severity.MEDIUM,
                    "Authentication failures were found in recent SSH logs.",
                    "The redacted events should be correlated with expected operator access.",
                    [
                        Evidence(
                            source="SSH journal",
                            excerpt=snapshot.logs.auth[:400],
                            citation="logs.auth",
                        )
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Review authentication events",
                        rationale="Identity events require operator context.",
                    ),
                    0.82,
                )
            )
        if snapshot.logs.kernel and any(
            token in snapshot.logs.kernel.lower()
            for token in ("out of memory", "oom-killer", "i/o error", "filesystem error")
        ):
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "kernel_health",
                    Severity.CRITICAL,
                    "Critical kernel or resource events were detected.",
                    "Kernel evidence contains an OOM, I/O, or filesystem failure marker.",
                    [
                        Evidence(
                            source="kernel journal",
                            excerpt=snapshot.logs.kernel[:400],
                            citation="logs.kernel",
                        )
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Review critical kernel events",
                        rationale="Patching should not proceed until the host is stable.",
                    ),
                    0.95,
                )
            )
        return findings


class LinuxStateAgent(SpecialistAgent):
    name = AgentName.LINUX_STATE_ANALYST

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        findings: List[Finding] = []
        packages = snapshot.package_summary
        if packages.pending_package_updates:
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "patching",
                    Severity.HIGH if packages.pending_security_updates else Severity.MEDIUM,
                    "%s package update(s) are pending, including %s security update(s)."
                    % (
                        packages.pending_package_updates,
                        packages.pending_security_updates,
                    ),
                    "The orchestrator must choose a cataloged update scope and request approval.",
                    [
                        Evidence(
                            source="apt list --upgradable",
                            excerpt=snapshot.commands.get("upgradable_packages", "")[:600],
                            citation="commands.upgradable_packages",
                        )
                    ],
                    RecommendedAction(
                        action_type="package_upgrade",
                        title="Create a controlled patch plan",
                        rationale="Package changes must use a cataloged Ansible playbook.",
                    ),
                    0.98,
                )
            )
        if snapshot.system_summary.disk_usage_percent >= 80:
            severity = (
                Severity.CRITICAL
                if snapshot.system_summary.disk_usage_percent >= 95
                else Severity.MEDIUM
            )
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "capacity",
                    severity,
                    "Root filesystem usage is %.0f%%."
                    % snapshot.system_summary.disk_usage_percent,
                    "Low free space can cause package installation and metadata operations to fail.",
                    [
                        Evidence(
                            source="df -P /",
                            excerpt="%.0f%% used"
                            % snapshot.system_summary.disk_usage_percent,
                            citation="systemSummary.diskUsagePercent",
                        )
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Verify free disk space",
                        rationale="Automated cleanup is not in the action catalog.",
                    ),
                    0.99,
                )
            )
        if snapshot.package_summary.held_packages:
            findings.append(
                make_finding(
                    host,
                    self.name,
                    "patching",
                    Severity.MEDIUM,
                    "Held packages may prevent a complete patch transaction.",
                    "The held-package list must be reviewed before execution.",
                    [
                        Evidence(
                            source="apt-mark showhold",
                            excerpt=", ".join(snapshot.package_summary.held_packages),
                            citation="commands.held_packages",
                        )
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Review held packages",
                        rationale="The alpha does not automatically remove package holds.",
                    ),
                    0.99,
                )
            )
        return findings


class OrchestratorAgent:
    def __init__(
        self,
        router: ModelRouter,
        memory: AgentMemory,
        contract: AgentContract,
    ) -> None:
        self.contract = contract
        self.routed: RoutedModel = router.route(
            AgentName.ORCHESTRATOR,
            contract.version,
            contract.content_hash,
        )
        self.memory = memory

    async def synthesize(
        self,
        scan_id: str,
        host: Host,
        snapshot: HostSnapshot,
        reports: List[AgentReport],
        peer_messages: List[AgentMessage],
        rejected_claims: List[str],
    ) -> Tuple[Optional[Remediation], AgentRun, AgentMessage]:
        findings = [item for report in reports for item in report.findings]
        deterministic_scope = (
            host.patch_policy.update_mode
            if host.patch_policy.update_mode in ("all", "security")
            else ("all" if snapshot.package_summary.pending_package_updates else "none")
        )
        conflicts = [
            message.reasoning
            for message in peer_messages
            if message.response in ("challenge", "request_evidence")
        ] + rejected_claims
        citations = sorted(
            {
                evidence.citation
                for finding in findings
                for evidence in finding.evidence
            }
        )
        fallback = {
            "update_scope": deterministic_scope,
            "risk_level": "high" if findings else "info",
            "explanation": (
                "Verified evidence supports a controlled package plan."
                if deterministic_scope != "none"
                else "No package remediation is required."
            ),
            "status": "insufficient_evidence" if conflicts else "plan_ready",
            "supporting_citations": citations,
            "unresolved_conflicts": conflicts,
        }
        payload = {
            "host_policy": host.patch_policy.model_dump(mode="json"),
            "host_criticality": host.criticality,
            "availability_class": host.availability_class,
            "verified_reports": [report.model_dump(mode="json") for report in reports],
            "peer_review_messages": [
                message.model_dump(mode="json") for message in peer_messages
            ],
            "policy_constraints": {
                "allowed_scopes": ["all", "security", "none"],
                "human_approval_required": True,
                "arbitrary_commands_forbidden": True,
            },
        }
        provider_payload = (
            redact_payload(payload, host)
            if self.routed.provider and self.routed.provider.external
            else payload
        )
        prompt = compact_json(provider_payload, self.contract.max_input_tokens)
        input_hash = stable_hash(
            {
                "contract": self.contract.content_hash,
                "provider": self.routed.identity.provider,
                "model": self.routed.identity.model,
                "prompt": prompt,
            }
        )
        cache_key = "agent-cache:%s" % input_hash
        response = fallback
        completion = ProviderCompletion(data={})
        cache_hit = False
        fallback_reason: Optional[str] = None
        started = time.perf_counter()
        cached = self.memory.get(cache_key)
        if cached:
            cache_hit = True
            response = validate_orchestrator_response(
                json.loads(cached),
                fallback,
                citations,
            )
        elif self.routed.provider:
            try:
                completion = await self.routed.provider.complete_json(
                    self.contract.content,
                    prompt,
                    self.contract.max_output_tokens,
                )
                response = validate_orchestrator_response(
                    completion.data,
                    fallback,
                    citations,
                )
                self.memory.put(cache_key, json.dumps(response))
            except Exception as error:
                fallback_reason = safe_provider_error(error)
        else:
            fallback_reason = "No AI provider configured; deterministic synthesis used."
        if host.patch_policy.update_mode in ("all", "security"):
            response["update_scope"] = host.patch_policy.update_mode

        run = AgentRun(
            id=new_id("agent-run"),
            scan_id=scan_id,
            agent=self.routed.identity,
            status="succeeded",
            input_hash=input_hash,
            output=response,
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
            cache_hit=cache_hit,
            fallback_reason=fallback_reason,
            externally_processed=bool(
                self.routed.provider and self.routed.provider.external
            ),
            created_at=utc_now(),
        )
        message = AgentMessage(
            id=new_id("agent-message"),
            scan_id=scan_id,
            from_agent=AgentName.ORCHESTRATOR,
            to_agent=AgentName.ORCHESTRATOR,
            response="synthesis",
            claim_ids=[finding.id for finding in findings],
            reasoning=response["explanation"],
            citations=response["supporting_citations"],
            created_at=utc_now(),
        )
        remediation = self._build_remediation(
            scan_id,
            host,
            snapshot,
            reports,
            response,
        )
        return remediation, run, message

    def _build_remediation(
        self,
        scan_id: str,
        host: Host,
        snapshot: HostSnapshot,
        reports: List[AgentReport],
        response: Dict[str, Any],
    ) -> Optional[Remediation]:
        if (
            response["status"] != "plan_ready"
            or response["update_scope"] == "none"
            or snapshot.package_summary.pending_package_updates == 0
        ):
            return None
        update_scope = response["update_scope"]
        reboot = assess_reboot(snapshot, update_scope)
        risk = enforce_risk(
            host,
            snapshot,
            Severity(response["risk_level"]),
            reboot,
        )
        rollout = rollout_policy(host, risk)
        decision = AiDecision(
            update_scope=update_scope,
            risk_level=risk,
            explanation=response["explanation"],
            status=response["status"],
            supporting_citations=response["supporting_citations"],
            unresolved_conflicts=response["unresolved_conflicts"],
            agent_assignments=[self.routed.identity]
            + [report.agent for report in reports],
        )
        remediation = Remediation(
            id=new_id("remediation"),
            host_id=host.id,
            scan_id=scan_id,
            title="Patch %s with %s updates" % (host.name, update_scope),
            update_scope=update_scope,
            risk_level=risk,
            ai_decision=decision,
            reboot_assessment=reboot,
            rollout_policy=rollout,
            execution_timing=host.patch_policy.execution_timing,
            maintenance_window=host.patch_policy.maintenance_window,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        if host.snapshot_platform != "none":
            remediation.pre_change_protection = {
                "supported": True,
                "status": "configured",
                "provider": host.snapshot_platform,
                "retention_days": host.snapshot_retention_days,
            }
        remediation.plan_hash = remediation_plan_hash(remediation)
        return remediation


class MultiAgentWorkflow:
    def __init__(
        self,
        router: ModelRouter,
        memory: AgentMemory,
        contracts: AgentContractLoader,
    ) -> None:
        loaded = contracts.load_all()
        self.log_agent = LogAnalysisAgent(
            router,
            memory,
            loaded[AgentName.LOG_ANALYST],
        )
        self.state_agent = LinuxStateAgent(
            router,
            memory,
            loaded[AgentName.LINUX_STATE_ANALYST],
        )
        self.orchestrator = OrchestratorAgent(
            router,
            memory,
            loaded[AgentName.ORCHESTRATOR],
        )
        self.verifier = DeterministicVerifier()

    async def run(
        self,
        scan_id: str,
        host: Host,
        snapshot: HostSnapshot,
    ) -> WorkflowResult:
        state_result, log_result = await asyncio.gather(
            self.state_agent.analyze(scan_id, host, snapshot),
            self.log_agent.analyze(scan_id, host, snapshot),
        )
        state_report, state_run, state_message = state_result
        log_report, log_run, log_message = log_result
        review_results = await asyncio.gather(
            self.state_agent.peer_review(
                scan_id,
                host,
                state_report,
                log_report,
            ),
            self.log_agent.peer_review(
                scan_id,
                host,
                log_report,
                state_report,
            ),
        )
        peer_messages = [item[0] for item in review_results]
        peer_runs = [item[1] for item in review_results if item[1] is not None]
        all_findings = state_report.findings + log_report.findings
        verified, rejected = self.verifier.verify_findings(
            snapshot,
            all_findings,
            peer_messages,
        )
        state_report.findings = [
            item for item in verified if item.source_agent == AgentName.LINUX_STATE_ANALYST
        ]
        log_report.findings = [
            item for item in verified if item.source_agent == AgentName.LOG_ANALYST
        ]
        remediation, orchestrator_run, synthesis_message = (
            await self.orchestrator.synthesize(
                scan_id,
                host,
                snapshot,
                [state_report, log_report],
                peer_messages,
                rejected,
            )
        )
        return WorkflowResult(
            findings=verified,
            remediation=remediation,
            reports=[state_report, log_report],
            runs=[state_run, log_run] + peer_runs + [orchestrator_run],
            messages=[
                state_message,
                log_message,
            ]
            + peer_messages
            + [synthesis_message],
            rejected_claims=rejected,
        )


def make_finding(
    host: Host,
    source: AgentName,
    category: str,
    severity: Severity,
    summary: str,
    explanation: str,
    evidence: List[Evidence],
    action: Optional[RecommendedAction],
    confidence: float,
) -> Finding:
    return Finding(
        id=new_id("finding"),
        host_id=host.id,
        source_agent=source,
        category=category,
        severity=severity,
        summary=summary,
        explanation=explanation,
        evidence=evidence,
        recommended_action=action,
        requires_approval=action is not None,
        confidence=confidence,
        created_at=utc_now(),
    )


def validate_review_response(
    response: Dict[str, Any],
    relevant: List[Finding],
    fallback: Dict[str, Any],
) -> Dict[str, Any]:
    allowed_responses = {
        "confirm",
        "challenge",
        "request_evidence",
        "not_applicable",
    }
    result = dict(fallback)
    provider_response = response.get("response")
    if (
        result["response"] != "request_evidence"
        and provider_response in allowed_responses
    ):
        result["response"] = provider_response
    allowed_claim_ids = {item.id for item in relevant}
    claim_ids = [
        str(item)
        for item in response.get("claim_ids", [])
        if str(item) in allowed_claim_ids
    ]
    if claim_ids:
        result["claim_ids"] = claim_ids
    result["reasoning"] = str(response.get("reasoning") or result["reasoning"])[:1000]
    allowed_citations = {
        evidence.citation for item in relevant for evidence in item.evidence
    }
    result["citations"] = [
        str(item)
        for item in response.get("citations", [])
        if str(item) in allowed_citations
    ]
    return result


def validate_orchestrator_response(
    response: Dict[str, Any],
    fallback: Dict[str, Any],
    allowed_citations: List[str],
) -> Dict[str, Any]:
    result = dict(fallback)
    if response.get("update_scope") in ("all", "security", "none"):
        result["update_scope"] = response["update_scope"]
    if response.get("risk_level") in ("info", "low", "medium", "high", "critical"):
        result["risk_level"] = response["risk_level"]
    if (
        result["status"] != "insufficient_evidence"
        and response.get("status") in ("plan_ready", "insufficient_evidence")
    ):
        result["status"] = response["status"]
    result["explanation"] = str(
        response.get("explanation") or result["explanation"]
    )[:1600]
    allowed = set(allowed_citations)
    supplied = [
        str(item)
        for item in response.get("supporting_citations", [])
        if str(item) in allowed
    ]
    if supplied:
        result["supporting_citations"] = supplied
    provider_conflicts = [
        str(item)[:500] for item in response.get("unresolved_conflicts", [])
    ][:10]
    result["unresolved_conflicts"] = list(
        dict.fromkeys(result["unresolved_conflicts"] + provider_conflicts)
    )[:10]
    if result["unresolved_conflicts"]:
        result["status"] = "insufficient_evidence"
    return result


def safe_provider_error(error: Exception) -> str:
    if isinstance(error, ProviderError):
        return redact_text(str(error))[:300]
    return "AI provider request failed; deterministic output used."


def assess_reboot(snapshot: HostSnapshot, update_scope: str) -> RebootAssessment:
    package_summary = snapshot.package_summary
    if package_summary.reboot_required_now:
        status = "required"
        rationale = "The host already has a reboot-required marker."
    else:
        selected = [
            item
            for item in package_summary.updates
            if update_scope == "all" or item.security_update
        ]
        reboot_packages = [item.name for item in selected if item.reboot_hint]
        if reboot_packages:
            status = "required_after_patch"
            rationale = (
                "Selected kernel or core system packages are expected to require a reboot: %s."
                % ", ".join(reboot_packages)
            )
        elif selected:
            status = "unknown"
            rationale = "The final reboot decision must be checked after package installation."
        else:
            status = "not_expected"
            rationale = "No selected package has a known reboot hint."
    return RebootAssessment(
        status=status,
        rationale=rationale,
        evidence=[
            Evidence(
                source="reboot marker and package classification",
                excerpt=rationale,
                citation="packageSummary",
            )
        ],
        estimated_downtime_minutes=5 if status != "not_expected" else 0,
        approved_if_required=False,
    )


def enforce_risk(
    host: Host,
    snapshot: HostSnapshot,
    requested: Severity,
    reboot: RebootAssessment,
) -> Severity:
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    requested_value = severity_value(requested)
    required = "medium"
    if (
        host.criticality == "high"
        or host.availability_class == "high_availability"
        or reboot.status in ("required", "required_after_patch")
        or snapshot.service_summary.failed_units
    ):
        required = "high"
    if snapshot.system_summary.disk_usage_percent >= 95:
        required = "critical"
    return Severity(requested_value if rank[requested_value] >= rank[required] else required)


def rollout_policy(host: Host, risk: Severity) -> RolloutPolicy:
    risk_value = severity_value(risk)
    one_at_time = (
        host.criticality == "high"
        or host.availability_class == "high_availability"
        or risk_value in ("high", "critical")
    )
    if one_at_time:
        return RolloutPolicy(
            strategy="one_at_a_time",
            batch_size=1,
            canary_count=1,
            rationale="High-risk or high-availability hosts are patched and validated one at a time.",
        )
    return RolloutPolicy(
        strategy="canary_then_batches",
        batch_size=host.patch_policy.max_batch_size,
        canary_count=host.patch_policy.canary_count,
        rationale="Start with canaries, validate, then continue in bounded batches.",
    )
