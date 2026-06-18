from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .memory import AgentMemory
from .models import (
    AgentName,
    AgentReport,
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
from .providers import ModelRouter, ProviderError, RoutedModel


def new_id(prefix: str) -> str:
    return "%s-%s" % (prefix, uuid4().hex[:12])


class SpecialistAgent:
    name: AgentName

    def __init__(self, router: ModelRouter, memory: AgentMemory) -> None:
        self.routed = router.route(self.name)
        self.memory = memory

    async def analyze(self, host: Host, snapshot: HostSnapshot) -> AgentReport:
        findings = self.policy_findings(host, snapshot)
        overview = self.fallback_overview(snapshot, findings)
        if self.routed.provider:
            try:
                response = await self.routed.provider.complete_json(
                    self.system_prompt(),
                    json.dumps(
                        {
                            "host": host.model_dump(mode="json"),
                            "snapshot": snapshot.model_dump(mode="json"),
                            "policy_findings": [
                                item.model_dump(mode="json") for item in findings
                            ],
                            "required_output": {"overview": "string"},
                        }
                    ),
                )
                overview = str(response.get("overview") or overview)
            except (ProviderError, KeyError, ValueError) + http_errors():
                overview = "%s AI enrichment was unavailable; policy analysis was retained." % overview

        report = AgentReport(
            agent=self.routed.identity,
            overview=overview,
            findings=findings,
        )
        self.memory.put(
            "agent:%s:%s" % (host.id, self.name.value),
            report.model_dump_json(),
        )
        return report

    def system_prompt(self) -> str:
        return (
            "You are a read-only Linux specialist. Explain only the supplied evidence. "
            "Do not invent commands, facts, or remediation. Return JSON only."
        )

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        raise NotImplementedError

    def fallback_overview(self, snapshot: HostSnapshot, findings: List[Finding]) -> str:
        return "%s produced %s evidence-backed finding(s)." % (self.name.value, len(findings))


def http_errors() -> Tuple[type, ...]:
    try:
        import httpx

        return (httpx.HTTPError,)
    except ImportError:
        return ()


def finding(
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


class LogAnalysisAgent(SpecialistAgent):
    name = AgentName.LOG_ANALYST

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        findings: List[Finding] = []
        if snapshot.service_summary.failed_units:
            findings.append(
                finding(
                    host,
                    self.name,
                    "service_health",
                    Severity.HIGH,
                    "%s failed service unit(s) detected."
                    % len(snapshot.service_summary.failed_units),
                    (
                        "Recent journal entries and systemd state agree that service "
                        "health needs review before and after patching."
                    ),
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
                        rationale="A pre-existing failure can make post-patch validation ambiguous.",
                    ),
                    0.96,
                )
            )
        if "authentication failure" in snapshot.logs.auth.lower():
            findings.append(
                finding(
                    host,
                    self.name,
                    "authentication",
                    Severity.MEDIUM,
                    "Authentication failures were found in recent SSH logs.",
                    "The event should be correlated with expected operator access.",
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
        return findings


class LinuxStateAgent(SpecialistAgent):
    name = AgentName.LINUX_STATE_ANALYST

    def policy_findings(self, host: Host, snapshot: HostSnapshot) -> List[Finding]:
        findings: List[Finding] = []
        packages = snapshot.package_summary
        if packages.pending_package_updates:
            findings.append(
                finding(
                    host,
                    self.name,
                    "patching",
                    Severity.HIGH if packages.pending_security_updates else Severity.MEDIUM,
                    "%s package update(s) are pending, including %s security update(s)."
                    % (
                        packages.pending_package_updates,
                        packages.pending_security_updates,
                    ),
                    (
                        "The orchestrator must choose all or security-only updates, "
                        "then request approval for patching and any required reboot."
                    ),
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
                finding(
                    host,
                    self.name,
                    "capacity",
                    severity,
                    "Root filesystem usage is %.0f%%."
                    % snapshot.system_summary.disk_usage_percent,
                    "Low free space can cause package installation and rollback metadata to fail.",
                    [
                        Evidence(
                            source="df -P /",
                            excerpt="%.0f%% used" % snapshot.system_summary.disk_usage_percent,
                            citation="systemSummary.diskUsagePercent",
                        )
                    ],
                    RecommendedAction(
                        action_type="manual_review",
                        title="Verify free disk space",
                        rationale="Automated cleanup is not in the approved action catalog.",
                    ),
                    0.99,
                )
            )
        return findings


class OrchestratorAgent:
    def __init__(self, router: ModelRouter, memory: AgentMemory) -> None:
        self.routed: RoutedModel = router.route(AgentName.ORCHESTRATOR)
        self.memory = memory

    async def synthesize(
        self,
        host: Host,
        snapshot: HostSnapshot,
        reports: List[AgentReport],
    ) -> Tuple[List[Finding], Optional[Remediation]]:
        findings = [finding for report in reports for finding in report.findings]
        update_scope, explanation, requested_risk = await self._choose_scope(
            host, snapshot, reports
        )
        reboot = self._assess_reboot(snapshot, update_scope)
        risk = self._enforce_risk(host, snapshot, requested_risk, reboot)
        rollout = self._rollout(host, risk)

        if not findings:
            findings.append(
                finding(
                    host,
                    AgentName.ORCHESTRATOR,
                    "posture",
                    Severity.INFO,
                    "No actionable issues were detected.",
                    "Both specialist agents completed without policy-triggering evidence.",
                    [],
                    None,
                    0.9,
                )
            )

        if update_scope == "none" or snapshot.package_summary.pending_package_updates == 0:
            return findings, None

        assignments = [self.routed.identity] + [report.agent for report in reports]
        remediation = Remediation(
            id=new_id("remediation"),
            host_id=host.id,
            title="Patch %s with %s updates" % (host.name, update_scope),
            update_scope=update_scope,
            risk_level=risk,
            ai_decision=AiDecision(
                update_scope=update_scope,
                risk_level=risk,
                explanation=explanation,
                agent_assignments=assignments,
            ),
            reboot_assessment=reboot,
            rollout_policy=rollout,
            execution_timing=host.patch_policy.execution_timing,
            maintenance_window=host.patch_policy.maintenance_window,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        self.memory.put(
            "orchestrator:%s" % host.id,
            remediation.ai_decision.model_dump_json(),
        )
        return findings, remediation

    async def _choose_scope(
        self,
        host: Host,
        snapshot: HostSnapshot,
        reports: List[AgentReport],
    ) -> Tuple[str, str, Severity]:
        fixed_mode = host.patch_policy.update_mode
        if fixed_mode in ("all", "security"):
            return (
                fixed_mode,
                "Host policy explicitly requires %s updates." % fixed_mode,
                Severity.HIGH,
            )

        fallback_scope = "all" if snapshot.package_summary.pending_package_updates else "none"
        fallback_explanation = (
            "All pending updates were selected because host policy delegates scope "
            "to the orchestrator and the complete package set can be validated together."
        )
        fallback_risk = Severity.HIGH
        if not self.routed.provider:
            return fallback_scope, fallback_explanation, fallback_risk

        try:
            response = await self.routed.provider.complete_json(
                (
                    "You are the senior Linux patch orchestrator. Choose update_scope from "
                    "all, security, or none. Explain operator impact. Never propose shell "
                    "commands. Return JSON with update_scope, explanation, and risk_level."
                ),
                json.dumps(
                    {
                        "host_policy": host.patch_policy.model_dump(mode="json"),
                        "host_criticality": host.criticality,
                        "availability_class": host.availability_class,
                        "packages": snapshot.package_summary.model_dump(mode="json"),
                        "specialist_reports": [
                            report.model_dump(mode="json") for report in reports
                        ],
                    }
                ),
            )
            scope = str(response.get("update_scope", fallback_scope))
            if scope not in ("all", "security", "none"):
                scope = fallback_scope
            risk_text = str(response.get("risk_level", "high"))
            risk = Severity(risk_text) if risk_text in Severity._value2member_map_ else fallback_risk
            explanation = str(response.get("explanation") or fallback_explanation)
            return scope, explanation, risk
        except (ProviderError, KeyError, ValueError) + http_errors():
            return fallback_scope, fallback_explanation, fallback_risk

    @staticmethod
    def _assess_reboot(snapshot: HostSnapshot, update_scope: str) -> RebootAssessment:
        package_summary = snapshot.package_summary
        if package_summary.reboot_required_now:
            status = "required"
            rationale = "The host already has /var/run/reboot-required."
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
                rationale = (
                    "A reboot is not currently required, but the final decision must be "
                    "checked after package installation."
                )
            else:
                status = "not_expected"
                rationale = "No selected package has a known reboot hint."

        return RebootAssessment(
            status=status,
            rationale=rationale,
            evidence=[
                Evidence(
                    source="/var/run/reboot-required and package classification",
                    excerpt=rationale,
                    citation="packageSummary",
                )
            ],
            estimated_downtime_minutes=5 if status != "not_expected" else 0,
            approved_if_required=False,
        )

    @staticmethod
    def _enforce_risk(
        host: Host,
        snapshot: HostSnapshot,
        requested: Severity,
        reboot: RebootAssessment,
    ) -> Severity:
        rank = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        required = Severity.MEDIUM
        if (
            host.criticality == "high"
            or host.availability_class == "high_availability"
            or reboot.status in ("required", "required_after_patch")
            or snapshot.service_summary.failed_units
        ):
            required = Severity.HIGH
        if snapshot.system_summary.disk_usage_percent >= 95:
            required = Severity.CRITICAL
        return requested if rank[requested] >= rank[required] else required

    @staticmethod
    def _rollout(host: Host, risk: Severity) -> RolloutPolicy:
        one_at_time = (
            host.criticality == "high"
            or host.availability_class == "high_availability"
            or risk in (Severity.HIGH, Severity.CRITICAL)
        )
        if one_at_time:
            return RolloutPolicy(
                strategy="one_at_a_time",
                batch_size=1,
                canary_count=1,
                rationale=(
                    "High-risk, high-criticality, or high-availability hosts are patched "
                    "and validated one at a time."
                ),
            )
        return RolloutPolicy(
            strategy="canary_then_batches",
            batch_size=host.patch_policy.max_batch_size,
            canary_count=host.patch_policy.canary_count,
            rationale="Start with canaries, validate, then continue in bounded batches.",
        )
