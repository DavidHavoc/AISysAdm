from __future__ import annotations

from typing import List, Set, Tuple

from .models import AgentMessage, Finding, HostSnapshot


ALLOWED_ACTIONS = {"package_upgrade", "manual_review"}


def evidence_registry(snapshot: HostSnapshot) -> Set[str]:
    citations = {
        "serviceSummary.failedUnits",
        "services.failed_units",
        "logs.journal",
        "logs.kernel",
        "logs.auth",
        "logs.aptHistory",
        "logs.apt_history",
        "logs.rebootHistory",
        "systemSummary.diskUsagePercent",
        "systemSummary.inodeUsagePercent",
        "systemSummary.memoryUsagePercent",
        "systemSummary.kernelVersion",
        "system.reboot_marker",
        "packageSummary",
        "packages.updates",
    }
    citations.update("commands.%s" % key for key in snapshot.commands)
    citations.update("evidenceStates.%s" % key for key in snapshot.evidence_states)
    return citations


class DeterministicVerifier:
    def verify_findings(
        self,
        snapshot: HostSnapshot,
        findings: List[Finding],
        messages: List[AgentMessage],
    ) -> Tuple[List[Finding], List[str]]:
        allowed = evidence_registry(snapshot)
        conflicts = {
            claim_id
            for message in messages
            if message.response in ("challenge", "request_evidence")
            for claim_id in message.claim_ids
        }
        verified: List[Finding] = []
        rejected: List[str] = []
        for item in findings:
            citations = {evidence.citation for evidence in item.evidence}
            reasons: List[str] = []
            if item.severity != "info" and not citations:
                reasons.append("finding has no evidence citations")
            invalid = citations - allowed
            if invalid:
                reasons.append("unknown citations: %s" % ", ".join(sorted(invalid)))
            if item.recommended_action and item.recommended_action.action_type not in ALLOWED_ACTIONS:
                reasons.append("action is not in the remediation catalog")
            if item.id in conflicts:
                reasons.append("peer review left the claim challenged or missing evidence")
            if item.confidence < 0.75 and item.recommended_action:
                reasons.append("confidence is below executable-plan threshold")
            if reasons:
                item.verifier_status = "rejected"
                item.verifier_reason = "; ".join(reasons)
                rejected.append("%s: %s" % (item.id, item.verifier_reason))
                continue
            item.verifier_status = "verified"
            verified.append(item)
        return verified, rejected
