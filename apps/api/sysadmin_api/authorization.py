from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet

from .models import User, UserRole


class ProtectedAction(str, Enum):
    VIEW_SESSION = "view_session"
    VIEW_CREDENTIALS = "view_credentials"
    MANAGE_CREDENTIALS = "manage_credentials"
    VIEW_HOSTS = "view_hosts"
    MANAGE_HOSTS = "manage_hosts"
    TEST_HOST_CONNECTIONS = "test_host_connections"
    VIEW_SCANS = "view_scans"
    RUN_SCANS = "run_scans"
    VIEW_FINDINGS = "view_findings"
    VIEW_REMEDIATIONS = "view_remediations"
    MANAGE_REMEDIATIONS = "manage_remediations"
    VIEW_JOBS = "view_jobs"
    VIEW_SCHEDULES = "view_schedules"
    MANAGE_SCHEDULES = "manage_schedules"
    VIEW_AGENT_ACTIVITY = "view_agent_activity"
    VIEW_LOGS = "view_logs"
    VIEW_ALERTS = "view_alerts"
    ACKNOWLEDGE_ALERTS = "acknowledge_alerts"
    VIEW_AUDIT = "view_audit"
    VIEW_CAMPAIGNS = "view_campaigns"
    MANAGE_CAMPAIGNS = "manage_campaigns"
    LOGOUT = "logout"


class AuthorizationPolicy:
    def __init__(self, allowed_roles: Dict[ProtectedAction, FrozenSet[UserRole]]) -> None:
        self.allowed_roles = allowed_roles

    def authorize(self, user: User, action: ProtectedAction) -> bool:
        return user.role in self.allowed_roles.get(action, frozenset())


class AlphaAuthorizationPolicy(AuthorizationPolicy):
    def __init__(self) -> None:
        admin_only = frozenset({UserRole.ADMIN})
        super().__init__(
            {
                action: admin_only
                for action in ProtectedAction
            }
        )
