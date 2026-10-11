from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import FrozenSet
@dataclass(frozen=True, slots=True)
class UserAttributes:
    subject_id: str
    tenant_id: str
    role: str
    department: str
    clearance_level: int
    authenticated: bool = True


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    tenant_id: str
    department: str
    minimum_clearance: int
    allowed_roles: FrozenSet[str]
    active_hours_utc: tuple[int, int] = (0, 24)


@dataclass(frozen=True, slots=True)
class AccessRequest:
    user: UserAttributes
    resource: ResourcePolicy
    action: str
    hour_utc: int | None = None


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason_code: str
    message: str


class ABACEngine:
    SUPPORTED_ACTIONS = frozenset({"search", "aggregate", "read", "index", "audit", "admin"})

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        user, policy = request.user, request.resource
        hour = datetime.now(timezone.utc).hour if request.hour_utc is None else request.hour_utc
        if request.action not in self.SUPPORTED_ACTIONS:
            return self._deny("UNSUPPORTED_ACTION", "The requested action is not recognized")
        if not 0 <= hour <= 23:
            return self._deny("INVALID_SESSION_TIME", "Session hour must be between 0 and 23 UTC")
        if not user.authenticated:
            return self._deny("NOT_AUTHENTICATED", "An authenticated session is required")
        if not hmac_safe_equal(user.tenant_id, policy.tenant_id):
            return self._deny("TENANT_MISMATCH", "Cross-tenant access is forbidden")
        if user.role not in policy.allowed_roles:
            return self._deny("ROLE_DENIED", "The role is not permitted by this policy")
        if user.department != policy.department and user.role != "admin":
            return self._deny("DEPARTMENT_MISMATCH", "The department attribute does not match")
        if user.clearance_level < policy.minimum_clearance:
            return self._deny("INSUFFICIENT_CLEARANCE", "The user's clearance is too low")
        if not self._hour_allowed(hour, policy.active_hours_utc):
            return self._deny("OUTSIDE_ACTIVE_HOURS", "The session is outside allowed UTC hours")
        return AccessDecision(True, "ALLOW", "All policy attributes satisfied")

    @staticmethod
    def _hour_allowed(hour: int, window: tuple[int, int]) -> bool:
        start, end = window
        if not (0 <= start <= 23 and 1 <= end <= 24):
            return False
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end

    @staticmethod
    def _deny(code: str, message: str) -> AccessDecision:
        return AccessDecision(False, code, message)


def hmac_safe_equal(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))

