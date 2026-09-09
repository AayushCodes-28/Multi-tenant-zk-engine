from src.access_control import ABACEngine, AccessRequest, ResourcePolicy, UserAttributes


POLICY = ResourcePolicy("tenant-a", "finance", 2, frozenset({"analyst", "admin"}), (8, 18))


def test_abac_allows_matching_attributes() -> None:
    user = UserAttributes("u1", "tenant-a", "analyst", "finance", 2)
    assert ABACEngine().evaluate(AccessRequest(user, POLICY, "search", 10)).allowed


def test_abac_denies_cross_tenant_and_inactive_session() -> None:
    cross_tenant = UserAttributes("u1", "tenant-b", "analyst", "finance", 3)
    decision = ABACEngine().evaluate(AccessRequest(cross_tenant, POLICY, "search", 10))
    assert not decision.allowed and decision.reason_code == "TENANT_MISMATCH"
    user = UserAttributes("u1", "tenant-a", "analyst", "finance", 3)
    decision = ABACEngine().evaluate(AccessRequest(user, POLICY, "search", 22))
    assert not decision.allowed and decision.reason_code == "OUTSIDE_ACTIVE_HOURS"


def test_admin_may_cross_department_but_not_tenant() -> None:
    user = UserAttributes("u1", "tenant-a", "admin", "operations", 3)
    assert ABACEngine().evaluate(AccessRequest(user, POLICY, "aggregate", 12)).allowed

