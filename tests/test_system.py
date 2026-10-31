import time

import pytest
from fastapi.testclient import TestClient

from src.access_control import UserAttributes
from src.audit import verify_entries
from src.capability import Authority
from src.client import ApiError, VerificationError, ZKClient
from src.crypto_engine import KeyMaterial
from src.server import create_app

POLICY = {"department": "finance", "roles": ["analyst", "manager", "admin"], "writers": ["manager", "admin"], "min_clearance": 1}
ROWS = [
    {"id": "r1", "text": "payroll batch for engineering", "amount": 1200, "department": "finance", "classification": 1},
    {"id": "r2", "text": "payroll bonus for sales", "amount": 800, "department": "finance", "classification": 2},
    {"id": "r3", "text": "vendor invoice cloud hosting", "amount": 450, "department": "finance", "classification": 1},
    {"id": "r4", "text": "payroll audit adjustment", "amount": -150, "department": "finance", "classification": 3},
    {"id": "r5", "text": "quarterly vendor payment", "amount": 90, "department": "finance", "classification": 1},
]


def user(role="admin", clearance=3, subject=None, tenant="acme", department="finance"):
    return UserAttributes(subject or f"{role}-{clearance}", tenant, role, department, clearance)


@pytest.fixture(scope="module")
def authority():
    return Authority.generate()


@pytest.fixture(scope="module")
def keys():
    return KeyMaterial.generate("acme", paillier_bits=1024)


@pytest.fixture()
def env(authority, keys):
    app = create_app(authority.public_key, demo=True)
    http = TestClient(app)
    client = ZKClient(http, keys, authority.issue(user()))
    client.register(POLICY)
    client.bulk_load(ROWS)
    return http, client, authority


def as_user(env, **kwargs):
    http, client, authority = env
    other = ZKClient(http, client.keys, authority.issue(user(**kwargs)), epoch=client.epoch, index_root=client.index_root, record_root=client.record_root)
    return other


def test_search_and_sum_match_plaintext(env):
    _, client, _ = env
    result = client.search("payroll")
    assert {r["id"] for r in result.records} == {"r1", "r2", "r4"}
    assert client.aggregate_search("payroll")[0] == 1200 + 800 - 150
    assert client.aggregate_search(["vendor", "payroll"], mode="or")[0] == sum(r["amount"] for r in ROWS)
    assert client.aggregate_search(["payroll", "vendor"], mode="and") == (0, 0)


def test_weighted_sum_and_average(env):
    _, client, _ = env
    ids = ["r1", "r2", "r3"]
    assert client.aggregate(ids, [2, 1, -1]) == 2 * 1200 + 800 - 450
    total, count = client.aggregate_search("payroll")
    assert total / count == pytest.approx(1850 / 3)


def test_server_enforces_clearance_not_the_client(env):
    analyst = as_user(env, role="analyst", clearance=2)
    assert {r["id"] for r in analyst.search("payroll").records} == {"r1", "r2"}
    assert analyst.search("payroll").denied == 1
    with pytest.raises(ApiError) as denied:
        analyst.aggregate(["r1", "r4"])
    assert denied.value.status == 403 and "INSUFFICIENT_CLEARANCE" in denied.value.detail


def test_abac_blocks_cross_tenant_department_and_role(env):
    for kwargs, code in (
        ({"tenant": "other"}, "TENANT_MISMATCH"),
        ({"role": "analyst", "department": "hr", "clearance": 3}, "DEPARTMENT_MISMATCH"),
        ({"role": "intern", "clearance": 3}, "ROLE_NOT_ALLOWED"),
    ):
        with pytest.raises(ApiError) as denied:
            as_user(env, **kwargs).search("payroll")
        assert denied.value.status in (401, 403)


def test_analyst_cannot_write(env):
    with pytest.raises(ApiError) as denied:
        as_user(env, role="analyst", clearance=2).add_record({"text": "x", "amount": 1, "department": "finance", "classification": 1})
    assert denied.value.status == 403


def test_forged_expired_and_revoked_tokens(env, authority):
    http, client, _ = env
    forged = authority.issue(user()).rsplit(".", 1)[0] + "." + Authority.generate().issue(user()).rsplit(".", 1)[1]
    assert ZKClient(http, client.keys, forged, index_root=client.index_root).token == forged
    with pytest.raises(ApiError) as bad:
        ZKClient(http, client.keys, forged, index_root=client.index_root).search("payroll")
    assert bad.value.status == 401
    expired = authority.issue(user(), ttl=1, now=time.time() - 100)
    with pytest.raises(ApiError):
        ZKClient(http, client.keys, expired, index_root=client.index_root).search("payroll")
    victim = as_user(env, role="analyst", clearance=2, subject="mallory")
    victim.search("payroll")
    client.revoke("mallory")
    with pytest.raises(ApiError) as gone:
        victim.search("payroll")
    assert gone.value.status == 401
    fresh = as_user(env, role="analyst", clearance=2, subject="mallory")
    time.sleep(0.01)
    fresh.token = authority.issue(user(role="analyst", clearance=2, subject="mallory"), now=time.time() + 1)
    assert fresh.search("payroll").records


def test_incremental_add_keeps_roots_consistent(env):
    _, client, _ = env
    client.add_record({"id": "r6", "text": "payroll correction", "amount": 50, "department": "finance", "classification": 1})
    assert client.aggregate_search("payroll")[0] == 1200 + 800 - 150 + 50
    with pytest.raises(VerificationError):
        client.add_record({"id": "r6", "text": "dup", "amount": 1, "department": "finance", "classification": 1})


def test_epoch_rotation_unlinks_tokens_and_search_spans_epochs(env):
    _, client, _ = env
    first = client.trapdoors.create("payroll", 0)
    client.rotate_epoch()
    assert client.trapdoors.create("payroll", 1) != first
    client.add_record({"id": "r7", "text": "payroll retro", "amount": 10, "department": "finance", "classification": 1})
    result = client.search("payroll")
    assert {"r1", "r7"} <= {r["id"] for r in result.records} and result.lookups == 2


def test_padding_adds_decoys_but_results_stay_exact(authority, keys):
    http = TestClient(create_app(authority.public_key))
    client = ZKClient(http, keys, authority.issue(user()))
    client.register(POLICY)
    stats = client.bulk_load(ROWS, pad=True)
    assert stats["decoys"] > 0
    result = client.search("payroll")
    assert {r["id"] for r in result.records} == {"r1", "r2", "r4"} and result.candidates > 3
    assert client.aggregate_search("payroll")[0] == 1850


def test_dropped_result_is_detected(env):
    http, client, _ = env
    http.post("/_demo/tamper", json={"mode": "drop_result"})
    with pytest.raises(VerificationError, match="tampered or incomplete"):
        client.search("payroll")


def test_forged_sum_is_detected_by_audit(env):
    http, client, _ = env
    http.post("/_demo/tamper", json={"mode": "forge_sum"})
    with pytest.raises(VerificationError, match="forged"):
        client.aggregate(["r1", "r2"])
    assert client.aggregate(["r1", "r2"], audit=False) == 2000 + 1000


def test_audit_chain_detects_edits(env):
    http, client, _ = env
    client.search("payroll")
    assert client.audit_log()["valid"]
    seq = http.post("/_demo/audit-edit/acme").json()["seq"]
    log = client.audit_log()
    assert not log["valid"] and log["bad_seq"] == seq
    assert verify_entries(log["entries"][:seq]) == (True, None)


def test_server_view_contains_no_plaintext(env):
    http, _, _ = env
    view = http.get("/_demo/view/acme").text
    for word in ("payroll", "vendor", "engineering", "1200"):
        assert word not in view
        
def test_eve_cannot_read_dump_and_tampering_is_caught_then_restored(env):
    http, client, _ = env
    raw = http.get("/_demo/eve/dump/acme").json()["raw"].lower()
    assert all(word not in raw for word in ("payroll", "engineering", "vendor", "1200"))
    http.post("/_demo/eve/corrupt/acme")
    with pytest.raises(VerificationError, match="commitment"):
        client.search("payroll")
    http.post("/_demo/eve/restore/acme")
    http.post("/_demo/eve/inject/acme")
    with pytest.raises(VerificationError, match="tampered or incomplete"):
        client.search("payroll")
    http.post("/_demo/eve/restore/acme")
    assert {r["id"] for r in client.search("payroll").records} == {"r1", "r2", "r4"}
    http.post("/_demo/audit-edit/acme")
    assert not client.audit_log()["valid"]
    http.post("/_demo/eve/restore/acme")
    assert client.audit_log()["valid"]


def test_execution_steps_report_real_verification(env):
    _, client, _ = env
    client.steps.clear()
    client.search("payroll")
    text = " ".join(step[1] for step in client.steps)
    assert "derived trapdoor" in text and "matches pinned" in text and "decrypted" in text
    assert {step[0] for step in client.steps} == {"Client", "Server"}
    assert any(len(v) == 64 for step in client.steps for v in step[2].values())