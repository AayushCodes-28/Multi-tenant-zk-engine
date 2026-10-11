from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx
import pandas as pd
import streamlit as st

from src.access_control import UserAttributes
from src.attack import DEFENSES, run_attack
from src.capability import Authority
from src.client import ApiError, VerificationError, ZKClient
from src.crypto_engine import KeyMaterial

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "sample_records.json"
KEY_PATH = ROOT / ".keys" / "authority.key"
SERVER_URL = os.environ.get("ZK_SERVER_URL", "http://127.0.0.1:8000")
TENANTS = {
    "acme-finance": {"department": "finance", "roles": ["analyst", "manager", "admin"], "writers": ["manager", "admin"]},
    "northstar-health": {"department": "clinical", "roles": ["clinician", "researcher", "admin"], "writers": ["clinician", "admin"]},
}

st.set_page_config(page_title="Multi-Tenant ZK Cloud Engine", layout="wide")


def reachable() -> bool:
    try:
        return bool(httpx.get(f"{SERVER_URL}/health", timeout=1).json().get("ok"))
    except (httpx.HTTPError, ValueError):
        return False


@st.cache_resource
def server_process() -> subprocess.Popen | None:
    if reachable():
        return None
    Authority.load_or_create(KEY_PATH)
    env = {**os.environ, "ZK_DEMO": "1", "ZK_AUTHORITY_KEY": str(KEY_PATH)}
    port = str(urlparse(SERVER_URL).port or 8000)
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.server:create_app_from_env", "--factory", "--port", port, "--log-level", "warning"],
        cwd=ROOT,
        env=env,
    )
    for _ in range(80):
        if reachable():
            break
        time.sleep(0.25)
    return process


@st.cache_resource
def authority() -> Authority:
    return Authority.load_or_create(KEY_PATH)


@st.cache_resource
def http() -> httpx.Client:
    return httpx.Client(base_url=SERVER_URL, timeout=60)


def token(tenant: str, role: str, clearance: int, department: str, subject: str) -> str:
    return authority().issue(UserAttributes(subject, tenant, role, department, clearance))


def admin_token(tenant: str) -> str:
    return token(tenant, "admin", 3, TENANTS[tenant]["department"], "tenant-admin")


def guard(action: Callable[[], Any]) -> Any:
    try:
        return action()
    except VerificationError as exc:
        st.error(f"VERIFICATION FAILED - result rejected: {exc}")
    except ApiError as exc:
        st.warning(f"Server denied the request ({exc.status}): {exc.detail}")
    except (httpx.HTTPError, ValueError) as exc:
        st.error(str(exc))


def setup(bits: int, pad: bool) -> None:
    http().post("/_demo/tamper", json={"mode": None})
    rows = json.loads(DATA.read_text())["records"]
    clients = {}
    for tenant, cfg in TENANTS.items():
        client = ZKClient(http(), KeyMaterial.generate(tenant, paillier_bits=bits), admin_token(tenant))
        client.register({**cfg, "min_clearance": 1, "active_hours": [0, 24]})
        client.bulk_load([r for r in rows if r["tenant_id"] == tenant], pad=pad)
        clients[tenant] = client
    st.session_state.clients = clients
    st.session_state.found = None


def tamper(mode: str | None) -> None:
    http().post("/_demo/tamper", json={"mode": mode})


st.title("Multi-Tenant Zero-Knowledge Cloud Engine")
server_process()
if not reachable():
    st.error(f"Server not reachable at {SERVER_URL}")
    st.stop()

with st.sidebar:
    st.header("Setup")
    bits = st.selectbox("Paillier key bits", [1024, 2048])
    pad = st.checkbox("Pad posting lists with decoys", value=True)
    if st.button("Register tenants and load demo data", type="primary"):
        with st.spinner("Generating keys, encrypting, building authenticated index"):
            guard(lambda: setup(bits, pad))
    st.header("Caller identity")
    tenant = st.selectbox("Tenant", list(TENANTS))
    cfg = TENANTS[tenant]
    role = st.selectbox("Role", [*cfg["roles"], "intern"])
    clearance = st.slider("Clearance level", 0, 3, 2)
    department = st.selectbox("Department", [cfg["department"], "other"])
    subject = st.text_input("Subject id", f"{role}-{clearance}")

clients: dict[str, ZKClient] = st.session_state.get("clients", {})
client = clients.get(tenant)
if client is None:
    st.info("Register tenants and load demo data from the sidebar.")
    st.stop()


def as_caller() -> ZKClient:
    client.token = token(tenant, role, clearance, department, subject)
    return client


def as_admin() -> ZKClient:
    client.token = admin_token(tenant)
    return client


query_tab, trace_tab, attack_tab, tamper_tab, admin_tab = st.tabs(["Query", "Client / server trace", "Leakage attack lab", "Malicious server", "Admin"])

with query_tab:
    left, right = st.columns([3, 1])
    terms = left.text_input("Search terms (blind trapdoors)", "payroll")
    mode = right.radio("Combine", ["and", "or"], horizontal=True)
    audit = st.checkbox("Audit homomorphic result against committed ciphertexts", value=True)
    search_col, sum_col, avg_col = st.columns(3)
    if search_col.button("Search"):
        st.session_state.found = guard(lambda: as_caller().search(terms, mode))
    found = st.session_state.get("found")
    if found:
        st.caption(f"{found.lookups} trapdoor lookups, {found.candidates} candidates (incl. decoys), {found.denied} hidden by clearance, all index and record proofs verified")
        st.dataframe(pd.DataFrame(found.records), use_container_width=True, hide_index=True)
    for button, label in ((sum_col, "Encrypted sum"), (avg_col, "Encrypted average")):
        if button.button(label):
            def run() -> None:
                caller = as_caller()
                result = caller.search(terms, mode)
                ids = [r["id"] for r in result.records]
                if not ids:
                    st.info("No matching records")
                    return
                total = caller.aggregate(ids, audit=audit)
                expected = sum(r["amount"] for r in result.records)
                st.metric(label, f"{total if label.endswith('sum') else total / len(ids):,.2f}")
                st.caption(f"Plaintext cross-check: {expected:,} ({'match' if expected == total else 'MISMATCH'}), {len(ids)} records")

            guard(run)

with trace_tab:
    c1, c2 = st.columns(2)
    c1.subheader("Client")
    c1.dataframe(pd.DataFrame(client.trace[-25:], columns=["stage", "event"]), use_container_width=True, hide_index=True)
    c2.subheader("Server audit chain")
    log = guard(lambda: as_admin().audit_log())
    if log:
        c2.success("Hash chain intact") if log["valid"] else c2.error(f"Chain broken at entry {log['bad_seq']}")
        frame = pd.DataFrame(log["entries"]).fillna("").astype(str)
        cols = [c for c in ("seq", "component", "action", "decision", "reason", "detail", "ms", "hash") if c in frame]
        frame["hash"] = frame["hash"].str[:10]
        c2.dataframe(frame[cols].iloc[::-1].head(40), use_container_width=True, hide_index=True)
    st.subheader("What the server stores")
    view = http().get(f"/_demo/view/{tenant}").json()
    v1, v2 = st.columns(2)
    v1.dataframe(pd.DataFrame(view["postings"], columns=["trapdoor", "posting size"]), use_container_width=True, hide_index=True)
    v2.dataframe(pd.DataFrame(view["records"]), use_container_width=True, hide_index=True)
    st.code(f"index root   {view['index_root']}\nrecord root  {view['record_root']}")

with attack_tab:
    st.write("Frequency/count attack: the server knows public word statistics and matches posting-list sizes to keywords.")
    a, b, c, d = st.columns(4)
    docs = a.number_input("Documents", 200, 5000, 2000, step=200)
    vocab = b.number_input("Vocabulary", 50, 1000, 400, step=50)
    top_k = c.number_input("Top-K words attacked", 5, 100, 40)
    trials = d.number_input("Trials", 1, 10, 3)
    if st.button("Run attack against every defense"):
        with st.spinner("Attacking"):
            frame = pd.DataFrame(run_attack(int(docs), int(vocab), 14, int(top_k), int(trials)))
        st.dataframe(frame, use_container_width=True, hide_index=True)
        st.bar_chart(frame.set_index("defense")["top_k_recovery_pct"])

with tamper_tab:
    st.write("Switch the server into malicious mode and watch the client reject its answers.")
    modes = {"Honest": None, "Drop one search result": "drop_result", "Forge encrypted sum": "forge_sum"}
    for label, mode_value in modes.items():
        if st.button(label, key=f"mode-{label}"):
            tamper(mode_value)
            st.toast(f"Server mode: {label}")
    if st.button("Edit a server audit entry"):
        http().post(f"/_demo/audit-edit/{tenant}")
    if st.button("Run search + sum with audit"):
        def probe() -> None:
            caller = as_caller()
            result = caller.search("payroll" if tenant == "acme-finance" else "patient", "or")
            st.success(f"{len(result.records)} verified records")
            st.success(f"Verified sum: {caller.aggregate([r['id'] for r in result.records], audit=True):,}")

        guard(probe)

with admin_tab:
    text = st.text_input("New record text", "Payroll correction for support staff")
    amount = st.number_input("Amount", value=500)
    level = st.slider("Classification", 0, 3, 1)
    a1, a2, a3 = st.columns(3)
    if a1.button("Add record (verified incremental update)"):
        guard(lambda: st.success(f"Added {as_admin().add_record({'text': text, 'amount': int(amount), 'department': cfg['department'], 'classification': level})}"))
    if a2.button("Rotate trapdoor epoch"):
        st.success(f"Epoch {client.rotate_epoch()}: new records get unlinkable trapdoors; searches now use {client.epoch + 1} per term")
    if a3.button("Revoke current subject"):
        guard(lambda: (as_admin().revoke(subject), st.success(f"Revoked {subject}; older tokens rejected")))