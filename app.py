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
    pace = st.slider("Trace speed (seconds per step)", 0.0, 1.0, 0.3)
    show_full = st.checkbox("Show full ciphertexts (no truncation)", value=False)

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

def traced(title: str, action: Callable[[ZKClient], Any], who: Callable[[], ZKClient] = as_caller) -> Any:
    caller = who()
    caller.full_values = show_full
    caller.steps.clear()
    outcome, error = None, None
    try:
        outcome = action(caller)
    except (VerificationError, ApiError, httpx.HTTPError, ValueError) as exc:
        error = exc
    with st.status(title, expanded=True) as box:
        for number, (actor, text, values) in enumerate(caller.steps, 1):
            st.markdown(f"{number}. **{actor}:** {text}")
            if values:
                st.code("\n".join(f"{name}: {value}" for name, value in values.items()), language=None, wrap_lines=True)
            time.sleep(pace)
        if error is None:
            box.update(label=f"{title}: every check passed", state="complete")
        else:
            st.markdown(f"**Client:** REJECTED - {error}")
            box.update(label=f"{title}: rejected", state="error")
    return outcome


query_tab, trace_tab, attack_tab, eve_tab, admin_tab = st.tabs(["Query", "Client / server trace", "Leakage attack lab", "Eve: insider attack", "Admin"])

with query_tab:
    left, right = st.columns([3, 1])
    terms = left.text_input("Search terms (blind trapdoors)", "payroll")
    mode = right.radio("Combine", ["and", "or"], horizontal=True)
    audit = st.checkbox("Audit homomorphic result against committed ciphertexts", value=True)
    search_col, sum_col, avg_col = st.columns(3)
    if search_col.button("Search"):
        st.session_state.found = traced("Search pipeline", lambda c: c.search(terms, mode))
    found = st.session_state.get("found")
    if found:
        st.caption(f"{found.lookups} trapdoor lookups, {found.candidates} candidates (incl. decoys), {found.denied} hidden by clearance")
        frame = pd.DataFrame(found.records)
        if not st.checkbox("Show encrypted columns and record digest next to the plaintext", value=True):
            frame = frame.drop(columns=["aes_ciphertext", "paillier_amount", "record_digest"])
        st.dataframe(frame, use_container_width=True, hide_index=True)
    for button, label in ((sum_col, "Encrypted sum"), (avg_col, "Encrypted average")):
        if button.button(label):
            def run(c: ZKClient) -> tuple[list[dict[str, Any]], int] | None:
                rows = c.search(terms, mode).records
                return (rows, c.aggregate([r["id"] for r in rows], audit=audit)) if rows else None

            outcome = traced(f"{label} pipeline", run)
            if outcome:
                rows, total = outcome
                expected = sum(r["amount"] for r in rows)
                st.metric(label, f"{total if label.endswith('sum') else total / len(rows):,.2f}")
                st.caption(f"Plaintext cross-check: {expected:,} ({'match' if expected == total else 'MISMATCH'}), {len(rows)} records")

with trace_tab:
    c1, c2 = st.columns(2)
    c1.subheader("Client")
    c1.dataframe(pd.DataFrame(client.trace[-25:], columns=["stage", "event"]), use_container_width=True, hide_index=True)
    c2.subheader("Server audit chain")
    log = guard(lambda: as_admin().audit_log())
    if log:
        c2.success("Hash chain intact") if log["valid"] else c2.error(f"Chain broken at entry {log['bad_seq']}")
        frame = pd.DataFrame(log["entries"]).fillna("").astype(str)
        cols = [c for c in ("seq", "component", "action", "decision", "reason", "detail", "ms", "prev", "hash") if c in frame]
        frame["hash"] = frame["hash"].str[:16]
        frame["prev"] = frame["prev"].str[:16]
        with c2.expander("Latest audit entry with full hashes"):
            st.json(log["entries"][-1])
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

with eve_tab:
    st.info(
        "**The question:** what if the cloud server is hacked or run by someone dishonest? "
        "**Eve** has full control of the server but never gets the client's secret keys. "
        "Left column: what Eve sees or does. Right column: what the client sees and verifies. "
        "Three scenarios: can Eve read the data, can she learn secrets from patterns, can she tamper without being caught."
    )
    word = st.text_input("Keyword Eve is after", "payroll" if tenant == "acme-finance" else "patient", key="eve-word")

    st.subheader("1. Can Eve read our data?")
    st.caption("Click Dump to see exactly what is stored on the server, then Decrypt to see what the client can read from the same data.")
    left, right = st.columns(2)
    left.markdown("#### What Eve sees (server storage)")
    if left.button("Dump server database"):
        st.session_state.dump = (tenant, http().get(f"/_demo/eve/dump/{tenant}").json())
    saved = st.session_state.get("dump")
    if saved and saved[0] == tenant:
        dump = saved[1]
        left.dataframe(pd.DataFrame(dump["records"]), use_container_width=True, hide_index=True)
        left.dataframe(pd.DataFrame(dump["postings"]), use_container_width=True, hide_index=True)
        left.metric(f"Occurrences of '{word}' in raw storage", dump["raw"].lower().count(word.lower()))
        left.caption("Department and classification are stored in plaintext, so Eve does learn those.")
    right.markdown("#### What the client sees")
    if right.button("Decrypt with the client's local keys"):
        with right:
            hits = guard(lambda: as_admin().search(word, "or"))
            if hits:
                st.dataframe(pd.DataFrame(hits.records), use_container_width=True, hide_index=True)
    st.success("**Takeaway:** the server holds the data but cannot read it; only the key holder can. Eve still sees department, classification and which records match a search.")

    st.subheader("2. Can Eve learn secrets just by watching patterns?")
    st.caption("Even encrypted, patterns leak: a search token matching many records is probably a common word. Eve ranks tokens by match count and guesses the words. The chart shows how often she is right, with and without our defenses.")
    if st.button("Run Eve's attack (synthetic corpus, 1500 docs, 3 trials)"):
        with st.spinner("Attacking"):
            st.session_state.eve_attack = pd.DataFrame(run_attack(1500, 400, 14, 40, 3, defenses=(DEFENSES[0], DEFENSES[1], DEFENSES[5])))
    result = st.session_state.get("eve_attack")
    if result is not None:
        left, right = st.columns(2)
        left.markdown("#### Top-40 keywords Eve recovers (%)")
        left.bar_chart(result.set_index("defense")["top_k_recovery_pct"])
        right.markdown("#### What the defense costs")
        right.dataframe(result[["defense", "index_size_x", "lookups_per_query"]], use_container_width=True, hide_index=True)
        st.caption(f"Eve recovers {result.top_k_recovery_pct.iloc[0]}% undefended and {result.top_k_recovery_pct.iloc[-1]}% with padding + epochs. The defense reduces the leak a lot but does not remove it.")
        st.success("**Takeaway:** the attack works on the plain scheme, and padding plus epoch rotation cut Eve's success by about 4x. It is measured on generated test data, not real documents.")

    st.subheader("3. Can Eve change things without getting caught?")
    st.caption("Step 1: click one of Eve's cheats on the left. Step 2: click 'Client searches and sums' on the right and watch whether the client notices. Click Undo before trying the next cheat.")

    st.subheader("3. Eve tampers with the data")
    left, right = st.columns(2)
    left.markdown("#### Eve's actions on the server")
    attacks = {
        "Flip bytes in every stored ciphertext": (f"/_demo/eve/corrupt/{tenant}", None),
        "Inject a forged id into every posting list": (f"/_demo/eve/inject/{tenant}", None),
        "Drop one result from every search": ("/_demo/tamper", {"mode": "drop_result"}),
        "Forge the encrypted sum": ("/_demo/tamper", {"mode": "forge_sum"}),
        "Edit an audit log entry": (f"/_demo/audit-edit/{tenant}", None),
    }
    for label, (path, body) in attacks.items():
        if left.button(label):
            http().post(path, json=body)
            left.warning(f"Done: {label}")
    if left.button("Undo all of Eve's changes"):
        http().post(f"/_demo/eve/restore/{tenant}")
        left.success("Server restored")
    right.markdown("#### The client's verdict")
    if right.button("Client searches and sums"):
        def probe(c: ZKClient) -> tuple[int, int | None]:
            rows = c.search(word, "or").records
            return len(rows), (c.aggregate([r["id"] for r in rows], audit=True) if rows else None)

        with right:
            verdict = traced(f"Search + sum for '{word}'", probe, who=as_admin)
            if verdict:
                st.success(f"{verdict[0]} verified record(s), verified sum {verdict[1]}")
    if right.button("Check the audit chain"):
        log = guard(lambda: as_admin().audit_log())
        if log:
            right.success("Hash chain intact") if log["valid"] else right.error(f"BUSTED: chain broken at entry {log['bad_seq']}")
        st.success("**Takeaway:** when the client uploaded, it saved a short fingerprint (a Merkle root) of everything. Every server answer must come with a proof matching it, so any change fails the check. We detect cheating; we cannot stop Eve from corrupting data.")
        
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