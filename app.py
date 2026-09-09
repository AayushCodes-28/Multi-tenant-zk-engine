"""Interactive Streamlit demo for the Multi-Tenant Zero-Knowledge Cloud Engine."""

from __future__ import annotations

import hashlib
import html
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st
from phe.paillier import EncryptedNumber, PaillierPublicKey

from src.access_control import ABACEngine, AccessRequest, ResourcePolicy, UserAttributes
from src.crypto_engine import AESCBCCipher, KeyMaterial, PaillierClient, TrapdoorGenerator, tokenize
from src.homomorphic import HomomorphicAccumulator
from src.sse_engine import EncryptedInvertedIndex

ROOT = Path(__file__).resolve().parent
DEMO_DATA = ROOT / "data" / "sample_records.json"

TENANT_SETTINGS: dict[str, dict[str, Any]] = {
    "acme-finance": {
        "department": "finance",
        "roles": frozenset({"analyst", "manager", "admin"}),
        "active_hours": (0, 24),
    },
    "northstar-health": {
        "department": "clinical",
        "roles": frozenset({"clinician", "researcher", "admin"}),
        "active_hours": (0, 24),
    },
}

TENANT_LABELS = {
    "acme-finance": "Acme Finance",
    "northstar-health": "Northstar Health",
}

APP_STYLES = """
<style>
:root { --ink:#eaf1ff; --muted:#8ea1c4; --panel:rgba(13,23,43,.78); --line:rgba(141,163,203,.16); --cyan:#56e6d8; --violet:#8b7cff; }
.stApp { background:radial-gradient(circle at 8% 0%,rgba(69,91,255,.15),transparent 30rem),radial-gradient(circle at 92% 15%,rgba(18,211,184,.10),transparent 26rem),#070d19; color:var(--ink); }
html,body,[class*="css"] { font-family:"DM Sans",sans-serif; }
h1,h2,h3 { font-family:"Space Grotesk",sans-serif!important; letter-spacing:-.03em; }
[data-testid="stHeader"] { background:transparent; }
[data-testid="stToolbar"] { right:1rem; }
.block-container { max-width:1480px; padding-top:1.4rem; padding-bottom:4rem; }
.zk-nav { display:flex;align-items:center;justify-content:space-between;padding:.75rem 0 1.5rem;border-bottom:1px solid var(--line);margin-bottom:1.6rem; }
.zk-brand { display:flex;align-items:center;gap:.75rem; }
.zk-mark { width:2.4rem;height:2.4rem;border-radius:.8rem;display:grid;place-items:center;background:linear-gradient(145deg,#6b5cff,#22c7ba);box-shadow:0 0 28px rgba(86,230,216,.20);font-weight:800;color:white; }
.zk-brand-name { font:700 1rem "Space Grotesk"; }
.zk-brand-sub { color:var(--muted);font-size:.73rem; }
.zk-status { display:flex;align-items:center;gap:.48rem;color:#a8b7d1;font-size:.78rem; }
.zk-dot { width:.48rem;height:.48rem;border-radius:50%;background:#49df9a;box-shadow:0 0 12px #49df9a; }
.zk-hero { padding:2.1rem 0 1.5rem; }
.zk-eyebrow { color:var(--cyan);font-size:.75rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase; }
.zk-title { max-width:850px;margin:.65rem 0 .7rem;font:700 clamp(2.2rem,5vw,4.6rem)/.98 "Space Grotesk";letter-spacing:-.06em; }
.zk-title span { background:linear-gradient(100deg,#8b7cff,#56e6d8);-webkit-background-clip:text;color:transparent; }
.zk-lead { max-width:760px;color:#9baac6;font-size:1.04rem;line-height:1.65; }
.zk-chip-row { display:flex;flex-wrap:wrap;gap:.55rem;margin:1rem 0 .3rem; }
.zk-chip { border:1px solid var(--line);background:rgba(255,255,255,.025);border-radius:999px;padding:.42rem .7rem;color:#aab9d2;font-size:.75rem; }
[data-testid="stVerticalBlockBorderWrapper"] { background:var(--panel);border-color:var(--line)!important;border-radius:1rem;box-shadow:0 14px 45px rgba(0,0,0,.16); }
[data-testid="stMetric"] { background:rgba(255,255,255,.025);border:1px solid var(--line);padding:.85rem 1rem;border-radius:.8rem; }
[data-testid="stMetricLabel"] { color:var(--muted); }
[data-testid="stMetricValue"] { font-family:"Space Grotesk"; }
.zk-section-kicker { color:var(--cyan);text-transform:uppercase;letter-spacing:.12em;font-size:.68rem;font-weight:700;margin-bottom:.25rem; }
.zk-section-title { font:650 1.28rem "Space Grotesk";margin-bottom:.25rem; }
.zk-section-copy { color:var(--muted);font-size:.84rem;margin-bottom:.9rem; }
.zk-boundary { display:flex;align-items:center;gap:.45rem;font-size:.75rem;color:#8fa0bd;margin-bottom:.9rem; }
.zk-boundary b { color:#c8d5eb; }
.zk-result { background:rgba(34,199,186,.055);border:1px solid rgba(86,230,216,.18);border-radius:.8rem;padding:.9rem 1rem;margin:.55rem 0; }
.zk-result-id { color:var(--cyan);font:600 .72rem "Space Grotesk";letter-spacing:.08em;text-transform:uppercase; }
.zk-result-text { color:#dbe5f7;font-size:.9rem;line-height:1.45;margin-top:.3rem; }
.zk-log { border-left:2px solid #52617c;padding:.2rem 0 .7rem .8rem;margin:.2rem 0 .55rem; }
.zk-log.abac { border-color:#8b7cff; }.zk-log.sse { border-color:#56e6d8; }.zk-log.paillier { border-color:#f2bd65; }.zk-log.index { border-color:#49df9a; }
.zk-log-head { display:flex;justify-content:space-between;gap:1rem;color:#7f92b2;font-size:.68rem;text-transform:uppercase;letter-spacing:.07em; }
.zk-log-body { color:#c7d3e7;font-size:.78rem;line-height:1.42;margin-top:.2rem;overflow-wrap:anywhere; }
.zk-step { min-height:9.5rem;padding:1.05rem;border:1px solid var(--line);border-radius:.9rem;background:rgba(255,255,255,.022); }
.zk-step-no { color:var(--cyan);font:700 .72rem "Space Grotesk"; }.zk-step-title { font:600 .96rem "Space Grotesk";margin:.45rem 0; }.zk-step-copy { color:var(--muted);font-size:.79rem;line-height:1.45; }
.stButton>button { border-radius:.7rem;min-height:2.8rem;font-weight:650;border-color:rgba(139,124,255,.4); }
.stButton>button[kind="primary"] { background:linear-gradient(100deg,#695cff,#3a9fbd);border:0; }
.stTextInput input,.stTextArea textarea,[data-baseweb="select"]>div { border-radius:.65rem!important; }
[data-testid="stTabs"] [data-baseweb="tab-list"] { gap:.4rem;border-bottom:1px solid var(--line); }
[data-testid="stTabs"] button { padding:.7rem 1rem; }
footer { visibility:hidden; }
@media(max-width:760px){.block-container{padding:.8rem 1rem 3rem}.zk-nav{padding-top:.25rem}.zk-brand-sub,.zk-status span:last-child{display:none}.zk-hero{padding-top:1rem}.zk-step{min-height:auto}}

/* Restrained project UI: neutral surfaces, system typography, one accent. */
:root { --ink:#17212b; --muted:#66727f; --panel:#ffffff; --line:#dce2e7; --cyan:#087f73; --violet:#087f73; }
.stApp { background:#f5f7f8; color:var(--ink); }
html,body,[class*="css"] { font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
h1,h2,h3 { font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif!important; letter-spacing:-.02em; }
.block-container { max-width:1360px; padding-top:1.25rem; }
.zk-nav { padding:.35rem 0 1.1rem; margin-bottom:1.25rem; border-color:var(--line); }
.zk-mark { width:2.1rem;height:2.1rem;border-radius:.35rem;background:#17324d;box-shadow:none;font:700 .7rem ui-monospace,SFMono-Regular,Consolas,monospace; }
.zk-brand-name { color:#17212b;font:650 .93rem Inter,ui-sans-serif,sans-serif;letter-spacing:0; }
.zk-brand-sub,.zk-status { color:var(--muted); }
.zk-dot { width:.42rem;height:.42rem;background:#16856f;box-shadow:none; }
.zk-hero { max-width:900px;padding:2.3rem 0 1.25rem; }
.zk-eyebrow { color:#087f73;font-size:.7rem;letter-spacing:.1em; }
.zk-title { font:650 clamp(2rem,4vw,3.5rem)/1.06 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.045em; }
.zk-title span { background:none;-webkit-background-clip:initial;color:#087f73; }
.zk-title { max-width:880px;margin:.7rem 0 1rem;color:#17212b;font:650 clamp(2rem,4vw,3.7rem)/1.06 Inter,ui-sans-serif,sans-serif;letter-spacing:-.045em; }
.zk-title span { background:none;color:#17212b; }
.zk-lead { max-width:780px;color:#596673;font-size:1rem;line-height:1.65; }
.zk-chip-row { display:none; }
[data-testid="stVerticalBlockBorderWrapper"] { background:#fff;border-color:var(--line)!important;border-radius:.45rem;box-shadow:none; }
[data-testid="stMetric"] { background:#fff;border-color:var(--line);border-radius:.35rem;box-shadow:none; }
[data-testid="stMetricLabel"] { color:var(--muted); }
[data-testid="stMetricValue"] { color:#17212b;font-family:Inter,ui-sans-serif,sans-serif; }
.zk-section-kicker { color:#087f73;letter-spacing:.09em; }
.zk-section-title { color:#17212b;font:650 1.12rem Inter,ui-sans-serif,sans-serif;letter-spacing:-.01em; }
.zk-section-copy,.zk-boundary { color:var(--muted); }
.zk-boundary b { color:#33404c; }
.zk-result { background:#f3faf8;border-color:#cce5df;border-radius:.35rem; }
.zk-result-id { color:#087f73;font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
.zk-result-text { color:#263541; }
.zk-log { border-left-color:#9aa6b2; }.zk-log.abac,.zk-log.sse,.zk-log.index { border-left-color:#087f73; }.zk-log.paillier { border-left-color:#9a6b16; }
.zk-log-head { color:#6d7884;font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
.zk-log-body { color:#293640;font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
.zk-step { min-height:8.5rem;background:#fff;border-color:var(--line);border-radius:.4rem; }
.zk-step-no { color:#087f73;font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
.zk-step-title { color:#17212b;font:650 .93rem Inter,ui-sans-serif,sans-serif; }
.zk-step-copy { color:#66727f; }
.stButton>button { border-radius:.3rem;min-height:2.65rem;font-weight:600;border-color:#aeb8c2; }
.stButton>button[kind="primary"] { background:#17324d;border:1px solid #17324d; }
.stTextInput input,.stTextArea textarea,[data-baseweb="select"]>div { border-radius:.3rem!important; }
[data-testid="stTabs"] [data-baseweb="tab-list"] { border-color:var(--line); }
</style>
"""


@dataclass(slots=True)
class ClientVault:
    """Trusted client state. Never store this object inside ``server`` state."""

    keys: KeyMaterial
    cipher: AESCBCCipher
    trapdoors: TrapdoorGenerator
    paillier: PaillierClient


def safe_fingerprint(value: str | int) -> str:
    """Create a non-reversible short identifier suitable for demonstration logs."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def log_event(component: str, event: str, *, latency_ms: float | None = None) -> None:
    """Append a sanitized server event. Callers must not pass secrets/plaintext."""
    entry = {
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z",
        "component": component,
        "event": event,
    }
    if latency_ms is not None:
        entry["latency_ms"] = round(latency_ms, 3)
    st.session_state.logs.insert(0, entry)
    del st.session_state.logs[100:]


def initialize_state() -> None:
    defaults = {
        "vaults": {},
        "server": {"indexes": {}, "records": {}, "public_keys": {}},
        "logs": [],
        "search_results": [],
        "last_sum": None,
        "last_decision": None,
        "last_query_count": 0,
        "last_search_tenant": None,
        "last_search_context": None,
        "demo_ready": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def create_vault(tenant_id: str) -> ClientVault:
    # 1024-bit keys make the educational live demo responsive. Use 2048+ in a
    # deployment after evaluating the applicable security policy.
    keys = KeyMaterial.generate(tenant_id, paillier_bits=1024)
    return ClientVault(
        keys=keys,
        cipher=AESCBCCipher(keys.aes_master_key, tenant_id),
        trapdoors=TrapdoorGenerator(keys.search_key, tenant_id),
        paillier=PaillierClient(keys.public_key, keys.private_key),
    )


def encrypt_and_upload(records: list[dict[str, Any]]) -> None:
    """Simulate client encryption followed by a ciphertext-only server upload."""
    tenant_ids = sorted({str(record["tenant_id"]) for record in records})
    vaults = {tenant: create_vault(tenant) for tenant in tenant_ids}
    server: dict[str, Any] = {"indexes": {}, "records": {}, "public_keys": {}}
    started = time.perf_counter()

    for tenant, vault in vaults.items():
        server["indexes"][tenant] = EncryptedInvertedIndex(tenant)
        server["records"][tenant] = {}
        server["public_keys"][tenant] = vault.keys.public_key

    for source in records:
        required = {"id", "tenant_id", "department", "classification", "text", "amount"}
        if required - source.keys():
            raise ValueError(f"record is missing fields: {sorted(required - source.keys())}")
        tenant = str(source["tenant_id"])
        if tenant not in TENANT_SETTINGS:
            raise ValueError(f"unknown demo tenant: {tenant}")
        vault = vaults[tenant]
        record_id = str(source["id"])
        text = str(source["text"])
        encrypted_amount = vault.paillier.encrypt_integer(int(source["amount"]))
        server["records"][tenant][record_id] = {
            "payload": vault.cipher.encrypt(text).to_dict(),
            "amount": encrypted_amount,
            # Policy metadata is intentionally visible to the server in this model.
            "department": str(source["department"]),
            "classification": int(source["classification"]),
        }
        blind_terms = (vault.trapdoors.create(term) for term in tokenize(text))
        server["indexes"][tenant].add_document(record_id, blind_terms)

    st.session_state.vaults = vaults
    st.session_state.server = server
    st.session_state.demo_ready = True
    st.session_state.search_results = []
    st.session_state.last_sum = None
    st.session_state.last_decision = None
    st.session_state.last_query_count = 0
    st.session_state.last_search_tenant = None
    st.session_state.last_search_context = None
    log_event(
        "INDEX",
        f"Accepted {len(records)} encrypted records across {len(tenant_ids)} isolated tenants",
        latency_ms=(time.perf_counter() - started) * 1000,
    )


def load_demo() -> None:
    payload = json.loads(DEMO_DATA.read_text(encoding="utf-8"))
    encrypt_and_upload(payload["records"])


def policy_for(tenant_id: str, clearance: int) -> ResourcePolicy:
    settings = TENANT_SETTINGS[tenant_id]
    return ResourcePolicy(
        tenant_id=tenant_id,
        department=settings["department"],
        minimum_clearance=clearance,
        allowed_roles=settings["roles"],
        active_hours_utc=settings["active_hours"],
    )


def authorize(user: UserAttributes, action: str, *, minimum_clearance: int, hour: int) -> bool:
    started = time.perf_counter()
    decision = ABACEngine().evaluate(
        AccessRequest(user, policy_for(user.tenant_id, minimum_clearance), action, hour)
    )
    st.session_state.last_decision = decision
    log_event(
        "ABAC",
        f"{decision.reason_code}: action={action}; subject={safe_fingerprint(user.subject_id)}; tenant={user.tenant_id}",
        latency_ms=(time.perf_counter() - started) * 1000,
    )
    if not decision.allowed:
        st.error(f"Access denied: {decision.message} ({decision.reason_code})")
    return decision.allowed


def user_context_signature(user: UserAttributes, hour: int) -> tuple[str, str, str, int, int]:
    """Identify the exact client context under which plaintext was released."""
    return (user.tenant_id, user.role, user.department, user.clearance_level, hour)


def run_search(user: UserAttributes, term: str, hour: int) -> None:
    """Authorize first, then create the client trapdoor and perform blind lookup."""
    if not authorize(user, "search", minimum_clearance=1, hour=hour):
        return
    vault: ClientVault = st.session_state.vaults[user.tenant_id]
    try:
        trapdoor = vault.trapdoors.create(term)
    except ValueError as exc:
        st.error(str(exc))
        return
    log_event("CLIENT", f"Created opaque query token id={safe_fingerprint(trapdoor)} after ABAC allow")
    started = time.perf_counter()
    matches = st.session_state.server["indexes"][user.tenant_id].search(trapdoor)
    log_event(
        "SSE",
        f"Blind lookup token={safe_fingerprint(trapdoor)} matched {len(matches)} document id(s)",
        latency_ms=(time.perf_counter() - started) * 1000,
    )

    visible: list[dict[str, Any]] = []
    for record_id in matches:
        encrypted = st.session_state.server["records"][user.tenant_id][record_id]
        if user.clearance_level < encrypted["classification"]:
            log_event("ABAC", f"Filtered document={safe_fingerprint(record_id)}: classification too high")
            continue
        visible.append({"id": record_id, "text": vault.cipher.decrypt(encrypted["payload"])})
    st.session_state.search_results = visible
    st.session_state.last_query_count = len(matches)
    st.session_state.last_search_tenant = user.tenant_id
    st.session_state.last_search_context = user_context_signature(user, hour)
    st.session_state.last_sum = None


def aggregate_results(user: UserAttributes, hour: int) -> None:
    if not authorize(user, "aggregate", minimum_clearance=1, hour=hour):
        return
    if st.session_state.last_search_tenant != user.tenant_id:
        st.warning("Run a search for the selected tenant first.")
        return
    if st.session_state.last_search_context != user_context_signature(user, hour):
        st.warning("Identity attributes changed. Re-run the search before aggregating.")
        return
    tenant_records = st.session_state.server["records"][user.tenant_id]
    ids = [
        record["id"]
        for record in st.session_state.search_results
        if tenant_records[record["id"]]["classification"] <= user.clearance_level
    ]
    if not ids:
        st.warning("Run a search with at least one authorized result first.")
        return
    public_key: PaillierPublicKey = st.session_state.server["public_keys"][user.tenant_id]
    encrypted_values: list[EncryptedNumber] = [
        st.session_state.server["records"][user.tenant_id][record_id]["amount"] for record_id in ids
    ]
    started = time.perf_counter()

    def on_step(position: int, total: int, operation: str) -> None:
        log_event("PAILLIER", f"Step {position}/{total}: {operation}")

    encrypted_total = HomomorphicAccumulator(public_key).sum_encrypted(encrypted_values, on_step=on_step)
    log_event(
        "PAILLIER",
        f"Returned one encrypted aggregate for {len(ids)} ciphertext(s)",
        latency_ms=(time.perf_counter() - started) * 1000,
    )
    vault: ClientVault = st.session_state.vaults[user.tenant_id]
    st.session_state.last_sum = vault.paillier.decrypt_integer(encrypted_total)


def add_record(tenant_id: str, text: str, amount: int, classification: int) -> None:
    vault: ClientVault = st.session_state.vaults[tenant_id]
    record_id = f"custom-{time.time_ns()}"
    settings = TENANT_SETTINGS[tenant_id]
    st.session_state.server["records"][tenant_id][record_id] = {
        "payload": vault.cipher.encrypt(text).to_dict(),
        "amount": vault.paillier.encrypt_integer(amount),
        "department": settings["department"],
        "classification": classification,
    }
    trapdoors = (vault.trapdoors.create(term) for term in tokenize(text))
    st.session_state.server["indexes"][tenant_id].add_document(record_id, trapdoors)
    log_event("INDEX", f"Accepted encrypted document={safe_fingerprint(record_id)} for tenant={tenant_id}")


def render_header() -> None:
    mode = "Demo environment active" if st.session_state.demo_ready else "Environment not initialized"
    st.markdown(
        f"""<div class="zk-nav"><div class="zk-brand"><div class="zk-mark">MZK</div>
        <div><div class="zk-brand-name">Multi-Tenant Zero-Knowledge Cloud Engine</div><div class="zk-brand-sub">Information Security Lab · System Demonstrator</div></div></div>
        <div class="zk-status"><span class="zk-dot"></span>{mode}</div></div>""",
        unsafe_allow_html=True,
    )


def render_landing() -> None:
    st.markdown(
        """<section class="zk-hero"><div class="zk-eyebrow">Interactive system demonstration</div>
        <div class="zk-title">Search and aggregate<br><span>encrypted tenant records</span></div>
        <div class="zk-lead">This interface demonstrates the complete protocol boundary: client-side encryption and trapdoor generation, attribute-based authorization, blind server lookup, homomorphic accumulation, and local result decryption.</div></section>""",
        unsafe_allow_html=True,
    )
    action, note = st.columns([.34, .66], vertical_alignment="center")
    with action:
        if st.button("Initialize demo environment", type="primary", use_container_width=True):
            with st.spinner("Generating isolated tenant keys and encrypting records…"):
                load_demo()
            st.rerun()
    note.caption("Creates two isolated tenant key sets and encrypts six sample records in memory.")
    st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)
    columns = st.columns(4)
    steps = (
        ("01", "Policy evaluation", "Tenant, role, department, clearance, and session time are evaluated."),
        ("02", "Query preparation", "The authorized client produces a tenant-bound HMAC-SHA256 trapdoor."),
        ("03", "Server processing", "The server matches opaque tokens and combines Paillier ciphertexts."),
        ("04", "Client recovery", "The tenant client authenticates documents and decrypts the final sum."),
    )
    for column, (number, title, copy) in zip(columns, steps):
        column.markdown(f'<div class="zk-step"><div class="zk-step-no">{number}</div><div class="zk-step-title">{title}</div><div class="zk-step-copy">{copy}</div></div>', unsafe_allow_html=True)


def render_identity_controls() -> tuple[UserAttributes, str, int]:
    st.markdown('<div class="zk-section-kicker">Client identity</div><div class="zk-section-title">Access context</div><div class="zk-section-copy">Change an attribute to see the policy engine allow or deny the operation.</div>', unsafe_allow_html=True)
    first, second = st.columns(2)
    tenant_id = first.selectbox("Tenant", tuple(TENANT_SETTINGS), format_func=lambda value: TENANT_LABELS[value])
    roles = sorted(TENANT_SETTINGS[tenant_id]["roles"] | {"guest"})
    role = second.selectbox("Role", roles, index=roles.index("admin"))
    third, fourth = st.columns(2)
    department = third.text_input("Department", TENANT_SETTINGS[tenant_id]["department"], key=f"department_{tenant_id}")
    clearance = fourth.select_slider("Clearance", options=[0, 1, 2, 3], value=3)
    hour = st.slider("Session hour · UTC", 0, 23, datetime.now(timezone.utc).hour)
    return UserAttributes("demo-user", tenant_id, role, department, clearance), tenant_id, hour


def render_server_console(tenant_id: str) -> None:
    st.markdown('<div class="zk-section-kicker">Untrusted server</div><div class="zk-section-title">Execution trace</div><div class="zk-section-copy">Messages recorded at the server boundary, without plaintext values or secret keys.</div>', unsafe_allow_html=True)
    index = st.session_state.server["indexes"][tenant_id]
    records = st.session_state.server["records"][tenant_id]
    one, two = st.columns(2)
    one.metric("Ciphertexts", len(records))
    two.metric("Blind tokens", index.term_count)
    st.markdown('<div class="zk-boundary">◉ <b>Server visibility:</b> public key · ciphertext · policy metadata · token fingerprints</div>', unsafe_allow_html=True)
    filter_col, clear_col = st.columns([.72, .28], vertical_alignment="bottom")
    component = filter_col.selectbox("Event filter", ["ALL", "ABAC", "SSE", "PAILLIER", "INDEX", "CLIENT"], label_visibility="collapsed")
    if clear_col.button("Clear", use_container_width=True):
        st.session_state.logs = []
        st.rerun()
    events = [event for event in st.session_state.logs if component == "ALL" or event["component"] == component]
    if not events:
        st.info("No matching events yet. Run a secure operation to populate the trace.")
        return
    with st.container(height=410):
        for event in events:
            latency = f" · {event['latency_ms']:.3f} ms" if "latency_ms" in event else ""
            kind = html.escape(event["component"].lower())
            st.markdown(f'<div class="zk-log {kind}"><div class="zk-log-head"><span>{html.escape(event["component"])}</span><span>{html.escape(event["time"])}{latency}</span></div><div class="zk-log-body">{html.escape(event["event"])}</div></div>', unsafe_allow_html=True)


def render_operations() -> tuple[UserAttributes, str, int]:
    left, right = st.columns([1.08, .92], gap="large")
    with left:
        with st.container(border=True):
            user, tenant_id, hour = render_identity_controls()
        st.markdown("<div style='height:.5rem'></div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown('<div class="zk-section-kicker">Encrypted search</div><div class="zk-section-title">Blind record discovery</div><div class="zk-section-copy">The query becomes a tenant-bound trapdoor only after access is approved.</div>', unsafe_allow_html=True)
            search_col, button_col = st.columns([.72, .28], vertical_alignment="bottom")
            term = search_col.text_input("Search token", placeholder="Try quarterly, patient, or cardiology", label_visibility="collapsed")
            submitted = button_col.button("Secure search", type="primary", use_container_width=True, disabled=not term.strip())
            if submitted:
                run_search(user, term, hour)
            context_matches = st.session_state.last_search_context == user_context_signature(user, hour)
            results = st.session_state.search_results if context_matches else []
            if results:
                st.caption(f"{len(results)} authorized result(s) decrypted inside the client boundary")
                for record in results:
                    st.markdown(f'<div class="zk-result"><div class="zk-result-id">{html.escape(record["id"])}</div><div class="zk-result-text">{html.escape(record["text"])}</div></div>', unsafe_allow_html=True)
                aggregate_col, total_col = st.columns([.55, .45], vertical_alignment="center")
                if aggregate_col.button("Compute encrypted total", use_container_width=True):
                    aggregate_results(user, hour)
                if st.session_state.last_sum is not None:
                    total_col.metric("Locally decrypted", f"{st.session_state.last_sum:,}")
            elif submitted:
                st.info("No authorized records matched this blind token.")
    with right:
        with st.container(border=True):
            render_server_console(tenant_id)
    return user, tenant_id, hour


def render_ingestion(user: UserAttributes, tenant_id: str, hour: int) -> None:
    content, explanation = st.columns([1.05, .95], gap="large")
    with content:
        with st.container(border=True):
            st.markdown('<div class="zk-section-kicker">Trusted client</div><div class="zk-section-title">Encrypt a new record</div><div class="zk-section-copy">Raw values exist only during this client operation. The server receives ciphertexts and HMAC index tokens.</div>', unsafe_allow_html=True)
            with st.form("record_form", clear_on_submit=True):
                new_text = st.text_area("Sensitive document", placeholder="Enter a financial or medical record…", height=150)
                amount_col, class_col = st.columns(2)
                new_amount = amount_col.number_input("Integer amount / metric", step=1, value=0)
                new_classification = class_col.select_slider("Classification", options=[1, 2, 3], value=1)
                uploaded = st.form_submit_button("Encrypt & upload  →", type="primary", use_container_width=True)
            if uploaded:
                if not new_text.strip():
                    st.error("Enter record text before uploading.")
                elif authorize(user, "index", minimum_clearance=new_classification, hour=hour):
                    add_record(tenant_id, new_text, int(new_amount), new_classification)
                    st.success("Encrypted record accepted. No plaintext was retained by the server.")
    with explanation:
        with st.container(border=True):
            st.markdown("### Upload transformation")
            for label, detail in (("Document", "AES-256-CBC + HMAC envelope"), ("Numeric field", "Paillier ciphertext"), ("Search terms", "HMAC-SHA256 tokens")):
                st.markdown(f"**{label}**  →  {detail}")
                st.progress(1.0)
            st.caption("Independent keys are generated per tenant. Cross-tenant ciphertexts and tokens cannot be mixed successfully.")


def render_security_model() -> None:
    st.markdown("## Security model")
    st.caption("An honest-but-curious cloud can execute the workflow without receiving the secrets needed to reveal its inputs.")
    columns = st.columns(4)
    cards = (
        ("01", "Cipher documents", "Fresh IVs and encrypt-then-MAC protect sensitive UTF-8 payloads."),
        ("02", "Gate requests", "Deny-by-default ABAC executes before any search trapdoor is produced."),
        ("03", "Match blindly", "Tenant-scoped deterministic tokens reveal no plaintext query word."),
        ("04", "Add ciphertexts", "Paillier multiplication modulo n² yields an encrypted plaintext sum."),
    )
    for column, (number, title, copy) in zip(columns, cards):
        column.markdown(f'<div class="zk-step"><div class="zk-step-no">{number}</div><div class="zk-step-title">{title}</div><div class="zk-step-copy">{copy}</div></div>', unsafe_allow_html=True)
    st.warning("Leakage remains: deterministic SSE reveals repeated queries, match counts, and access patterns. Tenant IDs, document IDs, policy metadata, and ciphertext sizes are visible. This is not a formal zero-knowledge proof protocol.")


def main() -> None:
    st.set_page_config(page_title="Multi-Tenant ZK Engine", page_icon="◈", layout="wide", initial_sidebar_state="collapsed")
    initialize_state()
    st.markdown(APP_STYLES, unsafe_allow_html=True)
    render_header()
    if not st.session_state.demo_ready:
        render_landing()
        return
    st.caption("SIMULATION SESSION · 2 ISOLATED TENANTS · CLIENT KEYS HELD IN MEMORY · SERVER VIEW SANITIZED")
    operations_tab, ingestion_tab, model_tab = st.tabs(["Query workspace", "Record ingestion", "Protocol notes"])
    with operations_tab:
        user, tenant_id, hour = render_operations()
    with ingestion_tab:
        render_ingestion(user, tenant_id, hour)
    with model_tab:
        render_security_model()


if __name__ == "__main__":
    main()
