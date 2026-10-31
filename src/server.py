from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
import json

from fastapi import FastAPI, HTTPException, Request
from phe.paillier import PaillierPublicKey
from pydantic import BaseModel, Field

from .access_control import ABACEngine, AccessRequest, ResourcePolicy
from .audit import AuditLog, recompute_hash
from .capability import Authority, Claims, TokenError, verify_token
from .homomorphic import HomomorphicAccumulator
from .merkle import SparseMerkle
from .protocol import TRAPDOOR_PATTERN, posting_digest, record_digest

MAX_IDS = 10_000


class Policy(BaseModel):
    department: str
    roles: list[str]
    writers: list[str]
    active_hours: tuple[int, int] = (0, 24)
    min_clearance: int = 1


class RegisterIn(BaseModel):
    paillier_n: str
    policy: Policy


class RecordIn(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    amount: str
    department: str
    classification: int = Field(ge=0, le=9)


class BulkIn(BaseModel):
    records: list[RecordIn]
    postings: dict[str, list[str]]


class PostingIn(BaseModel):
    ids: list[str]


class SearchIn(BaseModel):
    trapdoor: str


class FetchIn(BaseModel):
    ids: list[str] = Field(max_length=MAX_IDS)


class AggregateIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=MAX_IDS)
    weights: list[int] | None = None


class RevokeIn(BaseModel):
    subject_id: str


class TamperIn(BaseModel):
    mode: str | None = None


@dataclass
class Tenant:
    public_key: PaillierPublicKey
    policy: Policy
    index: SparseMerkle = field(default_factory=SparseMerkle)
    postings: dict[str, list[str]] = field(default_factory=dict)
    record_tree: SparseMerkle = field(default_factory=SparseMerkle)
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    audit: AuditLog = field(default_factory=AuditLog)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def create_app(authority_public: bytes, *, demo: bool = False, clock: Callable[[], float] = time.time) -> FastAPI:
    app = FastAPI(title="Multi-Tenant ZK Cloud Engine", docs_url=None, redoc_url=None)
    tenants: dict[str, Tenant] = {}
    system_audit = AuditLog()
    revoked: dict[tuple[str, str], float] = {}
    tamper: dict[str, str | None] = {"mode": None}

    def log_of(tenant_id: str) -> AuditLog:
        return tenants[tenant_id].audit if tenant_id in tenants else system_audit

    def authorize(request: Request, tenant_id: str, action: str, policy: Policy | None = None) -> Claims:
        started = time.perf_counter()
        log = log_of(tenant_id)

        def deny(status: int, code: str, message: str, subject: str = "-") -> HTTPException:
            log.append(tenant=tenant_id, subject=subject, action=action, decision="DENY", reason=code)
            return HTTPException(status, f"{code}: {message}")

        header = request.headers.get("authorization", "")
        try:
            if not header.startswith("Bearer "):
                raise TokenError("missing bearer token")
            claims = verify_token(header[7:], authority_public, now=clock())
        except TokenError as exc:
            raise deny(401, "BAD_TOKEN", str(exc)) from exc
        user = claims.user
        subject = _fingerprint(user.subject_id)
        revoked_at = revoked.get((user.tenant_id, user.subject_id))
        if revoked_at is not None and claims.issued_at <= revoked_at:
            raise deny(401, "REVOKED", "capability was revoked", subject)
        if policy is None:
            if tenant_id not in tenants:
                raise HTTPException(404, "unknown tenant")
            policy = tenants[tenant_id].policy
        if action == "index":
            roles = frozenset(policy.writers)
        elif action in ("audit", "admin"):
            roles = frozenset({"admin"})
        else:
            roles = frozenset(policy.roles)
        start_hour, end_hour = policy.active_hours
        resource = ResourcePolicy(tenant_id, policy.department, policy.min_clearance, roles, (start_hour, end_hour))
        decision = ABACEngine().evaluate(AccessRequest(user, resource, action, time.gmtime(clock()).tm_hour))
        log.append(
            tenant=tenant_id,
            subject=subject,
            action=action,
            decision="ALLOW" if decision.allowed else "DENY",
            reason=decision.reason_code,
            ms=round((time.perf_counter() - started) * 1000, 3),
        )
        if not decision.allowed:
            raise HTTPException(403, f"{decision.reason_code}: {decision.message}")
        return claims

    def tenant_of(tenant_id: str) -> Tenant:
        return tenants[tenant_id]

    def note(tenant_id: str, component: str, detail: str, started: float | None = None) -> None:
        extra = {} if started is None else {"ms": round((time.perf_counter() - started) * 1000, 3)}
        tenants[tenant_id].audit.append(tenant=tenant_id, component=component, detail=detail, **extra)

    def roots(tenant: Tenant) -> dict[str, str]:
        return {"index": tenant.index.root.hex(), "records": tenant.record_tree.root.hex()}

    def store_record(tenant: Tenant, record: RecordIn) -> None:
        try:
            ciphertext = int(record.amount, 16)
        except ValueError as exc:
            raise HTTPException(422, "amount must be hexadecimal") from exc
        if not 0 < ciphertext < tenant.public_key.nsquare:
            raise HTTPException(422, "amount ciphertext out of range")
        stored = record.model_dump()
        tenant.records[record.id] = stored
        tenant.record_tree.set(record.id, record_digest(stored))

    def store_posting(tenant: Tenant, trapdoor: str, ids: list[str]) -> None:
        if not TRAPDOOR_PATTERN.match(trapdoor):
            raise HTTPException(422, "trapdoor must be a lowercase SHA-256 hex digest")
        unique = sorted(set(ids))
        if any(i not in tenant.records for i in unique):
            raise HTTPException(422, "posting references an unknown record")
        if unique:
            tenant.postings[trapdoor] = unique
            tenant.index.set(trapdoor, posting_digest(unique))
        else:
            tenant.postings.pop(trapdoor, None)
            tenant.index.set(trapdoor, None)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "demo": demo}

    @app.post("/tenants/{tenant_id}", status_code=201)
    def register(tenant_id: str, body: RegisterIn, request: Request) -> dict[str, str]:
        authorize(request, tenant_id, "admin", policy=body.policy)
        if tenant_id in tenants:
            raise HTTPException(409, "tenant already registered")
        try:
            tenants[tenant_id] = Tenant(PaillierPublicKey(int(body.paillier_n, 16)), body.policy)
        except ValueError as exc:
            raise HTTPException(422, "invalid Paillier modulus") from exc
        note(tenant_id, "TENANT", "registered")
        return roots(tenants[tenant_id])

    @app.get("/t/{tenant_id}/roots")
    def get_roots(tenant_id: str, request: Request) -> dict[str, str]:
        authorize(request, tenant_id, "read")
        return roots(tenant_of(tenant_id))

    @app.post("/t/{tenant_id}/bulk")
    def bulk(tenant_id: str, body: BulkIn, request: Request) -> dict[str, str]:
        authorize(request, tenant_id, "index")
        tenant, started = tenant_of(tenant_id), time.perf_counter()
        if tenant.records or tenant.postings:
            raise HTTPException(409, "bulk load requires an empty tenant")
        for record in body.records:
            store_record(tenant, record)
        for trapdoor, ids in body.postings.items():
            store_posting(tenant, trapdoor, ids)
        note(tenant_id, "INDEX", f"bulk accepted records={len(body.records)} tokens={len(body.postings)}", started)
        return roots(tenant)

    @app.get("/t/{tenant_id}/record/{record_id}/proof")
    def record_proof(tenant_id: str, record_id: str, request: Request) -> dict[str, Any]:
        authorize(request, tenant_id, "index")
        return {"proof": tenant_of(tenant_id).record_tree.prove(record_id)}

    @app.put("/t/{tenant_id}/record/{record_id}")
    def put_record(tenant_id: str, record_id: str, body: RecordIn, request: Request) -> dict[str, str]:
        authorize(request, tenant_id, "index")
        if body.id != record_id:
            raise HTTPException(422, "record id mismatch")
        tenant = tenant_of(tenant_id)
        store_record(tenant, body)
        note(tenant_id, "INDEX", "record stored")
        return roots(tenant)

    @app.get("/t/{tenant_id}/index/{trapdoor}/proof")
    def index_proof(tenant_id: str, trapdoor: str, request: Request) -> dict[str, Any]:
        authorize(request, tenant_id, "index")
        return {"proof": tenant_of(tenant_id).index.prove(trapdoor)}

    @app.put("/t/{tenant_id}/index/{trapdoor}")
    def put_posting(tenant_id: str, trapdoor: str, body: PostingIn, request: Request) -> dict[str, str]:
        authorize(request, tenant_id, "index")
        tenant = tenant_of(tenant_id)
        store_posting(tenant, trapdoor, body.ids)
        note(tenant_id, "INDEX", f"posting updated token={trapdoor[:8]}")
        return roots(tenant)

    @app.post("/t/{tenant_id}/search")
    def search(tenant_id: str, body: SearchIn, request: Request) -> dict[str, Any]:
        authorize(request, tenant_id, "search")
        tenant, started = tenant_of(tenant_id), time.perf_counter()
        if not TRAPDOOR_PATTERN.match(body.trapdoor):
            raise HTTPException(422, "trapdoor must be a lowercase SHA-256 hex digest")
        ids = list(tenant.postings.get(body.trapdoor, []))
        if tamper["mode"] == "drop_result" and ids:
            ids = ids[:-1]
        note(tenant_id, "SSE", f"blind lookup token={body.trapdoor[:8]} matched={len(ids)}", started)
        return {"ids": ids, "proof": tenant.index.prove(body.trapdoor), "root": tenant.index.root.hex()}

    @app.post("/t/{tenant_id}/fetch")
    def fetch(tenant_id: str, body: FetchIn, request: Request) -> dict[str, Any]:
        claims = authorize(request, tenant_id, "read")
        tenant, started = tenant_of(tenant_id), time.perf_counter()
        granted, denied, missing = [], [], []
        for record_id in dict.fromkeys(body.ids):
            record = tenant.records.get(record_id)
            if record is None:
                missing.append(record_id)
            elif record["classification"] > claims.user.clearance_level:
                denied.append(record_id)
            else:
                granted.append({"record": record, "proof": tenant.record_tree.prove(record_id)})
        note(tenant_id, "ABAC", f"fetch granted={len(granted)} filtered_by_classification={len(denied)}", started)
        return {"records": granted, "denied": denied, "missing": missing, "root": tenant.record_tree.root.hex()}

    @app.post("/t/{tenant_id}/aggregate")
    def aggregate(tenant_id: str, body: AggregateIn, request: Request) -> dict[str, Any]:
        claims = authorize(request, tenant_id, "aggregate")
        tenant, started = tenant_of(tenant_id), time.perf_counter()
        ids = list(dict.fromkeys(body.ids))
        if body.weights is not None and len(body.weights) != len(body.ids):
            raise HTTPException(422, "one weight per id is required")
        if body.weights is not None and len(ids) != len(body.ids):
            raise HTTPException(422, "weights require distinct ids")
        records = [tenant.records.get(i) for i in ids]
        if any(r is None for r in records):
            raise HTTPException(404, "unknown record id")

        valid_records = [r for r in records if r is not None]

        if any(r["classification"] > claims.user.clearance_level for r in valid_records):
            tenant.audit.append(tenant=tenant_id, component="ABAC", decision="DENY", reason="INSUFFICIENT_CLEARANCE")
            raise HTTPException(403, "INSUFFICIENT_CLEARANCE: a requested record is above the caller's clearance")
        try:
            result = HomomorphicAccumulator.aggregate_raw(
                tenant.public_key,
                [int(r["amount"], 16) for r in valid_records],
                body.weights,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if tamper["mode"] == "forge_sum":
            forged = tenant.public_key.encrypt(1000).ciphertext(be_secure=False)
            result = result * forged % tenant.public_key.nsquare
        note(tenant_id, "PAILLIER", f"aggregated {len(ids)} ciphertexts weighted={body.weights is not None}", started)
        return {"ciphertext": format(result, "x"), "ids": ids, "count": len(ids)}

    @app.get("/t/{tenant_id}/audit")
    def audit(tenant_id: str, request: Request) -> dict[str, Any]:
        entries = tenant_of(tenant_id).audit.entries
        valid, bad = tenant_of(tenant_id).audit.verify()
        detail = None if valid else {"stored_hash": entries[bad]["hash"], "recomputed_hash": recompute_hash(entries, bad)}
        return {"entries": entries, "valid": valid, "bad_seq": bad, "detail": detail}

    @app.post("/t/{tenant_id}/revoke")
    def revoke(tenant_id: str, body: RevokeIn, request: Request) -> dict[str, bool]:
        authorize(request, tenant_id, "admin")
        revoked[(tenant_id, body.subject_id)] = clock()
        note(tenant_id, "ABAC", f"revoked subject={_fingerprint(body.subject_id)}")
        return {"revoked": True}

    if demo:
        @app.post("/_demo/tamper")
        def set_tamper(body: TamperIn) -> dict[str, str | None]:
            tamper["mode"] = body.mode
            return tamper

        undo: dict[str, list[Callable[[], None]]] = {}

        @app.post("/_demo/audit-edit/{tenant_id}")
        def edit_audit(tenant_id: str) -> dict[str, Any]:
            entries = tenants[tenant_id].audit.entries
            target = max(0, len(entries) // 2)
            entry = entries[target]
            had, original = "reason" in entry, entry.get("reason")
            entry["reason"] = "EDITED"
            undo.setdefault(tenant_id, []).append(lambda: entry.__setitem__("reason", original) if had else entry.pop("reason"))
            return {"seq": target, "field": "reason", "before": original, "after": "EDITED", "entry_hash_still_stored": entry["hash"]}

        @app.get("/_demo/eve/dump/{tenant_id}")
        def eve_dump(tenant_id: str) -> dict[str, Any]:
            tenant = tenants[tenant_id]
            records = [
                {
                    "id": r["id"],
                    "iv": r["payload"]["iv"],
                    "ciphertext": r["payload"]["ciphertext"][:40] + "...",
                    "mac": r["payload"]["mac"][:16] + "...",
                    "amount_ciphertext": r["amount"][:24] + "...",
                    "department": r["department"],
                    "classification": r["classification"],
                }
                for r in tenant.records.values()
            ]
            postings = [{"trapdoor": t[:16] + "...", "doc_ids": ", ".join(ids)} for t, ids in tenant.postings.items()]
            return {"records": records, "postings": postings, "raw": json.dumps({"records": tenant.records, "postings": tenant.postings})}

        @app.post("/_demo/eve/corrupt/{tenant_id}")
        def eve_corrupt(tenant_id: str) -> dict[str, Any]:
            records = list(tenants[tenant_id].records.values())
            example: dict[str, str] = {}
            for record in records:
                original = record["payload"]["ciphertext"]
                record["payload"]["ciphertext"] = ("A" if original[0] != "A" else "B") + original[1:]
                undo.setdefault(tenant_id, []).append(lambda r=record, o=original: r["payload"].__setitem__("ciphertext", o))
                example = example or {"record": record["id"], "ciphertext_before": original[:48], "ciphertext_after": record["payload"]["ciphertext"][:48]}
            return {"corrupted": len(records), **example}

        @app.post("/_demo/eve/inject/{tenant_id}")
        def eve_inject(tenant_id: str) -> dict[str, Any]:
            postings = tenants[tenant_id].postings
            example: dict[str, Any] = {}
            for token, ids in postings.items():
                original = list(ids)
                postings[token] = [*ids, "eve-forged"]
                undo.setdefault(tenant_id, []).append(lambda t=token, o=original: postings.__setitem__(t, o))
                example = example or {"token": token[:32] + "...", "posting_before": original, "posting_after": postings[token]}
            return {"injected": len(postings), **example}
        
        @app.post("/_demo/eve/restore/{tenant_id}")
        def eve_restore(tenant_id: str) -> dict[str, int]:
            actions = undo.pop(tenant_id, [])
            for action in reversed(actions):
                action()
            tamper["mode"] = None
            return {"restored": len(actions)}

        @app.get("/_demo/view/{tenant_id}")
        def server_view(tenant_id: str) -> dict[str, Any]:
            tenant = tenants[tenant_id]
            return {
                "postings": sorted(((t[:16], len(ids)) for t, ids in tenant.postings.items()), key=lambda x: -x[1]),
                "records": [
                    {
                        "id": r["id"],
                        "ciphertext_bytes": len(r["payload"]["ciphertext"]),
                        "department": r["department"],
                        "classification": r["classification"],
                    }
                    for r in tenant.records.values()
                ],
                "index_root": tenant.index.root.hex(),
                "record_root": tenant.record_tree.root.hex(),
            }

    return app


def create_app_from_env() -> FastAPI:
    key_path = Path(os.environ.get("ZK_AUTHORITY_KEY", ".keys/authority.key"))
    authority = Authority.load_or_create(key_path)
    return create_app(authority.public_key, demo=os.environ.get("ZK_DEMO", "0") == "1")