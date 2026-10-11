from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable

from phe.paillier import EncryptedNumber

from .crypto_engine import AESCBCCipher, CryptographicError, KeyMaterial, TrapdoorGenerator, tokenize
from .merkle import ProofError, SparseMerkle, empty_root, position, updated_root, verify
from .protocol import posting_digest, record_digest

CHUNK = 500


class VerificationError(Exception):
    pass
class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status} {detail}")
        self.status = status
        self.detail = detail

@dataclass
class SearchResult:
    records: list[dict[str, Any]]
    candidates: int
    denied: int
    lookups: int


@dataclass
class ZKClient:
    http: Any
    keys: KeyMaterial
    token: str | None = None
    audit_rate: float = 1.0
    epoch: int = 0
    index_root: bytes = field(default_factory=empty_root)
    record_root: bytes = field(default_factory=empty_root)
    trace: list[tuple[str, str]] = field(default_factory=list)
    steps: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.tenant = self.keys.tenant_id
        self.cipher = AESCBCCipher(self.keys.aes_master_key, self.tenant)
        self.trapdoors = TrapdoorGenerator(self.keys.search_key, self.tenant)

    def _step(self, actor: str, text: str) -> None:
        self.steps.append((actor, text))
        del self.steps[:-400]

    def _call(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        response = self.http.request(method, path, json=body, headers=headers)
        if response.status_code >= 400:
            detail = response.json().get("detail", response.text) if response.content else ""
            raise ApiError(response.status_code, str(detail))
        return response.json()

    def _t(self, suffix: str) -> str:
        return f"/t/{self.tenant}{suffix}"

    def register(self, policy: dict[str, Any]) -> None:
        self._call("POST", f"/tenants/{self.tenant}", {"paillier_n": format(self.keys.public_key.n, "x"), "policy": policy})

    def rotate_epoch(self) -> int:
        self.epoch += 1
        self.trace.append(("CLIENT", f"epoch rotated to {self.epoch}; new documents use unlinkable trapdoors"))
        return self.epoch

    def _make_record(self, raw: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
        amount = self.keys.public_key.encrypt(int(raw["amount"])).ciphertext(be_secure=False)
        record = {
            "id": raw.get("id") or secrets.token_hex(8),
            "payload": self.cipher.encrypt(raw["text"]).to_dict(),
            "amount": format(amount, "x"),
            "department": raw["department"],
            "classification": int(raw["classification"]),
        }
        return record, {self.trapdoors.create(term, self.epoch) for term in tokenize(raw["text"])}

    def bulk_load(self, rows: Iterable[dict[str, Any]], *, pad: bool = False) -> dict[str, int]:
        records, postings = [], {}
        for raw in rows:
            record, tokens = self._make_record(raw)
            records.append(record)
            for token in tokens:
                postings.setdefault(token, set()).add(record["id"])
        added = 0
        if pad:
            everyone = [r["id"] for r in records]
            rng = secrets.SystemRandom()
            for ids in postings.values():
                target = min(1 << (len(ids) - 1).bit_length(), len(everyone))
                pool = [i for i in everyone if i not in ids]
                extra = rng.sample(pool, min(target - len(ids), len(pool)))
                ids.update(extra)
                added += len(extra)
        index, record_tree = SparseMerkle(), SparseMerkle()
        for record in records:
            record_tree.set(record["id"], record_digest(record))
        for token, ids in postings.items():
            index.set(token, posting_digest(ids))
        body = {"records": records, "postings": {t: sorted(ids) for t, ids in postings.items()}}
        roots = self._call("POST", self._t("/bulk"), body)
        if roots["index"] != index.root.hex() or roots["records"] != record_tree.root.hex():
            raise VerificationError("server roots differ from locally computed roots")
        self.index_root, self.record_root = index.root, record_tree.root
        self.trace.append(("CLIENT", f"bulk load: {len(records)} records, {len(postings)} tokens, {added} decoys; roots pinned"))
        return {"records": len(records), "tokens": len(postings), "decoys": added}

    def add_record(self, raw: dict[str, Any]) -> str:
        record, tokens = self._make_record(raw)
        proof = self._call("GET", self._t(f"/record/{record['id']}/proof"))["proof"]
        try:
            if verify(self.record_root, record["id"], proof) is not None:
                raise VerificationError("record id already exists")
            new_root = updated_root(self.record_root, record["id"], record_digest(record), proof)
        except ProofError as exc:
            raise VerificationError(str(exc)) from exc
        roots = self._call("PUT", self._t(f"/record/{record['id']}"), record)
        if roots["records"] != new_root.hex():
            raise VerificationError("record root mismatch after insert")
        self.record_root = new_root
        for token in tokens:
            response = self._call("POST", self._t("/search"), {"trapdoor": token})
            ids = self._verified_ids(token, response)
            merged = sorted({*ids, record["id"]})
            new_index = updated_root(self.index_root, token, posting_digest(merged), response["proof"])
            roots = self._call("PUT", self._t(f"/index/{token}"), {"ids": merged})
            if roots["index"] != new_index.hex():
                raise VerificationError("index root mismatch after insert")
            self.index_root = new_index
        self.trace.append(("CLIENT", f"record added; {len(tokens)} postings updated under epoch {self.epoch}"))
        return record["id"]

    def _verified_ids(self, token: str, response: dict[str, Any]) -> list[str]:
        ids = response["ids"]
        proof = response["proof"]
        self._step("Server", f"scanned encrypted index for `{token[:12]}...` -> found {len(ids)} document id(s)")
        self._step("Server", f"sent Merkle proof for leaf `0x{position(token):010x}` ({len(proof.get('siblings', []))} sibling hashes)")
        try:
            committed = verify(self.index_root, token, proof)
        except ProofError as exc:
            self._step("Client", f"recomputed index root -> MISMATCH with pinned `{self.index_root.hex()[:12]}...` ({exc})")
            raise VerificationError(f"index proof rejected: {exc}") from exc
        if committed is None and ids or committed is not None and committed != posting_digest(ids):
            self._step("Client", "posting list digest differs from the proven leaf -> result tampered or incomplete")
            raise VerificationError("posting list does not match the committed index (result tampered or incomplete)")
        self._step("Client", f"recomputed index root -> matches pinned `{self.index_root.hex()[:12]}...`")
        return ids

    def _fetch(self, ids: list[str]) -> tuple[list[dict[str, Any]], int]:
        out, denied = [], 0
        for start in range(0, len(ids), CHUNK):
            response = self._call("POST", self._t("/fetch"), {"ids": ids[start : start + CHUNK]})
            denied += len(response["denied"])
            for item in response["records"]:
                record = item["record"]
                try:
                    committed = verify(self.record_root, record["id"], item["proof"])
                except ProofError as exc:
                    raise VerificationError(f"record proof rejected: {exc}") from exc
                if committed != record_digest(record):
                    self._step("Client", f"record `{record['id']}` does not match its Merkle leaf -> MODIFIED ON SERVER")
                    raise VerificationError(f"record {record['id']} does not match its commitment")
                out.append(record)
        self._step("Server", f"returned {len(out)} encrypted record(s) with inclusion proofs, {denied} withheld by clearance")
        if out:
            self._step("Client", f"verified {len(out)} record proof(s) -> match pinned record root `{self.record_root.hex()[:12]}...`")
        return out, denied

    def _amount(self, record: dict[str, Any]) -> int:
        return self.keys.private_key.decrypt(EncryptedNumber(self.keys.public_key, int(record["amount"], 16), 0))

    def search(self, terms: str | list[str], mode: str = "and") -> SearchResult:
        words = sorted(tokenize(terms)) if isinstance(terms, str) else sorted({t for x in terms for t in tokenize(x)})
        if not words:
            raise ValueError("no searchable terms")
        per_term, lookups = [], 0
        for word in words:
            found: set[str] = set()
            for epoch, token in enumerate(self.trapdoors.create_all(word, self.epoch)):
                self._step("Client", f"derived trapdoor HMAC-SHA256(key, `{word}`, epoch {epoch}) -> `{token[:12]}...`")
                found.update(self._verified_ids(token, self._call("POST", self._t("/search"), {"trapdoor": token})))
                lookups += 1
            per_term.append(found)
        candidates = set.intersection(*per_term) if mode == "and" else set.union(*per_term)
        self._step("Client", f"candidate ids after {mode.upper()}: {len(candidates)}")
        self.trace.append(("CLIENT", f"{len(words)} term(s) -> {lookups} trapdoors across {self.epoch + 1} epoch(s); all index proofs verified"))
        fetched, denied = self._fetch(sorted(candidates))
        rows = []
        for record in fetched:
            try:
                text = self.cipher.decrypt(record["payload"])
            except CryptographicError as exc:
                raise VerificationError("ciphertext authentication failed") from exc
            present = tokenize(text)
            if (mode == "and" and all(w in present for w in words)) or (mode == "or" and any(w in present for w in words)):
                rows.append({"id": record["id"], "text": text, "amount": self._amount(record), "department": record["department"], "classification": record["classification"]})
        self._step("Client", f"decrypted {len(fetched)} AES-CBC ciphertext(s) (MAC verified), dropped {len(fetched) - len(rows)} decoy/non-match -> {len(rows)} plaintext record(s)")
        return SearchResult(rows, len(candidates), denied, lookups)

    def aggregate(self, ids: list[str], weights: list[int] | None = None, *, audit: bool | None = None) -> int:
        ids = list(dict.fromkeys(ids))
        self._step("Client", f"requested homomorphic sum over {len(ids)} record(s)")
        response = self._call("POST", self._t("/aggregate"), {"ids": ids, "weights": weights})
        if response["ids"] != ids:
            raise VerificationError("server aggregated a different id set")
        self._step("Server", f"multiplied {len(ids)} Paillier ciphertexts mod n^2 without decrypting anything")
        value = self.keys.private_key.decrypt(EncryptedNumber(self.keys.public_key, int(response["ciphertext"], 16), 0))
        self._step("Client", f"decrypted the result locally -> {value:,}")
        check = secrets.SystemRandom().random() < self.audit_rate if audit is None else audit
        if check:
            fetched, denied = self._fetch(ids)
            by_id = {r["id"]: r for r in fetched}
            if denied or len(by_id) != len(ids):
                raise VerificationError("audit could not reproduce the aggregate input set")
            expected = sum((1 if weights is None else w) * self._amount(by_id[i]) for i, w in zip(ids, weights or [1] * len(ids)))
            self._step("Client", f"audit recomputed the sum from proven ciphertexts -> {expected:,} ({'match' if expected == value else 'MISMATCH'})")
            if expected != value:
                raise VerificationError("aggregate disagrees with the committed ciphertexts (server forged the sum)")
        self.trace.append(("CLIENT", f"Paillier result decrypted locally over {len(ids)} ciphertexts; audit={'on' if check else 'off'}"))
        return value

    def aggregate_search(self, terms: str | list[str], mode: str = "and", weights: list[int] | None = None) -> tuple[int, int]:
        ids = [r["id"] for r in self.search(terms, mode).records]
        if not ids:
            return 0, 0
        return self.aggregate(ids, weights), len(ids)

    def audit_log(self) -> dict[str, Any]:
        return self._call("GET", self._t("/audit"))

    def revoke(self, subject_id: str) -> None:
        self._call("POST", self._t("/revoke"), {"subject_id": subject_id})