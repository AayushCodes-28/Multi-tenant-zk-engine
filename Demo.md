# Demo

## 0. Pre-flight

Close old runs so nothing is left over:

```bash
# Mac / Linux
pkill -f uvicorn; pkill -f streamlit
# Windows (closes ALL python processes, save other work first)
taskkill /F /IM python.exe
```

Open two terminals in the project folder:

- Terminal A: `python -m pytest -v`
- Terminal B: `streamlit run app.py`, but do not start it until step 3.

Rules for the live demo:

- Do **not** refresh the browser page. It loses the client keys, and setup then fails with "tenant already registered". If it happens, kill the processes as above and restart Streamlit.
- Click the setup button **once**.
- Choose **1024** in the key-size dropdown. 2048 works but is slow.
- If port 8000 is busy, run `ZK_SERVER_URL=http://127.0.0.1:8010 streamlit run app.py`. On PowerShell use `$env:ZK_SERVER_URL="http://127.0.0.1:8010"` first.

## 1. Pitch

**Say:** "Cloud servers storing financial or medical records can't be trusted with plaintext. Normal encryption forces you to decrypt everything to search or compute. Our server searches and sums encrypted data without seeing plaintext, keys or search words. We also attack our own design to measure what it leaks, and the client verifies the server isn't lying."

## 2. Automated proof

**Action (Terminal A):**

```bash
python -m pytest -v
```

**Expected:** `27 passed`

- `test_search_and_sum_match_plaintext`: encrypted results equal plaintext results.
- `test_server_enforces_clearance_not_the_client`: access control lives on the server.
- `test_dropped_result_is_detected` and `test_forged_sum_is_detected_by_audit`: a lying server is caught.
- `test_audit_chain_detects_edits`: logs are tamper-evident.
- `test_server_view_contains_no_plaintext`: the server never holds plaintext.

## 3. Start the system

**Action (Terminal B):**

```bash
streamlit run app.py
```

**See:** the browser opens, a message says "Register tenants and load demo data from the sidebar" and the server starts in the background by itself.

**Say:** "The dashboard is only a client. The server is a separate FastAPI process. Keys never leave the client."

**Action:** in the sidebar, set key bits to 1024, keep **Pad posting lists** ticked, click **Register tenants and load demo data** and wait a few seconds.

**See:** the Query tab appears. The sidebar shows Tenant `acme-finance`, Role `analyst`, Clearance `2`.

**Say:** "Two tenants were created: Acme Finance and Northstar Health. Records were encrypted on the client with AES, amounts with Paillier, and a keyword index was built from HMAC trapdoors. The client also built Merkle trees and kept only the two root hashes."

## 4. Blind search and encrypted sums

Stay on `acme-finance`, role `analyst`, clearance `2`. Go to the **Query** tab.

1. **Action:** search `payroll`, click **Search**.
   - **See:** one row, `fin-001`, "Quarterly payroll review approved for the engineering division", amount 125000. The caption reads "1 trapdoor lookups ... all index and record proofs verified".
   - **Say:** "The server only saw an opaque 64-character token. It never saw the word payroll."
2. **Action:** click **Encrypted sum**.
   - **See:** `125,000.00` and a caption "Plaintext cross-check: 125,000 (match)".
   - **Say:** "The server multiplied ciphertexts under Paillier. Only the client can decrypt the result."
3. **Action:** change the search to `quarterly`, click **Search**, then **Encrypted sum**, then **Encrypted average**.
   - **See:** two rows (`fin-001`, `fin-003`), sum `143,000.00`, average `71,500.00`.
4. **Action:** search `quarterly planning` with **and** selected, click **Search**.
   - **See:** only `fin-003` (travel reimbursement, 18000).
   - **Action:** switch to **or**, click **Search**.
   - **See:** both rows.
   - **Say:** "AND and OR are combined on the client, each token verified separately."

## 5. Server-side access control

1. **Action:** search `acquisition`, click **Search** (still clearance 2).
   - **See:** an empty table and the caption "1 hidden by clearance".
   - **Say:** "The record exists, but it is classified level 3 and the caller has level 2. The server refused to return it."
2. **Action:** move the Clearance slider to **3**, click **Search** again.
   - **See:** `fin-002`, "Confidential acquisition reserve and treasury forecast", 275000.
3. **Action:** set the slider back to **1**, search `quarterly`, click **Search**, then **Encrypted sum**.
   - **See:** only `fin-003`, sum `18,000.00`.
4. **Action:** set Role to **intern**, click **Search**.
   - **See:** a yellow warning "Server denied the request (403)".
   - **Action:** set Role to analyst and Department to **other**, click **Search**.
   - **See:** another 403.
   - **Say:** "These checks run on the server using a signed token. Editing the UI cannot bypass them."
5. **Action:** switch Tenant to **northstar-health**, Role to `clinician`, Clearance `3`, search `patient`, click **Search**, then **Encrypted sum**.
   - **See:** three rows, sum `326.00`.
   - **Action:** search `payroll`.
   - **See:** nothing.
   - **Say:** "Tenants have separate keys and separate trees. One tenant cannot read the other."
6. **Action:** switch back to `acme-finance`, role `analyst`, clearance `2`.

## 6. What the server actually holds

**Action:** open the **Client / server trace** tab.

**See:**

- Left: the client's own events (trapdoor created, proofs verified, Paillier result decrypted locally).
- Right: the server audit chain, banner **Hash chain intact**. Rows show components such as SSE, ABAC and PAILLIER, ALLOW and DENY decisions, and latency in ms. Your intern attempt appears as a DENY row.
- Bottom, "What the server stores": a table of trapdoor prefixes with posting sizes, a table of records showing only ciphertext sizes, department and classification, and the two Merkle roots.

**Say:** "There is no plaintext anywhere on the server. It does see sizes, which records matched, and the department and classification fields it needs to enforce policy. The next section measures what that leaks."

**Optional terminal proof (a third terminal):**

```bash
curl http://127.0.0.1:8000/_demo/view/acme-finance
curl -i http://127.0.0.1:8000/t/acme-finance/roots
```

The first shows the server's raw view with no words in it. The second returns `401` with "missing bearer token", because without a signed capability nobody gets anything.

## 7. Malicious server

Open the **Malicious server** tab. Make sure the sidebar is `acme-finance`, `analyst`, clearance `2`.

1. **Action:** click **Run search + sum with audit**.
   - **See:** green "verified records" and "Verified sum".
2. **Action:** click **Forge encrypted sum**, then **Run search + sum with audit**.
   - **See:** red `VERIFICATION FAILED ... server forged the sum`.
   - **Say:** "The server returned a plausible but wrong encrypted total. The client re-checked it against Merkle-proven ciphertexts and rejected it."
3. **Action:** click **Drop one search result**, then **Run search + sum with audit**.
   - **See:** red `VERIFICATION FAILED ... result tampered or incomplete`.
   - **Say:** "The server hid a matching record. The Merkle proof for that token no longer matches, so the client caught it."
4. **Action:** click **Honest**, then **Run search + sum with audit** to show it works again.
5. **Action:** click **Edit a server audit entry**, then open the **Client / server trace** tab.
   - **See:** a red banner "Chain broken at entry N".
   - **Say:** "Every log entry hashes the previous one, so editing history is detectable." Do this last. It cannot be undone until you restart.

## 8. Adding data and epoch rotation

**Note:** if you did the audit edit above, the chain stays red. That is fine, the rest still works.

Open the **Admin** tab on `acme-finance`.

1. **Action:** keep the defaults ("Payroll correction for support staff", amount 500, classification 1), click **Add record (verified incremental update)**.
   - **See:** a green "Added ..." message with a new id.
   - **Say:** "The client fetched proofs, verified them against its pinned roots, computed the new roots itself, and checked the server agreed."
2. **Action:** go to **Query**, search `payroll`, click **Search**, then **Encrypted sum**.
   - **See:** two rows, sum `125,500.00`.
3. **Action:** back in **Admin**, click **Rotate trapdoor epoch**.
   - **See:** a message that searches now use 2 trapdoors per term.
4. **Action:** change the text to `Payroll retroactive adjustment`, amount `300`, click **Add record**.
5. **Action:** in **Query**, search `payroll`, click **Search**, then **Encrypted sum**.
   - **See:** three rows, sum `125,800.00`, and the caption "2 trapdoor lookups".
   - **Say:** "After rotation, new documents use tokens the server cannot link to older searches. That is forward privacy. The price is one extra lookup per epoch."

## 9. Leakage attack lab: your differentiator

**Action:** open **Leakage attack lab**, keep the defaults, click **Run attack against every defense**.

**See:** a table and bar chart. With the default 3 trials the numbers land within a few points of this table (the README numbers come from `python -m src.attack`, 5 trials):

| Defense | Keywords recovered by the server |
|---|---|
| none | about 40% |
| padding | about 11% |
| epochs = 4 | about 32% |
| epochs = 8 | about 25% |
| padding + epochs | about 10% |

**Say:** "Searchable encryption leaks. A server that knows public word statistics can match posting-list sizes to keywords. We implemented that attack, measured it, then added defenses and re-measured. Random guessing would be around 0.25%. Padding does most of the work against this attack. Epochs mainly buy forward privacy. Padding costs about 1.3 to 1.4 times the index size."

## 10. Closing

**Say:** "To summarise: a real client/server split, access control enforced server-side with signed capabilities, encrypted search and homomorphic sums, a measured leakage attack with defenses, Merkle-verified results, and a tamper-evident audit log. The README lists the limitations: in-memory storage, a single writer, and padding at bulk load only."

## Likely questions and short answers

- **Why is it called zero-knowledge?** The server learns nothing beyond the documented leakage. No zero-knowledge proofs are used, and the README says so.
- **What does the server still learn?** Record ids and sizes, which ids match a token, repeated searches within an epoch, padded posting sizes, and the department and classification fields.
- **Why Paillier?** It is additively homomorphic, so sums, weighted sums and averages work on ciphertexts. It cannot do min, max or multiplication of two encrypted values.
- **Why not just AES everywhere?** AES alone forces decryption before any computation or search.
- **How is access control enforced?** An Ed25519-signed token carries role, department, clearance and expiry. The server verifies it and runs the ABAC check on every request.
- **What stops the server returning a wrong sum?** The client recomputes it from Merkle-proven ciphertexts when audit is on.
- **What does padding do?** It adds decoy ids so posting-list sizes blur. The client filters decoys after decrypting.
- **What would you improve?** Persistent storage, multi-client root sync, TLS, and padding for incremental updates.

## Know your code before you present

Spend 15 minutes opening these in this order so you can answer follow-ups:

1. `src/crypto_engine.py`: AES-CBC with MAC, HKDF, trapdoor generation (`create` with `epoch`).
2. `src/server.py`: the `authorize` function, which does token check and ABAC on every request.
3. `src/client.py`: `search` and `aggregate`, plus `_verified_ids`, which is where the verification happens.
4. `src/merkle.py`: `verify` and `updated_root`.
5. `src/attack.py`: `count_attack`, about 15 lines.

If someone asks who wrote which part, answer honestly.

## If something breaks mid-demo

| Problem | Fix |
|---|---|
| "tenant already registered" | You refreshed or clicked setup twice. Kill all processes (step 0) and restart Streamlit. |
| "Server not reachable" | The server did not start. Run `ZK_DEMO=1 uvicorn src.server:create_app_from_env --factory --port 8000` in another terminal, then reload. |
| Setup is slow | You picked 2048 bits. Use 1024. |
| Red verification error after the malicious tab | The tamper mode is still on. Click **Honest** on the Malicious server tab. |
| Anything else | Fall back to `python -m pytest -v` and `python -m src.attack`, which need no UI. |