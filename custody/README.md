# NYAYAI — Cryptographic Chain of Custody Ledger (`custody/`)

**Module Lead:** Ridhi Masih (Evidence Intelligence Lead)  
**Standard:** ISO/IEC 27037 & Bharatiya Sakshya Adhiniyam (BSA), 2023 (Section 63/65B)  
**Package:** `custody`

---

## 1. Overview
The Chain of Custody module implements continuous cryptographic hash chaining and Merkle Tree Root verification for every evidence event from initial intake to final courtroom disposition.

## 2. Core Architectural Principles
1. **Case & Evidence Dual-Binding (Rule 9):** Every custody event block strictly records and binds both `case_id` and `evidence_id`.
2. **Deterministic Hash Chaining (Rule 7):** Each event hash is computed canonically:
   $$\text{event\_hash} = \text{SHA256}(\text{previous\_event\_hash} \mid \text{seq} \mid \text{case\_id} \mid \text{evidence\_id} \mid \text{action} \mid \text{actor\_id} \mid \text{timestamp} \mid \text{payload})$$
3. **Binary Merkle Root Checksum:** Computes a root hash over all sequential block hashes adhering to RFC 6962.
4. **Auditability & Non-Repudiation (Rule 8):** Every access, analysis, or transfer action is recorded with UTC timestamp and actor badge.
5. **Zero Evidence Mutation (Rule 2):** Ledger operations are metadata operations; original vaulted evidence is never touched.
6. **Independent Testability (Rule 15):** The custody engine is purely cryptographic and testable in total isolation.

## 3. Usage Example
```python
from custody import CryptographicCustodyLedger, GENESIS_HASH

ledger = CryptographicCustodyLedger()

# Create initial block
block1 = ledger.create_event(
    case_id="CR-2026-0042",
    evidence_id="EVD-2026-0001",
    sequence_number=1,
    action="EVIDENCE_INTAKE",
    actor_id="INV-DL-9841",
    details={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    previous_event_hash=GENESIS_HASH
)

# Verify chain integrity
verification = ledger.verify_chain([block1])
print(verification["is_valid"])      # True
print(verification["merkle_root"])  # SHA-256 Merkle root
```
