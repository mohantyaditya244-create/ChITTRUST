
# Uploaded Architecture → Prototype Mapping

| Architecture block | Prototype implementation |
|---|---|
| Members / Organizer / Witness / Auditor | Dashboard roles and confirmation fields |
| Responsive PWA / React | Responsive HTML/CSS/JS web UI |
| Offline Transaction Queue | UI/API-ready structure; offline queue is marked as next-stage |
| API / Event Gateway | FastAPI endpoints |
| Notifications | Next-stage |
| Evidence Capture | `/api/transactions/evidence` + `uploads/` |
| Member/Witness Confirmation | `confirmed_by` field |
| Digital Signature | Ed25519 signature |
| SHA-256 Hash | Evidence and transaction hashes |
| Previous-Hash Link | `previous_hash` |
| Hash-Linked Ledger | `transactions` table + `/api/verify` |
| Fund & Member Management | `schemes` and `members` tables |
| Contribution / Payout Ledger | `transactions` table |
| Transaction Event | Transaction creation endpoint |
| Multi-Signature Approval | Prototype confirmation field; multi-party approval is next-stage |
| Correction / Audit Trail | correction transaction type + audit_log |
| Expected Collection | members × contribution |
| Actual Collection | contribution transactions |
| Collection Ratio | actual / expected |
| Cash-Flow Coverage | (available + expected) / upcoming payout |
| 3-Month Forecast | Next-stage |
| Risk State | Healthy / Warning / Critical |
| Early Warning | Risk badge |
| Organizer Dashboard | Main dashboard |
| Member Dashboard | Member/ledger sections in same prototype |
| Verified Receipt / Ledger Report | Evidence links + CSV export |
| Integrity Verification | `/api/verify` |
| PostgreSQL | Production target; local demo uses SQLite |
| Evidence Storage | Local uploads folder; object storage is production target |
| Emergency Recovery | Architecture placeholder |
| Proof of Fairness | Architecture placeholder |
