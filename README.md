
# ChitTrust — Architecture Prototype

This prototype follows the uploaded architecture at a functional-demo level.

## Implemented

### Users & Channels
- Member / organizer style web dashboard
- Cash/paper receipt evidence input
- Member list with editable names

### Access Layer
- Responsive web UI
- FastAPI REST API
- Local evidence storage
- CSV export

### ChitTrust Core
- Scheme and member management
- Contribution / payout ledger
- Transaction events
- Audit log
- Correction transaction type
- Member confirmation field

### Evidence & Security Layer
- Receipt/photo upload
- SHA-256 evidence hash
- Ed25519 digital signature when `cryptography` is installed
- Previous-hash linking
- Hash-linked ledger
- Integrity verification

### Financial Health Engine
- Expected collection
- Actual collection
- Collection ratio
- Available cash
- Upcoming payout
- Coverage ratio
- Healthy / Warning / Critical state

### Dashboards & Reports
- Organizer-style dashboard
- Member list
- Ledger table
- Evidence links
- CSV export
- Integrity verification result

### Future-feature placeholders
- Emergency recovery workflow
- Proof-of-fairness workflow

## Run on Windows

Open PowerShell in this folder:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
py -m uvicorn app:app --reload
```

Open:

http://127.0.0.1:8000

If PowerShell blocks activation, run the server without activating:

```powershell
py -m pip install -r requirements.txt
py -m uvicorn app:app --reload
```

## Backend member-name editing

The frontend Edit button calls:

```http
PATCH /api/members/{member_id}
```

Example:

```json
{
  "name": "New Member Name",
  "phone": "9876543210"
}
```

The change is also written to the audit log. The member ID is preserved, so existing transaction references remain linked to that member.

## Database

The demo uses SQLite so it can run locally with almost no setup.

The architecture diagram shows PostgreSQL. For a production build, replace the SQLite repository layer with PostgreSQL/SQLAlchemy while keeping the API and security layers.

## Important prototype limitation

A hash/signature proves that the stored record/evidence was not silently altered after recording; it does not by itself prove that physical cash was actually handed over. The system should therefore keep member/witness confirmation and evidence together.

This is a transparency and record-keeping prototype. It does not grant legal authorization or determine whether a particular savings arrangement is lawful.
