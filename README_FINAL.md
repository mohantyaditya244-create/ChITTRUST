
# ChitTrust Final Prototype

## Professional enterprise-style features

- Administrator and read-only Member login
- Role-based UI
- Professional sidebar workspace
- Dashboard
- Transactions
- Financial Health
- Members
- Hash-Linked Ledger
- Integrity Verification
- Audit Log
- Notifications
- Reports & Evidence
- Member editing with audit trail
- Transaction correction with reason
- Transaction voiding with reason
- SHA-256 transaction/evidence hashes
- Ed25519 signatures when cryptography is installed
- Evidence upload
- CSV export
- SQLite local demo database

## Demo accounts

Administrator:
- username: `admin`
- password: `admin123`

Member:
- username: `rahul`
- password: `member123`

The member account is read-only.

## Run

```powershell
py -m pip install -r requirements.txt
py -m uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

## WhatsApp

The prototype contains the notification workspace and a production-safe notification architecture concept. A real WhatsApp Business API/provider requires provider credentials and approved messaging templates. The ledger transaction should be committed before sending the notification; failed notifications should be retried independently.

## Important

This is a hackathon prototype. The authentication/session implementation is intentionally simple for local demonstration. A production deployment should use HTTPS, secure HttpOnly cookies or JWT with refresh-token rotation, proper password policies, CSRF protection where applicable, secret/key management, PostgreSQL, object storage, rate limiting, and a real WhatsApp Business API integration.
