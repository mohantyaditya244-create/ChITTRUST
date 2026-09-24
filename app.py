
import os
import json
import sqlite3
import hashlib
import hmac
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "chittrust.db"
UPLOAD_DIR = BASE / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI(title="ChitTrust Prototype", version="1.0")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sign_payload(payload: str):
    if not CRYPTO_AVAILABLE:
        return "CRYPTOGRAPHY_NOT_INSTALLED"
    key_file = BASE / ".demo_ed25519_private"
    if key_file.exists():
        key = Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
    else:
        key = Ed25519PrivateKey.generate()
        key_file.write_bytes(
            key.private_bytes_raw()
        )
    sig = key.sign(payload.encode("utf-8"))
    return base64.b64encode(sig).decode()


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 from Python's standard library."""
    salt = os.urandom(16)
    iterations = 310000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt_b64, digest_b64 = stored.split("$", 3)
            salt = base64.urlsafe_b64decode(salt_b64.encode())
            expected = base64.urlsafe_b64decode(digest_b64.encode())
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
            return hmac.compare_digest(actual, expected)
        # Backward compatibility with the older demo fallback hashes.
        return hashlib.sha256(password.encode("utf-8")).hexdigest() == stored
    except Exception:
        return False


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        member_id INTEGER,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schemes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        members_count INTEGER NOT NULL,
        contribution REAL NOT NULL,
        payout REAL NOT NULL,
        cycle_months INTEGER NOT NULL DEFAULT 12,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scheme_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'member',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scheme_id) REFERENCES schemes(id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scheme_id INTEGER NOT NULL,
        member_id INTEGER,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        note TEXT,
        evidence_file TEXT,
        evidence_hash TEXT,
        confirmed_by TEXT,
        signature TEXT,
        previous_hash TEXT NOT NULL,
        transaction_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scheme_id) REFERENCES schemes(id),
        FOREIGN KEY(member_id) REFERENCES members(id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        entity TEXT NOT NULL,
        entity_id INTEGER,
        details TEXT,
        created_at TEXT NOT NULL
    );
    """)
    row = con.execute("SELECT COUNT(*) AS c FROM schemes").fetchone()
    # Demo accounts. Use Python's standard-library PBKDF2 password hashing
    # so the prototype does not depend on the Passlib/bcrypt version pairing.
    if con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        def ph(p):
            return hash_password(p)
        con.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            ("admin", ph("admin123"), "admin", now())
        )
        # Member account is linked to member #1 after the demo member seed below.
    if row["c"] == 0:
        con.execute(
            "INSERT INTO schemes(name,members_count,contribution,payout,cycle_months,created_at) VALUES(?,?,?,?,?,?)",
            ("Village Savings Circle - Demo", 20, 5000, 100000, 12, now())
        )
        sid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        names = [
            "Rahul Patil","Amit Sharma","Sneha More","Pooja Jadhav","Nitin Shinde",
            "Kiran Pawar","Meena Gaikwad","Sagar Chavan","Rohit Mane","Neha Deshmukh"
        ]
        for i, name in enumerate(names, 1):
            con.execute(
                "INSERT INTO members(scheme_id,name,phone,role,created_at) VALUES(?,?,?,?,?)",
                (sid, name, f"9{700000000+i:09d}", "member", now())
            )
        member_id = con.execute("SELECT id FROM members ORDER BY id LIMIT 1").fetchone()["id"]
        if con.execute("SELECT COUNT(*) AS c FROM users WHERE username='rahul'").fetchone()["c"] == 0:
            def ph2(p):
                return hash_password(p)
            con.execute(
                "INSERT INTO users(username,password_hash,role,member_id,created_at) VALUES(?,?,?,?,?)",
                ("rahul", ph2("member123"), "member", member_id, now())
            )
        con.execute(
            "INSERT INTO audit_log(action,entity,details,created_at) VALUES(?,?,?,?)",
            ("SYSTEM_INIT","scheme","Demo scheme created",now())
        )
    con.commit()
    con.close()


init_db()


@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse(BASE / "static" / "index.html")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(body: LoginRequest):
    con = db()
    user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (body.username.strip(),)).fetchone()
    if not user:
        con.close()
        raise HTTPException(401, "Invalid username or password")
    ok = verify_password(body.password, user["password_hash"])
    if not ok:
        con.close()
        raise HTTPException(401, "Invalid username or password")
    con.close()
    # Prototype session token. Production should use JWT/secure HttpOnly cookies.
    token_payload = f'{user["id"]}:{user["username"]}:{user["role"]}'
    token = base64.urlsafe_b64encode(token_payload.encode()).decode()
    return {"ok": True, "token": token, "role": user["role"], "username": user["username"], "member_id": user["member_id"]}

def current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        raw = base64.urlsafe_b64decode(authorization.split(" ",1)[1].encode()).decode()
        uid, username, role = raw.split(":", 2)
        return {"id": int(uid), "username": username, "role": role}
    except Exception:
        raise HTTPException(401, "Invalid session")



@app.get("/api/summary")
def summary():
    con = db()
    scheme = con.execute("SELECT * FROM schemes ORDER BY id LIMIT 1").fetchone()
    members = con.execute(
        "SELECT COUNT(*) AS c FROM members WHERE scheme_id=? AND active=1",
        (scheme["id"],)
    ).fetchone()["c"]
    actual = con.execute(
        "SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE scheme_id=? AND type='contribution'",
        (scheme["id"],)
    ).fetchone()["s"]
    payouts = con.execute(
        "SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE scheme_id=? AND type='payout'",
        (scheme["id"],)
    ).fetchone()["s"]
    expected = members * scheme["contribution"]
    ratio = (actual / expected) if expected else 0
    available = actual - payouts
    coverage = ((available + expected) / scheme["payout"]) if scheme["payout"] else 0
    if coverage >= 1:
        state = "Healthy"
    elif coverage >= 0.75:
        state = "Warning"
    else:
        state = "Critical"
    con.close()
    return {
        "scheme": dict(scheme),
        "members": members,
        "expected_collection": round(expected,2),
        "actual_collection": round(actual,2),
        "collection_ratio": round(ratio,3),
        "available_cash": round(available,2),
        "upcoming_payout": scheme["payout"],
        "coverage_ratio": round(coverage,3),
        "risk_state": state
    }


@app.get("/api/members")
def get_members():
    con = db()
    rows = con.execute(
        "SELECT id,name,phone,role,active,created_at FROM members WHERE active=1 ORDER BY id"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


class MemberUpdate(BaseModel):
    name: str
    phone: Optional[str] = None


@app.patch("/api/members/{member_id}")
def update_member(member_id: int, body: MemberUpdate, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    if current_user(authorization)["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Member name cannot be empty")
    con = db()
    old = con.execute("SELECT * FROM members WHERE id=?", (member_id,)).fetchone()
    if not old:
        con.close()
        raise HTTPException(404, "Member not found")
    con.execute("UPDATE members SET name=?, phone=? WHERE id=?", (name, body.phone, member_id))
    con.execute(
        "INSERT INTO audit_log(action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?)",
        ("MEMBER_UPDATED","member",member_id,
         json.dumps({"old_name":old["name"],"new_name":name}),now())
    )
    con.commit()
    con.close()
    return {"ok": True, "message": "Member updated", "member_id": member_id, "name": name}


class TransactionCreate(BaseModel):
    member_id: Optional[int] = None
    type: str
    amount: float
    note: Optional[str] = ""
    confirmed_by: Optional[str] = ""


@app.post("/api/transactions")
def create_transaction(body: TransactionCreate, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    if current_user(authorization)["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    if body.type not in ("contribution", "payout", "correction"):
        raise HTTPException(400, "type must be contribution, payout, or correction")
    if body.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    con = db()
    scheme = con.execute("SELECT id FROM schemes ORDER BY id LIMIT 1").fetchone()
    prev = con.execute(
        "SELECT transaction_hash FROM transactions WHERE scheme_id=? ORDER BY id DESC LIMIT 1",
        (scheme["id"],)
    ).fetchone()
    previous_hash = prev["transaction_hash"] if prev else "GENESIS"
    created = now()
    canonical = json.dumps({
        "scheme_id": scheme["id"],
        "member_id": body.member_id,
        "type": body.type,
        "amount": body.amount,
        "note": body.note,
        "confirmed_by": body.confirmed_by,
        "created_at": created,
        "previous_hash": previous_hash
    }, sort_keys=True)
    tx_hash = sha256_text(canonical)
    signature = sign_payload(tx_hash)
    cur = con.execute(
        """INSERT INTO transactions
        (scheme_id,member_id,type,amount,note,confirmed_by,signature,previous_hash,transaction_hash,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (scheme["id"],body.member_id,body.type,body.amount,body.note,body.confirmed_by,
         signature,previous_hash,tx_hash,created)
    )
    tx_id = cur.lastrowid
    con.execute(
        "INSERT INTO audit_log(action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?)",
        ("TRANSACTION_CREATED","transaction",tx_id,body.type,created)
    )
    con.commit()
    con.close()
    return {"ok":True,"transaction_id":tx_id,"transaction_hash":tx_hash,"signature":signature}


@app.post("/api/transactions/evidence")
async def create_transaction_with_evidence(
    member_id: int = Form(...),
    type: str = Form(...),
    amount: float = Form(...),
    note: str = Form(""),
    confirmed_by: str = Form(""),
    evidence: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    current_user(authorization)
    if current_user(authorization)["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    if type not in ("contribution", "payout"):
        raise HTTPException(400, "Invalid transaction type")
    if amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    safe_name = Path(evidence.filename or "evidence.bin").name
    stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    path = UPLOAD_DIR / f"{stamp}_{safe_name}"
    data = await evidence.read()
    path.write_bytes(data)
    evidence_hash = sha256_file(path)

    con = db()
    scheme = con.execute("SELECT id FROM schemes ORDER BY id LIMIT 1").fetchone()
    prev = con.execute(
        "SELECT transaction_hash FROM transactions WHERE scheme_id=? ORDER BY id DESC LIMIT 1",
        (scheme["id"],)
    ).fetchone()
    previous_hash = prev["transaction_hash"] if prev else "GENESIS"
    created = now()
    canonical = json.dumps({
        "scheme_id": scheme["id"], "member_id": member_id, "type": type,
        "amount": amount, "note": note, "confirmed_by": confirmed_by,
        "evidence_hash": evidence_hash, "created_at": created,
        "previous_hash": previous_hash
    }, sort_keys=True)
    tx_hash = sha256_text(canonical)
    signature = sign_payload(tx_hash)
    cur = con.execute(
        """INSERT INTO transactions
        (scheme_id,member_id,type,amount,note,evidence_file,evidence_hash,confirmed_by,signature,previous_hash,transaction_hash,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scheme["id"],member_id,type,amount,note,path.name,evidence_hash,confirmed_by,
         signature,previous_hash,tx_hash,created)
    )
    tx_id = cur.lastrowid
    con.execute(
        "INSERT INTO audit_log(action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?)",
        ("EVIDENCE_CAPTURED","transaction",tx_id,json.dumps({"file":path.name,"evidence_hash":evidence_hash}),created)
    )
    con.commit()
    con.close()
    return {
        "ok":True, "transaction_id":tx_id, "transaction_hash":tx_hash,
        "evidence_hash":evidence_hash, "signature":signature,
        "evidence_url":f"/uploads/{path.name}"
    }

class TransactionCorrection(BaseModel):
    amount: float
    reason: str

@app.patch("/api/transactions/{transaction_id}")
def correct_transaction(transaction_id: int, body: TransactionCorrection, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    if body.amount <= 0 or not body.reason.strip():
        raise HTTPException(400, "Amount and correction reason are required")
    con = db()
    old = con.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
    if not old:
        con.close()
        raise HTTPException(404, "Transaction not found")
    con.execute("UPDATE transactions SET note=COALESCE(note,'') || ' [CORRECTED: ' || ? || ']', amount=? WHERE id=?",
                (body.reason.strip(), body.amount, transaction_id))
    con.execute(
        "INSERT INTO audit_log(action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?)",
        ("TRANSACTION_CORRECTED","transaction",transaction_id,
         json.dumps({"old_amount":old["amount"],"new_amount":body.amount,"reason":body.reason,"admin":user["username"]}),now())
    )
    con.commit()
    con.close()
    return {"ok":True,"status":"CORRECTED","transaction_id":transaction_id}

class VoidRequest(BaseModel):
    reason: str

@app.post("/api/transactions/{transaction_id}/void")
def void_transaction(transaction_id: int, body: VoidRequest, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    if not body.reason.strip():
        raise HTTPException(400, "Void reason is required")
    con = db()
    old = con.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
    if not old:
        con.close()
        raise HTTPException(404, "Transaction not found")
    con.execute("UPDATE transactions SET note=COALESCE(note,'') || ' [VOIDED: ' || ? || ']' WHERE id=?",
                (body.reason.strip(), transaction_id))
    con.execute(
        "INSERT INTO audit_log(action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?)",
        ("TRANSACTION_VOIDED","transaction",transaction_id,
         json.dumps({"reason":body.reason,"admin":user["username"]}),now())
    )
    con.commit()
    con.close()
    return {"ok":True,"status":"VOIDED","transaction_id":transaction_id}



@app.get("/api/transactions")
def get_transactions():
    con = db()
    rows = con.execute("""
        SELECT t.*, COALESCE(m.name,'System') AS member_name
        FROM transactions t LEFT JOIN members m ON m.id=t.member_id
        ORDER BY t.id DESC
    """).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.get("/api/verify")
def verify_chain():
    con = db()
    rows = con.execute("SELECT * FROM transactions ORDER BY id").fetchall()
    issues = []
    previous = "GENESIS"
    for row in rows:
        if row["previous_hash"] != previous:
            issues.append({"transaction_id":row["id"],"issue":"Previous-hash link mismatch"})
        canonical = json.dumps({
            "scheme_id": row["scheme_id"],
            "member_id": row["member_id"],
            "type": row["type"],
            "amount": row["amount"],
            "note": row["note"],
            "confirmed_by": row["confirmed_by"],
            "created_at": row["created_at"],
            "previous_hash": row["previous_hash"]
        }, sort_keys=True)
        expected = sha256_text(canonical)
        # Evidence transactions include evidence_hash in their original payload.
        if row["evidence_hash"]:
            canonical_with_evidence = json.dumps({
                "scheme_id": row["scheme_id"],
                "member_id": row["member_id"],
                "type": row["type"],
                "amount": row["amount"],
                "note": row["note"],
                "confirmed_by": row["confirmed_by"],
                "evidence_hash": row["evidence_hash"],
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"]
            }, sort_keys=True)
            expected = sha256_text(canonical_with_evidence)
        if expected != row["transaction_hash"]:
            issues.append({"transaction_id":row["id"],"issue":"Transaction hash mismatch"})
        previous = row["transaction_hash"]
    con.close()
    return {"valid":len(issues)==0,"checked":len(rows),"issues":issues}

@app.get("/api/me")
def me(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    con = db()
    if user["role"] == "member":
        row = con.execute("""
            SELECT u.username,u.role,u.member_id,m.name,m.phone
            FROM users u LEFT JOIN members m ON m.id=u.member_id
            WHERE u.id=?
        """,(user["id"],)).fetchone()
    else:
        row = con.execute("SELECT username,role,NULL AS member_id,NULL AS name,NULL AS phone FROM users WHERE id=?",(user["id"],)).fetchone()
    con.close()
    return dict(row) if row else user



@app.get("/api/audit")
def audit():
    con = db()
    rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.get("/api/export.csv")
def export_csv():
    import csv
    import io
    con = db()
    rows = con.execute("""
        SELECT t.id,m.name AS member,t.type,t.amount,t.note,t.confirmed_by,
               t.evidence_hash,t.previous_hash,t.transaction_hash,t.created_at
        FROM transactions t LEFT JOIN members m ON m.id=t.member_id
        ORDER BY t.id
    """).fetchall()
    con.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Member","Type","Amount","Note","Confirmed By","Evidence Hash","Previous Hash","Transaction Hash","Created At"])
    for r in rows:
        writer.writerow(list(r))
    from fastapi.responses import Response
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=chittrust_ledger.csv"}
    )
