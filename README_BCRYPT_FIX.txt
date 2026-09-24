ChitTrust bcrypt compatibility fix

This version removes the Passlib/bcrypt dependency that caused the startup crash on Python 3.14.
Passwords are now hashed with PBKDF2-HMAC-SHA256 using Python's standard library.

Run:
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload

Demo:
admin / admin123
rahul / member123
