
# AuthKey Advanced Service

Features:
- Web admin panel (served at /admin.html)
- JWT cookie-based admin sessions
- Optional 2FA (TOTP)
- Rate limiting (IP + account)
- Encrypted keys (Fernet)
- Logs with CSV download
- Email alerts for suspicious activity
- Docker & docker-compose support
- .env example provided

## Quick start (local)

1. Copy `.env.example` -> `.env` and fill values (generate a FERNET_KEY: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)

2. Create venv & install:
```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Create an admin (one-time):
```
python -c "import requests; print('use /setup_admin')"
```

Or call the API:
```
POST /setup_admin  with JSON {\"email\":\"admin@example.com\", \"password\":\"secret\"}
```

4. Run:
```
uvicorn app:app --reload --port 8000
```

Open http://127.0.0.1:8000/admin.html and login with the admin account.

## Docker
```
cp .env.example .env
# edit .env
docker-compose up --build
```

