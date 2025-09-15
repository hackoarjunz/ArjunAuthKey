import os
from fastapi import FastAPI, Request, Depends, HTTPException, status, BackgroundTasks, Form, Response
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta
import secrets, csv, io, threading, time, smtplib, pyotp
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Config
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./authkeys_adv.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change_me_super_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
FERNET_KEY = os.getenv("FERNET_KEY") or Fernet.generate_key().decode()
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX_IP = int(os.getenv("RATE_LIMIT_MAX_IP", "10"))
RATE_LIMIT_MAX_ACCOUNT = int(os.getenv("RATE_LIMIT_MAX_ACCOUNT", "20"))
ADMIN_ALERT_EMAIL = os.getenv("ADMIN_ALERT_EMAIL", "")

fernet = Fernet(FERNET_KEY.encode())

# DB setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Boolean, default=False)
    twofa_secret = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    keys = relationship("AuthKey", back_populates="owner")

class AuthKey(Base):
    __tablename__ = "auth_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_encrypted = Column(Text, unique=True)
    status = Column(String, default="active")
    expires_at = Column(DateTime, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner = relationship("User", back_populates="keys")

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)  # generate, validate, revoke, login_fail, suspicious
    key_id = Column(Integer, nullable=True)
    user_id = Column(Integer, nullable=True)
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail = Column(Text, nullable=True)

Base.metadata.create_all(engine)

# Security
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(p): return pwd_ctx.hash(p)
def verify_password(p, h): return pwd_ctx.verify(p, h)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decrypt_key(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()

def encrypt_key(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()

# Rate limiting (in-memory)
rate_lock = threading.Lock()
rate_table_ip = {}      # ip -> [timestamps]
rate_table_account = {} # email -> [timestamps]

def check_rate_limit(ip: str, account: str = None):
    now = time.time()
    window = RATE_LIMIT_WINDOW
    with rate_lock:
        arr = rate_table_ip.get(ip, [])
        arr = [t for t in arr if t >= now - window]
        if len(arr) >= RATE_LIMIT_MAX_IP:
            return False, "ip"
        arr.append(now)
        rate_table_ip[ip] = arr
        if account:
            arr2 = rate_table_account.get(account, [])
            arr2 = [t for t in arr2 if t >= now - window]
            if len(arr2) >= RATE_LIMIT_MAX_ACCOUNT:
                return False, "account"
            arr2.append(now)
            rate_table_account[account] = arr2
    return True, None

# Email helper
def send_email(to_email, subject, body):
    if not SMTP_HOST:
        return False
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            msg = f"From: {SMTP_USER}\\r\\nTo: {to_email}\\r\\nSubject: {subject}\\r\\n\\r\\n{body}"
            smtp.sendmail(SMTP_USER, [to_email], msg)
        return True
    except Exception as e:
        print("Email failed:", e)
        return False

# FastAPI app
app = FastAPI(title="AuthKey Advanced Service")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_admin(request: Request, db=Depends(get_db)):
    token = request.cookies.get("admin_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user

# Routes
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Admin UI routes
@app.get("/admin.html", response_class=HTMLResponse)
def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/admin/login")
def admin_login(request: Request, background: BackgroundTasks, email: str = Form(...), password: str = Form(...), otp: str = Form(None), db=Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    ip = request.client.host
    ua = request.headers.get("user-agent", "")
    if not user or not verify_password(password, user.password_hash) or not user.is_admin:
        # log failed login
        db.add(Log(action="login_fail", user_id=(user.id if user else None), ip=ip, user_agent=ua, detail="bad credentials"))
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # if 2FA enabled, verify
    if user.twofa_secret:
        if not otp or not pyotp.TOTP(user.twofa_secret).verify(otp):
            db.add(Log(action="login_fail", user_id=user.id, ip=ip, user_agent=ua, detail="2fa failed"))
            db.commit()
            raise HTTPException(status_code=401, detail="2FA required/invalid")
    # create token cookie
    token = create_access_token({"sub": user.email})
    resp = RedirectResponse(url="/admin.html", status_code=302)
    resp.set_cookie(key="admin_token", value=token, httponly=True, samesite="lax")
    db.add(Log(action="login_ok", user_id=user.id, ip=ip, user_agent=ua))
    db.commit()
    return resp

@app.post("/admin/logout")
def admin_logout(response: Response):
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("admin_token")
    return resp

# API: create admin (one-off)
@app.post("/setup_admin")
def setup_admin(payload: dict, db=Depends(get_db)):
    email = payload.get("email"); pwd = payload.get("password")
    if not email or not pwd:
        raise HTTPException(status_code=400)
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="exists")
    u = User(email=email, password_hash=hash_password(pwd), is_admin=True)
    db.add(u); db.commit(); db.refresh(u)
    return {"msg":"created"}

# Generate key
class GenerateRequest(BaseModel):
    email: EmailStr = None
    days_valid: int = 30
    email_to_user: bool = False

@app.post("/generate")
def generate(req: GenerateRequest, request: Request, background: BackgroundTasks, db=Depends(get_db)):
    ip = request.client.host
    ok, why = check_rate_limit(ip, req.email if req.email else None)
    if not ok:
        # log suspicious
        db.add(Log(action="suspicious", ip=ip, user_agent=request.headers.get("user-agent",""), detail=f"rate_limit:{why}"))
        db.commit()
        # notify admin if configured
        if ADMIN_ALERT_EMAIL:
            background.add_task(send_email, ADMIN_ALERT_EMAIL, "Suspicious activity", f"Rate limit hit from {ip} reason:{why}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    plain = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(days=req.days_valid)
    encrypted = encrypt_key(plain)
    owner = None
    if req.email:
        owner = db.query(User).filter(User.email == req.email).first()
        if not owner:
            owner = User(email=req.email, password_hash=hash_password(secrets.token_urlsafe(12)), is_admin=False)
            db.add(owner); db.commit(); db.refresh(owner)
    ak = AuthKey(key_encrypted=encrypted, status="active", expires_at=expires_at, owner_id=(owner.id if owner else None))
    db.add(ak)
    db.add(Log(action="generate", key_id=None, user_id=(owner.id if owner else None), ip=ip, user_agent=request.headers.get("user-agent","")))
    db.commit(); db.refresh(ak)
    if req.email_to_user and req.email:
        body = f"Your key: {plain}\\nExpires: {expires_at.isoformat()}"
        background.add_task(send_email, req.email, "Your Auth Key", body)
    return {"key": plain, "expires_at": expires_at.isoformat(), "id": ak.id}

# Validate key
@app.get("/validate")
def validate(key: str, request: Request, db=Depends(get_db)):
    ip = request.client.host
    ua = request.headers.get("user-agent","")
    # naive linear scan (small DB). For scale, store HMAC index.
    matched = None
    for ak in db.query(AuthKey).filter(AuthKey.status=="active").all():
        try:
            if secrets.compare_digest(decrypt_key(ak.key_encrypted), key):
                matched = ak; break
        except Exception:
            continue
    if not matched:
        db.add(Log(action="validate_fail", ip=ip, user_agent=ua))
        db.commit()
        raise HTTPException(status_code=404, detail="Key not found or inactive")
    if matched.expires_at and datetime.utcnow() > matched.expires_at:
        matched.status = "expired"; db.add(matched); db.commit()
        db.add(Log(action="validate_fail", key_id=matched.id, ip=ip, user_agent=ua, detail="expired")); db.commit()
        raise HTTPException(status_code=403, detail="Key expired")
    db.add(Log(action="validate_ok", key_id=matched.id, user_id=matched.owner_id, ip=ip, user_agent=ua)); db.commit()
    return {"message":"Key valid", "key_id": matched.id}

# Admin API endpoints
@app.get("/admin/keys")
def admin_list_keys(q: str = "", page: int = 1, per_page: int = 50, admin=Depends(get_current_admin), db=Depends(get_db)):
    query = db.query(AuthKey)
    if q:
        # search by decrypted key or owner email
        results = []
        for ak in query.order_by(AuthKey.created_at.desc()).all():
            try:
                plain = decrypt_key(ak.key_encrypted)
            except Exception:
                plain = ""
            owner = db.query(User).filter(User.id==ak.owner_id).first()
            owner_email = owner.email if owner else ""
            if q in plain or q in owner_email:
                results.append((ak, plain, owner_email))
        total = len(results)
        start = (page-1)*per_page; end = start+per_page
        page_items = results[start:end]
        out = [{"id": a.id, "key": p, "status": a.status, "expires_at": a.expires_at.isoformat() if a.expires_at else None, "owner": o} for (a,p,o) in page_items]
        return {"total": total, "items": out}
    total = query.count()
    items = query.order_by(AuthKey.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()
    out = []
    for a in items:
        try:
            plain = decrypt_key(a.key_encrypted)
        except Exception:
            plain = "<cannot-decrypt>"
        owner = db.query(User).filter(User.id==a.owner_id).first()
        out.append({"id": a.id, "key": plain, "status": a.status, "expires_at": a.expires_at.isoformat() if a.expires_at else None, "owner": owner.email if owner else None})
    return {"total": total, "items": out}

@app.delete("/admin/keys/{key_id}")
def admin_revoke_key(key_id: int, admin=Depends(get_current_admin), db=Depends(get_db)):
    ak = db.query(AuthKey).filter(AuthKey.id==key_id).first()
    if not ak:
        raise HTTPException(status_code=404)
    ak.status = "revoked"; db.add(ak)
    db.add(Log(action="revoke", key_id=ak.id, user_id=admin.id, ip=None, user_agent=None))
    db.commit()
    return {"msg":"revoked"}

@app.get("/admin/logs/download")
def admin_download_logs(admin=Depends(get_current_admin), db=Depends(get_db)):
    logs = db.query(Log).order_by(Log.timestamp.desc()).all()
    out = io.StringIO(); writer = csv.writer(out)
    writer.writerow(["id","action","key_id","user_id","ip","user_agent","timestamp","detail"])
    for l in logs:
        writer.writerow([l.id,l.action,l.key_id,l.user_id,l.ip,l.user_agent,l.timestamp.isoformat(), (l.detail or "")])
    out.seek(0)
    return StreamingResponse(io.BytesIO(out.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=logs.csv"})

# Admin 2FA setup helper
@app.post("/admin/2fa/setup")
def admin_2fa_setup(admin=Depends(get_current_admin), db=Depends(get_db)):
    secret = pyotp.random_base32()
    admin.twofa_secret = secret; db.add(admin); db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=admin.email, issuer_name="AuthKeyService")
    return {"secret": secret, "uri": uri}

# Simple health
@app.get("/health")
def health():
    return {"status":"ok"}