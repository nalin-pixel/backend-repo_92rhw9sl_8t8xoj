import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import jwt
import bcrypt

from database import db, create_document, get_documents
from bson import ObjectId

# ---------- App & CORS ----------
app = FastAPI(title="Wedding Website API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Auth Helpers ----------
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")
JWT_ALG = "HS256"

ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
GUEST_PASSWORD_HASH = os.getenv("GUEST_PASSWORD_HASH")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
GUEST_PASSWORD = os.getenv("GUEST_PASSWORD")

security = HTTPBearer(auto_error=False)


def verify_password(input_password: str, role: str) -> bool:
    # Prefer bcrypt hashes if provided
    if role == "admin":
        if ADMIN_PASSWORD_HASH:
            try:
                return bcrypt.checkpw(input_password.encode(), ADMIN_PASSWORD_HASH.encode())
            except Exception:
                return False
        if ADMIN_PASSWORD:
            return input_password == ADMIN_PASSWORD
    if role == "guest":
        if GUEST_PASSWORD_HASH:
            try:
                return bcrypt.checkpw(input_password.encode(), GUEST_PASSWORD_HASH.encode())
            except Exception:
                return False
        if GUEST_PASSWORD:
            return input_password == GUEST_PASSWORD
    return False


def passwords_configured() -> bool:
    return any([ADMIN_PASSWORD_HASH, GUEST_PASSWORD_HASH, ADMIN_PASSWORD, GUEST_PASSWORD])


def create_token(role: str) -> str:
    payload = {
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_role(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    if not creds:
        return "guest"
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("role", "guest")
    except Exception:
        return "guest"


def require_admin(role: str = Depends(get_role)):
    if role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")


# ---------- Models ----------
class LoginRequest(BaseModel):
    password: str

class LoginResponse(BaseModel):
    token: str
    role: str

class RSVPModel(BaseModel):
    email: EmailStr
    name: str
    attending: bool
    guests: int = Field(0, ge=0, le=10)
    dietary: Optional[str] = None
    message: Optional[str] = None

class GiftClaimRequest(BaseModel):
    name: str
    note: Optional[str] = None
    action: str = Field("claim", pattern="^(claim|unclaim)$")

class MessageModel(BaseModel):
    name: str
    text: str = Field(..., min_length=1, max_length=500)
    public: bool = True

class PhotoModel(BaseModel):
    url: str
    caption: Optional[str] = None

class TimelineEventModel(BaseModel):
    title: str
    time: str
    location: Optional[str] = None
    description: Optional[str] = None
    order: int = 0


# ---------- Utils ----------

def oid(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    return obj


def serialize(doc):
    if not doc:
        return doc
    d = {k: oid(v) for k, v in doc.items()}
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


# ---------- Routes ----------
@app.get("/")
def read_root():
    return {"message": "Wedding API running"}


@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    # Require a valid password; do not allow empty config bypass
    if verify_password(payload.password, "admin"):
        return LoginResponse(token=create_token("admin"), role="admin")
    if verify_password(payload.password, "guest"):
        return LoginResponse(token=create_token("guest"), role="guest")
    # If no passwords configured at all, deny to enforce lock by default
    if not passwords_configured():
        raise HTTPException(status_code=403, detail="Password not configured. Please set ADMIN_PASSWORD or GUEST_PASSWORD.")
    raise HTTPException(status_code=401, detail="Invalid password")


# ----- RSVP -----
@app.get("/api/rsvp")
def get_rsvp(email: EmailStr):
    doc = db["rsvp"].find_one({"email": email})
    return serialize(doc) if doc else None


@app.post("/api/rsvp")
def save_rsvp(rsvp: RSVPModel):
    existing = db["rsvp"].find_one({"email": rsvp.email})
    data = rsvp.model_dump()
    data["updated_at"] = datetime.now(timezone.utc)
    if existing:
        db["rsvp"].update_one({"_id": existing["_id"]}, {"$set": data})
        return {"status": "updated", "id": str(existing["_id"])}
    else:
        new_id = create_document("rsvp", data)
        return {"status": "created", "id": new_id}


# ----- Timeline -----
@app.get("/api/timeline")
def get_timeline():
    items = list(db["timelineevent"].find().sort("order"))
    return [serialize(i) for i in items]


@app.post("/api/timeline")
def add_timeline(event: TimelineEventModel, _: None = Depends(require_admin)):
    eid = create_document("timelineevent", event.model_dump())
    return {"id": eid}


@app.put("/api/timeline/{event_id}")
def update_timeline(event_id: str, event: TimelineEventModel, _: None = Depends(require_admin)):
    try:
        _id = ObjectId(event_id)
    except Exception:
        raise HTTPException(400, "Invalid id")
    db["timelineevent"].update_one({"_id": _id}, {"$set": event.model_dump()})
    return {"status": "ok"}


@app.delete("/api/timeline/{event_id}")
def delete_timeline(event_id: str, _: None = Depends(require_admin)):
    try:
        _id = ObjectId(event_id)
    except Exception:
        raise HTTPException(400, "Invalid id")
    db["timelineevent"].delete_one({"_id": _id})
    return {"status": "ok"}


# ----- Gifts -----
@app.get("/api/gifts")
def get_gifts():
    items = list(db["gift"].find().sort("title"))
    return [serialize(i) for i in items]


@app.post("/api/gifts/{gift_id}/claim")
def claim_gift(gift_id: str, payload: GiftClaimRequest):
    try:
        _id = ObjectId(gift_id)
    except Exception:
        raise HTTPException(400, "Invalid id")
    gift = db["gift"].find_one({"_id": _id})
    if not gift:
        raise HTTPException(404, "Gift not found")
    if payload.action == "claim":
        db["gift"].update_one({"_id": _id}, {"$set": {"claimed_by": payload.name, "claim_note": payload.note, "claimed_at": datetime.now(timezone.utc)}})
    else:
        db["gift"].update_one({"_id": _id}, {"$unset": {"claimed_by": "", "claim_note": "", "claimed_at": ""}})
    updated = db["gift"].find_one({"_id": _id})
    return serialize(updated)


# ----- Messages -----
@app.get("/api/messages")
def get_messages(public: bool = True):
    filt = {"public": public} if public else {}
    items = list(db["message"].find(filt).sort("created_at", -1))
    return [serialize(i) for i in items]


@app.post("/api/messages")
def post_message(msg: MessageModel):
    mid = create_document("message", msg.model_dump())
    return {"id": mid}


# ----- Photos -----
@app.get("/api/photos")
def get_photos():
    items = list(db["photo"].find().sort("created_at", -1))
    return [serialize(i) for i in items]


@app.post("/api/photos")
def add_photo(photo: PhotoModel, role: str = Depends(get_role)):
    if role not in ("admin",):
        raise HTTPException(403, "Only admin can upload currently")
    pid = create_document("photo", photo.model_dump())
    return {"id": pid}


# ----- Admin -----
@app.get("/api/admin/rsvps")
def admin_rsvps(_: None = Depends(require_admin)):
    items = list(db["rsvp"].find().sort("updated_at", -1))
    return [serialize(i) for i in items]


@app.get("/api/admin/stats")
def admin_stats(_: None = Depends(require_admin)):
    total_rsvps = db["rsvp"].count_documents({})
    attending = db["rsvp"].count_documents({"attending": True})
    gifts_total = db["gift"].count_documents({})
    gifts_claimed = db["gift"].count_documents({"claimed_by": {"$exists": True}})
    messages_public = db["message"].count_documents({"public": True})
    return {
        "rsvps": {"total": total_rsvps, "attending": attending},
        "gifts": {"total": gifts_total, "claimed": gifts_claimed},
        "messages": {"public": messages_public},
    }


# ---------- Seed Data ----------
SAMPLE_GIFTS = [
    "WMF Knife Block Set",
    "Jean&Len Bath Towel",
    "Shower Curtain",
    "4 Seasons Duvet 155x220",
    "Salad Bowl Set",
    "Bedding Set",
    "Platypus Spatula",
    "Philips Hair Clipper",
]

SAMPLE_TIMELINE = [
    {"title": "Ceremony", "time": "12:00", "location": "Main Hall", "description": "Join us for the vows", "order": 1},
    {"title": "Cocktails", "time": "13:30", "location": "Garden Terrace", "description": "Drinks & canapés", "order": 2},
    {"title": "Reception", "time": "15:00", "location": "Ballroom", "description": "Dinner & speeches", "order": 3},
    {"title": "Dance", "time": "16:30", "location": "Ballroom", "description": "First dance & party", "order": 4},
]


def seed_collections():
    if db is None:
        return
    # Gifts
    if db["gift"].count_documents({}) == 0:
        for title in SAMPLE_GIFTS:
            create_document("gift", {"title": title})
    # Timeline
    if db["timelineevent"].count_documents({}) == 0:
        for ev in SAMPLE_TIMELINE:
            create_document("timelineevent", ev)


seed_collections()


# ---------- Diagnostics ----------
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
