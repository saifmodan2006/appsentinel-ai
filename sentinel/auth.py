import hashlib
import secrets
import time
from threading import BoundedSemaphore

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request
from sqlalchemy import delete, select, update

from sentinel.config import SESSION_TTL
from sentinel.db import engine, queue_lock, sessions, throttle, users

hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_urlsafe(32))
password_slots = BoundedSemaphore(4)


def password_hash(password):
    with password_slots:
        return hasher.hash(password)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def rate_limit(key, maximum, period):
    marker = digest(key)
    now = int(time.time())
    with engine.begin() as conn:
        queue_lock(conn)
        row = (
            conn.execute(select(throttle).where(throttle.c.key == marker))
            .mappings()
            .first()
        )
        if row is None:
            conn.execute(throttle.insert().values(key=marker, window=now, count=1))
        elif row["window"] + period <= now:
            conn.execute(
                update(throttle)
                .where(throttle.c.key == marker)
                .values(window=now, count=1)
            )
        elif row["count"] >= maximum:
            raise HTTPException(
                429,
                "Too many requests. Try again later.",
                headers={"Retry-After": str(period)},
            )
        else:
            conn.execute(
                update(throttle)
                .where(throttle.c.key == marker)
                .values(count=row["count"] + 1)
            )


def find_user(email, password):
    with engine.connect() as conn:
        row = (
            conn.execute(select(users).where(users.c.email == email)).mappings().first()
        )
    try:
        with password_slots:
            hasher.verify(row["password"] if row else dummy_hash, password)
    except VerifyMismatchError:
        return None
    if row and hasher.check_needs_rehash(row["password"]):
        with engine.begin() as conn:
            conn.execute(
                update(users)
                .where(users.c.id == row["id"], users.c.password == row["password"])
                .values(password=password_hash(password))
            )
    return row


def session_token(request):
    header = request.headers.get("authorization", "")
    if header.startswith("Bearer "):
        return header.removeprefix("Bearer ")
    return request.cookies.get("sentinel_session", "")


def create_session(owner, previous=""):
    token = secrets.token_urlsafe(32)
    with engine.begin() as conn:
        if previous:
            conn.execute(
                delete(sessions).where(
                    sessions.c.digest == digest(previous), sessions.c.owner == owner
                )
            )
        conn.execute(
            sessions.insert().values(
                digest=digest(token),
                owner=owner,
                expires=int(time.time()) + SESSION_TTL,
            )
        )
    return token


def current_user(request: Request):
    token = session_token(request)
    if not token or len(token) > 128:
        raise HTTPException(401, "Sign in to continue.")
    with engine.connect() as conn:
        row = (
            conn.execute(
                select(users.c.id, users.c.email, users.c.role)
                .join(sessions, sessions.c.owner == users.c.id)
                .where(
                    sessions.c.digest == digest(token),
                    sessions.c.expires > int(time.time()),
                )
            )
            .mappings()
            .first()
        )
    if row is None:
        raise HTTPException(401, "Session expired. Sign in again.")
    return dict(row)


def require_admin(user):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required.")
