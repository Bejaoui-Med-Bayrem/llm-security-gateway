from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher

from app.core.config import settings


password_hasher = PasswordHasher()

# Verified against when the email is unknown, so a login for a
# non-existent account costs the same Argon2 work as a wrong password
# and response timing does not reveal which emails are registered.
DUMMY_PASSWORD_HASH = password_hasher.hash("timing-equalizer")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        password_hasher.verify(password_hash, password)
        return True
    except Exception:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )