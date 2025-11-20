# security.py
from datetime import datetime, timedelta
from typing import Optional
import secrets

from jose import jwt, JWTError
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(
    data: dict,
    secret_key: str,
    algorithm: str = "HS256",
    expires_minutes: int = 15,
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt

def create_refresh_token(
    user_id: int,
    secret_key: str,
    algorithm: str = "HS256",
    expires_days: int = 30,
) -> tuple[str, datetime]:
    jti = secrets.token_urlsafe(32)
    expire = datetime.utcnow() + timedelta(days=expires_days)
    
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "jti": jti,
        "type": "refresh"
    }
    
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt, expire

def decode_access_token(
    token: str,
    secret_key: str,
    algorithms: list[str] = ["HS256"],
) -> dict:
    return jwt.decode(token, secret_key, algorithms=algorithms)

def create_password_reset_token(email: str, secret_key: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode = {
        "sub": email,
        "exp": expire,
        "type": "password_reset"
    }
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
    return encoded_jwt

def verify_password_reset_token(token: str, secret_key: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        if payload.get("type") != "password_reset":
            return None
        return payload.get("sub")
    except JWTError:
        return None