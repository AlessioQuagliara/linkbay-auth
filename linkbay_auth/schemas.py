from pydantic import BaseModel, EmailStr
from typing import Optional, Protocol
from datetime import datetime

# Protocol per l'interfaccia del servizio utente
class UserServiceProtocol(Protocol):
    async def get_user_by_email(self, email: str): ...
    async def get_user_by_id(self, user_id: int): ...
    async def create_user(self, email: str, hashed_password: str): ...
    async def update_user_password(self, email: str, hashed_password: str): ...
    async def save_refresh_token(self, user_id: int, token: str, expires_at: datetime): ...
    async def get_refresh_token(self, token: str): ...
    async def revoke_refresh_token(self, token: str) -> bool: ...
    async def revoke_all_user_tokens(self, user_id: int): ...

# Schemi Pydantic
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str