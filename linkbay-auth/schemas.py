# schemas.py
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password deve essere di almeno 8 caratteri"
    )
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Valida che la password contenga almeno una maiuscola, una minuscola e un numero"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('La password deve contenere almeno una lettera maiuscola')
        if not re.search(r'[a-z]', v):
            raise ValueError('La password deve contenere almeno una lettera minuscola')
        if not re.search(r'\d', v):
            raise ValueError('La password deve contenere almeno un numero')
        return v

class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True

class PasswordResetRequest(BaseModel):
    email: EmailStr = Field(..., description="Email dell'account da recuperare")

class PasswordResetConfirm(BaseModel):
    token: str = Field(..., description="Token di reset ricevuto via email")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Nuova password (min 8 caratteri)"
    )
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Valida che la password contenga almeno una maiuscola, una minuscola e un numero"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('La password deve contenere almeno una lettera maiuscola')
        if not re.search(r'[a-z]', v):
            raise ValueError('La password deve contenere almeno una lettera minuscola')
        if not re.search(r'\d', v):
            raise ValueError('La password deve contenere almeno un numero')
        return v

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token per ottenere un nuovo access token")