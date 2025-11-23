from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, Protocol, List
from datetime import datetime
import re

# Password Policy configurabile
class PasswordPolicy(BaseModel):
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = False
    blacklist: List[str] = ["password", "123456", "qwerty", "admin"]
    
    def validate(self, password: str) -> tuple[bool, Optional[str]]:
        """Valida password contro policy, ritorna (is_valid, error_message)"""
        if len(password) < self.min_length:
            return False, f"Password deve essere almeno {self.min_length} caratteri"
        
        if len(password) > self.max_length:
            return False, f"Password non può superare {self.max_length} caratteri"
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password deve contenere almeno una maiuscola"
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password deve contenere almeno una minuscola"
        
        if self.require_numbers and not re.search(r'\d', password):
            return False, "Password deve contenere almeno un numero"
        
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password deve contenere almeno un carattere speciale"
        
        # Check blacklist
        password_lower = password.lower()
        for banned in self.blacklist:
            if banned.lower() in password_lower:
                return False, f"Password contiene termine non permesso: {banned}"
        
        return True, None

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
    async def log_security_event(self, event_type: str, user_id: int, details: dict): ...
    async def check_login_attempts(self, email: str) -> bool: ...
    async def record_failed_login(self, email: str): ...
    async def reset_failed_logins(self, email: str): ...

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

class DeviceInfo(BaseModel):
    """Info sul dispositivo per tracking sessioni"""
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    device_name: Optional[str] = None
    device_type: Optional[str] = None  # mobile, desktop, tablet

class SecurityEvent(BaseModel):
    """Evento di sicurezza per logging"""
    event_type: str  # LOGIN_SUCCESS, LOGIN_FAILED, PASSWORD_RESET, etc.
    user_id: Optional[int] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[dict] = None
    timestamp: datetime = datetime.utcnow()