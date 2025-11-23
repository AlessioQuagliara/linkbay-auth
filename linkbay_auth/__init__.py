from .core import AuthCore
from .schemas import (
    UserCreate, UserLogin, Token, TokenData, 
    UserResponse, PasswordResetRequest, PasswordResetConfirm
)
from .dependencies import get_current_user, get_current_active_user
from .router import auth_router

__version__ = "0.1.0"
__all__ = [
    "AuthCore",
    "UserCreate",
    "UserLogin", 
    "Token",
    "TokenData",
    "UserResponse",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "get_current_user",
    "get_current_active_user",
    "auth_router"
]