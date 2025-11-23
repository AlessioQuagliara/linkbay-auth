from .core import AuthCore
from .schemas import (
    UserCreate, UserLogin, Token, TokenData, 
    UserResponse, PasswordResetRequest, PasswordResetConfirm,
    UserServiceProtocol, PasswordPolicy, DeviceInfo, SecurityEvent
)
from .dependencies import get_current_user, get_current_active_user
from .router import create_auth_router
from .security_utils import (
    validate_email_advanced, get_client_info, 
    hash_token_for_storage, RateLimitConfig, detect_suspicious_patterns
)

__version__ = "0.2.0"
__all__ = [
    "AuthCore",
    "UserCreate",
    "UserLogin", 
    "Token",
    "TokenData",
    "UserResponse",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "UserServiceProtocol",
    "PasswordPolicy",
    "DeviceInfo",
    "SecurityEvent",
    "validate_email_advanced",
    "get_client_info",
    "hash_token_for_storage",
    "RateLimitConfig",
    "detect_suspicious_patterns",
    "get_current_user",
    "get_current_active_user",
    "create_auth_router"
]