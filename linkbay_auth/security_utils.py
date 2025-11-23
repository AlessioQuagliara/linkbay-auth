"""Utility per sicurezza avanzata"""
from email_validator import validate_email, EmailNotValidError
from fastapi import HTTPException, Request
from typing import Optional
import hashlib


def validate_email_advanced(email: str, check_deliverability: bool = False) -> str:
    """
    Validazione email avanzata con controllo dominio opzionale
    
    Args:
        email: Email da validare
        check_deliverability: Se True, verifica esistenza dominio (richiede DNS lookup)
    
    Returns:
        Email normalizzata
        
    Raises:
        HTTPException: Se email non valida
    """
    try:
        valid = validate_email(email, check_deliverability=check_deliverability)
        return valid.email
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=f"Email non valida: {str(e)}")


def get_client_info(request: Request) -> dict:
    """
    Estrae informazioni sul client dalla request
    
    Returns:
        Dict con user_agent, ip_address, forwarded_for
    """
    return {
        "user_agent": request.headers.get("user-agent"),
        "ip_address": request.client.host if request.client else None,
        "forwarded_for": request.headers.get("x-forwarded-for"),
    }


def hash_token_for_storage(token: str) -> str:
    """
    Hash di un token per storage sicuro (es. per blacklist)
    Usa SHA-256 per evitare di salvare token in chiaro
    
    Args:
        token: JWT token
        
    Returns:
        Hash SHA-256 del token
    """
    return hashlib.sha256(token.encode()).hexdigest()


class RateLimitConfig:
    """Configurazione rate limiting"""
    def __init__(
        self,
        max_login_attempts: int = 5,
        login_window_minutes: int = 15,
        max_password_reset_requests: int = 3,
        password_reset_window_minutes: int = 60,
        account_lockout_minutes: int = 30
    ):
        self.max_login_attempts = max_login_attempts
        self.login_window_minutes = login_window_minutes
        self.max_password_reset_requests = max_password_reset_requests
        self.password_reset_window_minutes = password_reset_window_minutes
        self.account_lockout_minutes = account_lockout_minutes


def detect_suspicious_patterns(password: str) -> Optional[str]:
    """
    Rileva pattern sospetti nelle password
    
    Returns:
        Warning message se trovato pattern sospetto, None altrimenti
    """
    # Sequenze comuni
    sequences = ['12345', '23456', '34567', 'abcde', 'bcdef']
    for seq in sequences:
        if seq in password.lower():
            return f"Password contiene sequenza comune: {seq}"
    
    # Ripetizioni eccessive
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return f"Password contiene carattere ripetuto troppe volte: {password[i]}"
    
    return None
