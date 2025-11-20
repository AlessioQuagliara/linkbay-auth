from typing import Protocol, Optional, Any
from datetime import datetime

class UserServiceProtocol(Protocol):
    """Interfaccia che l'app madre deve implementare per gestire utenti e token"""
    
    def get_user_by_email(self, email: str) -> Optional[Any]:
        """Ritorna utente per email o None"""
        ...
    
    def get_user_by_id(self, user_id: int) -> Optional[Any]:
        """Ritorna utente per ID o None"""
        ...
    
    def create_user(self, email: str, hashed_password: str) -> Any:
        """Crea nuovo utente e ritorna l'oggetto creato"""
        ...
    
    def update_user_password(self, email: str, hashed_password: str) -> Optional[Any]:
        """Aggiorna password utente, ritorna utente aggiornato o None"""
        ...
    
    def save_refresh_token(self, user_id: int, token: str, expires_at: datetime) -> Any:
        """Salva refresh token e ritorna l'oggetto creato"""
        ...
    
    def get_refresh_token(self, token: str) -> Optional[Any]:
        """Ritorna refresh token non revocato o None"""
        ...
    
    def revoke_refresh_token(self, token: str) -> bool:
        """Revoca un refresh token, ritorna True se successo"""
        ...
    
    def revoke_all_user_tokens(self, user_id: int) -> None:
        """Revoca tutti i refresh token di un utente"""
        ...
