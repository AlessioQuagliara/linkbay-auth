from datetime import datetime, timedelta
from typing import Optional, Set
from jose import JWTError, jwt
import bcrypt
from .schemas import UserServiceProtocol, TokenData, PasswordPolicy

class AuthCore:
    def __init__(
        self,
        user_service: UserServiceProtocol,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 30,
        password_policy: Optional[PasswordPolicy] = None,
        enable_token_blacklist: bool = False
    ):
        self.user_service = user_service
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.password_policy = password_policy or PasswordPolicy()
        self.enable_token_blacklist = enable_token_blacklist
        # In-memory blacklist (in produzione usare Redis)
        self._token_blacklist: Set[str] = set()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verifica password con bcrypt - gestisce automaticamente il limite 72 byte"""
        try:
            # Converti in bytes se necessario
            if isinstance(plain_password, str):
                plain_password = plain_password.encode('utf-8')
            if isinstance(hashed_password, str):
                hashed_password = hashed_password.encode('utf-8')
            
            return bcrypt.checkpw(plain_password, hashed_password)
        except Exception as e:
            # Log error se necessario
            return False

    def get_password_hash(self, password: str) -> str:
        """Hash della password con bcrypt - gestisce automaticamente il limite 72 byte"""
        try:
            # Converti in bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Bcrypt gestisce automaticamente il limite 72 byte
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password, salt)
            
            # Ritorna come stringa
            return hashed.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Errore durante l'hashing della password: {str(e)}")

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, user_id: int) -> str:
        expires_delta = timedelta(days=self.refresh_token_expire_days)
        refresh_token = self.create_access_token(
            {"sub": str(user_id), "type": "refresh"}, expires_delta
        )
        return refresh_token

    async def verify_token(self, token: str) -> Optional[TokenData]:
        # Controlla blacklist
        if self.is_token_blacklisted(token):
            return None
            
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id: str = payload.get("sub")
            token_type: str = payload.get("type", "access")
            
            if user_id is None or token_type != "access":
                return None
                
            return TokenData(user_id=int(user_id))
        except JWTError:
            return None

    def validate_password_strength(self, password: str) -> tuple[bool, Optional[str]]:
        """Valida forza password usando policy configurata"""
        return self.password_policy.validate(password)
    
    def blacklist_token(self, token: str):
        """Aggiungi token alla blacklist (per logout immediato)"""
        if self.enable_token_blacklist:
            self._token_blacklist.add(token)
    
    def is_token_blacklisted(self, token: str) -> bool:
        """Verifica se token è in blacklist"""
        if not self.enable_token_blacklist:
            return False
        return token in self._token_blacklist
    
    def create_password_reset_token(self, email: str, expires_hours: int = 1) -> str:
        """Crea token per reset password con expiry verificabile"""
        expires_delta = timedelta(hours=expires_hours)
        reset_token = self.create_access_token(
            {"sub": email, "type": "password_reset"}, 
            expires_delta
        )
        return reset_token
    
    def verify_password_reset_token(self, token: str) -> Optional[str]:
        """Verifica token reset password e ritorna email se valido"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            email: str = payload.get("sub")
            token_type: str = payload.get("type")
            
            if email is None or token_type != "password_reset":
                return None
                
            return email
        except JWTError:
            return None

    async def authenticate_user(self, email: str, password: str):
        user = await self.user_service.get_user_by_email(email)
        if not user:
            return False
        if not self.verify_password(password, user.hashed_password):
            return False
        return user