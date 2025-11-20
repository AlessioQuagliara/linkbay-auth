# LinkBay-Auth

Libreria di autenticazione per LinkBayCMS.

Fornisce JWT auth, refresh tokens, password recovery e validazione robusta senza imporre modelli DB.

## Installazione

```bash
pip install -e .
```

## How to Use

### 1. Implementa UserService

```python
from linkbay_auth import UserServiceProtocol
from datetime import datetime

class MyUserService:
    def __init__(self, db_session):
        self.db = db_session
    
    def get_user_by_email(self, email: str):
        return self.db.query(User).filter(User.email == email).first()
    
    def get_user_by_id(self, user_id: int):
        return self.db.query(User).filter(User.id == user_id).first()
    
    def create_user(self, email: str, hashed_password: str):
        user = User(email=email, hashed_password=hashed_password)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def update_user_password(self, email: str, hashed_password: str):
        user = self.get_user_by_email(email)
        if user:
            user.hashed_password = hashed_password
            self.db.commit()
            self.db.refresh(user)
        return user
    
    def save_refresh_token(self, user_id: int, token: str, expires_at: datetime):
        rt = RefreshToken(user_id=user_id, token=token, expires_at=expires_at)
        self.db.add(rt)
        self.db.commit()
        return rt
    
    def get_refresh_token(self, token: str):
        return self.db.query(RefreshToken).filter(
            RefreshToken.token == token,
            RefreshToken.revoked == 0
        ).first()
    
    def revoke_refresh_token(self, token: str) -> bool:
        rt = self.db.query(RefreshToken).filter(RefreshToken.token == token).first()
        if rt:
            rt.revoked = 1
            self.db.commit()
            return True
        return False
    
    def revoke_all_user_tokens(self, user_id: int):
        self.db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == 0
        ).update({"revoked": 1})
        self.db.commit()
```

### 2. Configura il Plugin

```python
from linkbay_auth import LinkBayAuthPlugin, AuthConfig

user_service = MyUserService(db_session)

config = AuthConfig(
    user_service=user_service,
    secret_key="your-secret-key",
    access_token_minutes=15,
    refresh_token_days=30
)

LinkBayAuthPlugin.install(app, config)
```

### 3. Requisiti Minimi

Il tuo `UserService` deve implementare tutti i metodi di `UserServiceProtocol`.

I tuoi modelli devono avere questi campi minimi:

**User**: `id`, `email`, `hashed_password`

**RefreshToken**: `id`, `user_id`, `token`, `expires_at`, `revoked`

### 4. API Endpoints

Tutti gli endpoint sono sotto `/auth`:

- `POST /register` - Registrazione
- `POST /login` - Login con access + refresh token
- `POST /refresh` - Rinnova access token
- `POST /logout` - Revoca refresh token
- `POST /logout-all` - Revoca tutti i token utente
- `GET /me` - Info utente autenticato
- `POST /password-reset-request` - Richiedi reset password
- `POST /password-reset-confirm` - Conferma reset con token

### 5. Funzioni Utilità

```python
from linkbay_auth import hash_password, verify_password, create_access_token

# Hash password
hashed = hash_password("mypassword")

# Verifica password
valid = verify_password("mypassword", hashed)

# Crea token custom
token = create_access_token({"sub": "user@example.com"}, "secret", 15)
```

## Features

- ✅ **Zero dipendenze DB** - Nessun ORM imposto (SQLAlchemy, Django ORM, raw SQL, qualsiasi cosa)
- ✅ **Puramente logica** - Implementi il `UserServiceProtocol`, la libreria gestisce solo auth
- ✅ **JWT** con access (15min) e refresh tokens (30 giorni)
- ✅ **Password validation** - min 8 char, 1 maiuscola, 1 minuscola, 1 numero
- ✅ **Password recovery** con token temporanei (1 ora)
- ✅ **Token revocation** - singolo o tutti i dispositivi
- ✅ **Controllo totale** - L'app madre gestisce modelli, migrazioni, campi aggiuntivi
