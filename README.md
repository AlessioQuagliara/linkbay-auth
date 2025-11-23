# LinkBay-Auth Beta 1.0.0

[![License](https://img.shields.io/badge/license-MIT-blue)]()

**Sistema di autenticazione JWT per FastAPI - Zero dipendenze DB, puramente logica**

## Caratteristiche

- **JWT** con access token e refresh token
- **Zero dipendenze DB** - Implementi tu i modelli
- **Completamente async** - Perfetto per FastAPI
- **Password hashing** con bcrypt
- **Token revocation** - Singolo o tutti i dispositivi
- **Reset password** - Con token temporanei
- **Protocollo pulito** - UserServiceProtocol da implementare

## Installazione

```bash
pip install git+https://github.com/AlessioQuagliara/linkbay_auth.git
```

## Utilizzo Rapido

### 1. Implementa UserServiceProtocol

```python
from linkbay_auth import UserServiceProtocol
from datetime import datetime

class MyUserService(UserServiceProtocol):
    def __init__(self, db_session):
        self.db = db_session

    async def get_user_by_email(self, email: str):
        # Tua implementazione con i TUOI modelli
        return await self.db.query(User).filter(User.email == email).first()

    async def get_user_by_id(self, user_id: int):
        return await self.db.query(User).filter(User.id == user_id).first()

    # ... implementa tutti i metodi del Protocol
```

### 2. Configura nel tuo FastAPI

```python
from fastapi import FastAPI
from linkbay_auth import AuthCore, create_auth_router

app = FastAPI()

# Configurazione
user_service = MyUserService(db_session)
auth_core = AuthCore(
    user_service=user_service,
    secret_key="tuo-secret-key",
    access_token_expire_minutes=15,
    refresh_token_expire_days=30
)

# Aggiungi le route di autenticazione
auth_router = create_auth_router(auth_core)
app.include_router(auth_router)
```

### 3. Proteggi gli endpoint

```python
from linkbay_auth import get_current_active_user

@app.get("/protected")
async def protected_route(current_user = Depends(get_current_active_user)):
    return {"message": f"Ciao {current_user.email}"}
```

## Endpoints Disponibili

- `POST /auth/register` - Registrazione
- `POST /auth/login` - Login
- `POST /auth/refresh` - Rinnova access token
- `POST /auth/logout` - Logout
- `POST /auth/logout-all` - Logout da tutti i dispositivi
- `GET /auth/me` - Informazioni utente corrente
- `POST /auth/password-reset-request` - Richiedi reset password
- `POST /auth/password-reset-confirm` - Conferma reset password

## Requisiti Modelli

I tuoi modelli devono avere questi campi minimi:

**User**: `id`, `email`, `hashed_password`

**RefreshToken**: `id`, `user_id`, `token`, `expires_at`, `revoked`

## Licenza
```
MIT - Vedere LICENSE per dettagli.
```

## INSTALLAZIONE

```python
from fastapi import FastAPI, Depends
from linkbay_auth import AuthCore, create_auth_router, get_current_active_user

app = FastAPI()

# Configurazione (nel tuo main.py)
user_service = MyUserService()  # La tua implementazione
auth_core = AuthCore(
    user_service=user_service,
    secret_key="your-secret-key-here"
)

app.include_router(create_auth_router(auth_core))

@app.get("/protected")
async def protected_route(user = Depends(get_current_active_user)):
    return {"message": "Accesso consentito"}
```