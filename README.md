# LinkBay-Auth v0.2.0

[![License](https://img.shields.io/badge/license-MIT-blue)]() [![Python](https://img.shields.io/badge/python-3.8+-blue)]() [![Tests](https://img.shields.io/badge/tests-passing-green)]() [![Security](https://img.shields.io/badge/security-production--ready-brightgreen)]()

**Sistema di autenticazione JWT per FastAPI - Production-ready con sicurezza avanzata**

 **Production-Ready** - Protezione brute force, token blacklist, security logging  
 **Password Policy** - Policy configurabili con validazione avanzata  
 **Device Tracking** - Gestione sessioni multi-dispositivo  
 **Security Audit** - Log completo eventi di sicurezza  
 **Bcrypt nativo** - Usa `bcrypt>=4.0.0` direttamente

## Caratteristiche

###  Core
- **JWT** con access token e refresh token
- **Zero dipendenze DB** - Implementi tu i modelli
- **Completamente async** - Perfetto per FastAPI
- **Password hashing** con bcrypt nativo
- **Token revocation** - Singolo o tutti i dispositivi
- **Reset password** - Con token temporanei verificabili

### Sicurezza Avanzata (v0.2.0)
- **Protezione Brute Force** - Rate limiting configurabile
- **Token Blacklist** - Logout immediato access token
- **Password Policy** - Policy configurabili con validazione
- **Email Validation** - Validazione avanzata con check DNS
- **Security Logging** - Audit trail completo
- **Device Tracking** - Gestione sessioni multi-dispositivo
- **Pattern Detection** - Rilevamento password deboli

## Documentazione

- **[ Quick Start](QUICK_START.md)** - Setup in 5 minuti
- **[ Release Notes v0.2.0](RELEASE_NOTES_v0.2.0.md)** - Riepilogo completo release
- **[ Security Best Practices](SECURITY_BEST_PRACTICES.md)** - Guida produzione
- **[ Changelog v0.2.0](CHANGELOG_v0.2.0.md)** - Dettagli feature

## Installazione

```bash
pip install linkbay-auth==0.2.0
```
oppure
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

    async def create_user(self, email: str, hashed_password: str):
        user = User(email=email, hashed_password=hashed_password)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    async def update_user_password(self, email: str, hashed_password: str):
        user = await self.get_user_by_email(email)
        if user:
            user.hashed_password = hashed_password
            self.db.commit()
            self.db.refresh(user)
        return user

    async def save_refresh_token(self, user_id: int, token: str, expires_at: datetime):
        rt = RefreshToken(user_id=user_id, token=token, expires_at=expires_at, revoked=False)
        self.db.add(rt)
        self.db.commit()
        return rt

    async def get_refresh_token(self, token: str):
        return self.db.query(RefreshToken).filter(
            RefreshToken.token == token,
            RefreshToken.revoked == False
        ).first()

    async def revoke_refresh_token(self, token: str) -> bool:
        rt = self.db.query(RefreshToken).filter(RefreshToken.token == token).first()
        if rt:
            rt.revoked = True
            self.db.commit()
            return True
        return False

    async def revoke_all_user_tokens(self, user_id: int):
        self.db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False
        ).update({"revoked": True})
        self.db.commit()
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
from linkbay_auth import create_get_current_active_user

# Crea la dependency con il tuo auth_core
get_current_active_user = create_get_current_active_user(auth_core, create_get_current_user(auth_core))

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

### Modelli Base (v0.1.0)
**User**: `id`, `email`, `hashed_password`, `is_active`

**RefreshToken**: `id`, `user_id`, `token`, `expires_at`, `revoked`

### Modelli Avanzati (v0.2.0 - Opzionali)
**RefreshToken** (con device tracking):
- `user_agent`, `ip_address`, `device_name`

**SecurityLog** (audit trail):
- `id`, `event_type`, `user_id`, `email`, `ip_address`, `user_agent`, `details`, `timestamp`

**LoginAttempt** (brute force protection):
- `id`, `email`, `ip_address`, `success`, `timestamp`

Vedi `example_production.py` per implementazione completa.

## Note Tecniche

### Core
- **Bcrypt Nativo**: Usa direttamente `bcrypt>=4.0.0` (no passlib) per massima compatibilità
- **Password Sicure**: Gestisce automaticamente password lunghe (bcrypt ha limite 72 byte)
- **Async Support**: Tutti i metodi del `UserServiceProtocol` sono async
- **Token Expiry**: Access token default 15 min, Refresh token default 30 giorni
- **Sicurezza**: Hash bcrypt con salt automatico, JWT firmati con HS256
- **Error Handling**: Gestione robusta degli errori di hashing/verifica

### Sicurezza Avanzata (v0.2.0)
- **Token Blacklist**: In-memory (dev) / Redis (production) per logout immediato
- **Rate Limiting**: Configurabile, default 5 tentativi in 15 minuti
- **Account Lockout**: Blocco temporaneo dopo tentativi falliti (default 30 min)
- **Password Policy**: Min 8 caratteri, uppercase/lowercase/numbers configurabili
- **Email Validation**: RFC 5322 compliant con check DNS opzionale
- **Security Events**: 8 tipi di eventi tracciati automaticamente
- **Device Tracking**: User agent, IP, device name nei refresh token
- **Testato**: Test suite completa + esempio production-ready

## Testing

Esegui i test per verificare il funzionamento:

```bash
python3 test_basic.py
```

Tutti i test devono passare con ✅ (12/12 test)

## File Utili

- `test_basic.py` - Test suite completa (12 test)
- `example_integration.py` - Esempio base con SQLAlchemy
- `example_production.py` - **✨ Nuovo**: Implementazione production-ready con tutte le feature
- `CHANGELOG.md` - Storia delle modifiche v0.1.0
- `CHANGELOG_v0.2.0.md` - **✨ Nuovo**: Dettagli release v0.2.0
- `security_utils.py` - **✨ Nuovo**: Utility di sicurezza avanzate
- `README.md` - Questa documentazione

## Troubleshooting

### Errore bcrypt/passlib
Se vedi errori come `AttributeError: module 'bcrypt' has no attribute '__about__'`:
- ✅ **Risolto**: La libreria usa ora `bcrypt>=4.0.0` direttamente (no passlib)
- Reinstalla: `pip install -e . --force-reinstall`

### Password troppo lunghe
- ✅ **Risolto**: Gestione automatica del limite 72 byte di bcrypt
- Le password vengono gestite correttamente senza errori

### Import Error email-validator
Se vedi `ImportError: email-validator is not installed`:
- ✅ **Risolto**: Dipendenza inclusa in `pydantic[email]`
- Reinstalla: `pip install -e .`

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