# Changelog

Tutte le modifiche importanti a questo progetto saranno documentate in questo file.

## [0.1.0] - 2025-11-23

### 🎉 Release Iniziale

### ✅ Fixed
- **Bcrypt Compatibility**: Rimosso `passlib`, ora usa `bcrypt>=4.0.0` direttamente
- **Password Handling**: Gestione robusta del limite 72 byte di bcrypt
- **Error Handling**: Try-catch su hash/verify con gestione errori pulita
- **Email Validator**: Aggiunta dipendenza `pydantic[email]` per EmailStr

### ✨ Added
- Sistema completo di autenticazione JWT per FastAPI
- Support per access token (15min) e refresh token (30 giorni)
- 8 endpoint REST: register, login, refresh, logout, logout-all, me, password-reset
- `UserServiceProtocol` per disaccoppiamento totale dal DB
- Dependencies factory: `create_get_current_user` e `create_get_current_active_user`
- Test suite completa (`test_basic.py`) con 12 test
- Esempio di integrazione (`example_integration.py`) con SQLAlchemy
- Documentazione completa nel README
- Sezione Troubleshooting per problemi comuni

### 🏗️ Architecture
- Zero dipendenze DB - funziona con qualsiasi ORM
- Completamente async
- 384 linee di codice - semplice e mantenibile
- Type-safe con Pydantic v2

### 📦 Dependencies
- `fastapi>=0.100.0`
- `python-jose[cryptography]>=3.3.0`
- `bcrypt>=4.0.0`
- `python-multipart>=0.0.6`
- `pydantic[email]>=2.0.0`

### 🧪 Testing
- 12 test unitari
- 100% success rate
- Test per password lunghe (>72 byte)
- Test per token revocation
- Test per autenticazione completa
