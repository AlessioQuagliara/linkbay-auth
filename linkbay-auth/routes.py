# routes.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
from datetime import datetime

from . import schemas, security
from .plugin import AuthConfig

def get_auth_router(config: AuthConfig) -> APIRouter:
    router = APIRouter(tags=["Authentication"])
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
    
    def get_current_user(token: str = Depends(oauth2_scheme)):
        try:
            payload = security.decode_access_token(token, config.secret_key)
            email = payload.get("sub")
            if not email or payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Token non valido")
        except JWTError:
            raise HTTPException(status_code=401, detail="Token non valido")
        
        user = config.user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail="Utente non trovato")
        return user

    @router.post("/register", response_model=schemas.UserRead, status_code=201)
    def register(user_in: schemas.UserCreate):
        if config.user_service.get_user_by_email(user_in.email):
            raise HTTPException(status_code=400, detail="Email già registrata")
        
        hashed_password = security.hash_password(user_in.password)
        return config.user_service.create_user(user_in.email, hashed_password)

    @router.post("/login", response_model=schemas.Token)
    def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = config.user_service.get_user_by_email(form_data.username)
        if not user or not security.verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Email o password non corretti")
        
        access_token = security.create_access_token(
            data={"sub": user.email},
            secret_key=config.secret_key,
            expires_minutes=config.access_token_minutes
        )
        
        refresh_token, expires_at = security.create_refresh_token(
            user_id=user.id,
            secret_key=config.secret_key,
            expires_days=config.refresh_token_days
        )
        
        config.user_service.save_refresh_token(user.id, refresh_token, expires_at)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    @router.post("/refresh", response_model=schemas.Token)
    def refresh_token(refresh_request: schemas.RefreshTokenRequest):
        try:
            payload = security.decode_access_token(refresh_request.refresh_token, config.secret_key)
            if payload.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Token non valido")
            user_id = int(payload.get("sub"))
        except (JWTError, ValueError):
            raise HTTPException(status_code=401, detail="Token non valido")
        
        db_token = config.user_service.get_refresh_token(refresh_request.refresh_token)
        if not db_token or db_token.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token scaduto o revocato")
        
        user = config.user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="Utente non trovato")
        
        config.user_service.revoke_refresh_token(refresh_request.refresh_token)
        
        new_access_token = security.create_access_token(
            data={"sub": user.email},
            secret_key=config.secret_key,
            expires_minutes=config.access_token_minutes
        )
        
        new_refresh_token, expires_at = security.create_refresh_token(
            user_id=user.id,
            secret_key=config.secret_key,
            expires_days=config.refresh_token_days
        )
        
        config.user_service.save_refresh_token(user.id, new_refresh_token, expires_at)
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

    @router.post("/logout")
    def logout(refresh_request: schemas.RefreshTokenRequest, current_user = Depends(get_current_user)):
        config.user_service.revoke_refresh_token(refresh_request.refresh_token)
        return {"message": "Logout effettuato"}

    @router.post("/logout-all")
    def logout_all(current_user = Depends(get_current_user)):
        config.user_service.revoke_all_user_tokens(current_user.id)
        return {"message": "Logout da tutti i dispositivi"}

    @router.get("/me", response_model=schemas.UserRead)
    def get_me(current_user = Depends(get_current_user)):
        return current_user

    @router.post("/password-reset-request")
    def password_reset_request(request: schemas.PasswordResetRequest):
        user = config.user_service.get_user_by_email(request.email)
        if user:
            reset_token = security.create_password_reset_token(user.email, config.secret_key)
            # TODO: Invia email con reset_token
        return {"message": "Se l'email esiste, è stata inviata una mail di reset"}

    @router.post("/password-reset-confirm")
    def password_reset_confirm(confirm: schemas.PasswordResetConfirm):
        email = security.verify_password_reset_token(confirm.token, config.secret_key)
        if not email:
            raise HTTPException(status_code=400, detail="Token non valido o scaduto")
        
        hashed_password = security.hash_password(confirm.new_password)
        user = config.user_service.update_user_password(email, hashed_password)
        if not user:
            raise HTTPException(status_code=400, detail="Utente non trovato")
        
        config.user_service.revoke_all_user_tokens(user.id)
        return {"message": "Password aggiornata"}

    return router
