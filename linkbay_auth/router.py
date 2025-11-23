from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime
from .core import AuthCore
from .schemas import (
    UserCreate, UserLogin, Token, UserResponse,
    PasswordResetRequest, PasswordResetConfirm
)

def create_auth_router(auth_core: AuthCore) -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/register", response_model=Token)
    async def register(user_data: UserCreate):
        # Verifica se l'utente esiste già
        existing_user = await auth_core.user_service.get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Crea nuovo utente
        hashed_password = auth_core.get_password_hash(user_data.password)
        user = await auth_core.user_service.create_user(user_data.email, hashed_password)
        
        # Crea tokens
        access_token = auth_core.create_access_token(data={"sub": str(user.id)})
        refresh_token = auth_core.create_refresh_token(user.id)
        
        # Salva refresh token
        expires_at = datetime.utcnow() + auth_core.refresh_token_expire_days
        await auth_core.user_service.save_refresh_token(user.id, refresh_token, expires_at)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )

    @router.post("/login", response_model=Token)
    async def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = await auth_core.authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )
        
        access_token = auth_core.create_access_token(data={"sub": str(user.id)})
        refresh_token = auth_core.create_refresh_token(user.id)
        
        expires_at = datetime.utcnow() + auth_core.refresh_token_expire_days
        await auth_core.user_service.save_refresh_token(user.id, refresh_token, expires_at)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )

    @router.post("/refresh", response_model=Token)
    async def refresh_token(refresh_token: str):
        token_data = await auth_core.verify_token(refresh_token)
        if not token_data:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Verifica che il refresh token sia nel database e non revocato
        stored_token = await auth_core.user_service.get_refresh_token(refresh_token)
        if not stored_token:
            raise HTTPException(status_code=401, detail="Refresh token not found")
        
        # Crea nuovo access token
        new_access_token = auth_core.create_access_token(data={"sub": str(token_data.user_id)})
        
        return Token(
            access_token=new_access_token,
            refresh_token=refresh_token  # Il refresh token rimane lo stesso
        )

    @router.post("/logout")
    async def logout(refresh_token: str):
        success = await auth_core.user_service.revoke_refresh_token(refresh_token)
        if not success:
            raise HTTPException(status_code=404, detail="Token not found")
        return {"message": "Successfully logged out"}

    @router.post("/logout-all")
    async def logout_all(current_user: UserResponse = Depends(get_current_active_user)):
        await auth_core.user_service.revoke_all_user_tokens(current_user.id)
        return {"message": "Logged out from all devices"}

    @router.get("/me", response_model=UserResponse)
    async def get_me(current_user: UserResponse = Depends(get_current_active_user)):
        return current_user

    @router.post("/password-reset-request")
    async def password_reset_request(request: PasswordResetRequest):
        # Qui implementa la logica per inviare email di reset
        # Per semplicità, restituiamo un messaggio
        return {"message": "If email exists, reset instructions sent"}

    @router.post("/password-reset-confirm")
    async def password_reset_confirm(confirm: PasswordResetConfirm):
        # Qui implementa la verifica del token e reset password
        hashed_password = auth_core.get_password_hash(confirm.new_password)
        # ... logica per trovare l'utente dal token e aggiornare password
        return {"message": "Password reset successful"}

    return router