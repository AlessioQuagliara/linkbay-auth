from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from .core import AuthCore
from .schemas import (
    UserCreate, UserLogin, Token, UserResponse,
    PasswordResetRequest, PasswordResetConfirm
)
from .dependencies import get_current_active_user
from .security_utils import validate_email_advanced, get_client_info

def create_auth_router(auth_core: AuthCore) -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/register", response_model=Token)
    async def register(user_data: UserCreate, request: Request):
        # Validazione email avanzata
        validated_email = validate_email_advanced(user_data.email)
        
        # Verifica se l'utente esiste già
        existing_user = await auth_core.user_service.get_user_by_email(validated_email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Valida forza password
        is_valid, error_msg = auth_core.validate_password_strength(user_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )

        # Crea nuovo utente
        hashed_password = auth_core.get_password_hash(user_data.password)
        user = await auth_core.user_service.create_user(validated_email, hashed_password)
        
        # Log security event
        client_info = get_client_info(request)
        await auth_core.user_service.log_security_event(
            event_type="USER_REGISTERED",
            user_id=user.id,
            details=client_info
        )
        
        # Crea tokens
        access_token = auth_core.create_access_token(data={"sub": str(user.id)})
        refresh_token = auth_core.create_refresh_token(user.id)
        
        # Salva refresh token
        expires_at = datetime.utcnow() + timedelta(days=auth_core.refresh_token_expire_days)
        await auth_core.user_service.save_refresh_token(user.id, refresh_token, expires_at)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )

    @router.post("/login", response_model=Token)
    async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
        # Check protezione brute force
        can_attempt = await auth_core.user_service.check_login_attempts(form_data.username)
        if not can_attempt:
            client_info = get_client_info(request)
            await auth_core.user_service.log_security_event(
                event_type="LOGIN_BLOCKED_BRUTEFORCE",
                email=form_data.username,
                details=client_info
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Troppi tentativi di login. Account temporaneamente bloccato."
            )
        
        user = await auth_core.authenticate_user(form_data.username, form_data.password)
        if not user:
            # Log tentativo fallito
            await auth_core.user_service.record_failed_login(form_data.username)
            client_info = get_client_info(request)
            await auth_core.user_service.log_security_event(
                event_type="LOGIN_FAILED",
                email=form_data.username,
                details=client_info
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )
        
        # Reset contatore tentativi falliti
        await auth_core.user_service.reset_failed_logins(form_data.username)
        
        # Log login success
        client_info = get_client_info(request)
        await auth_core.user_service.log_security_event(
            event_type="LOGIN_SUCCESS",
            user_id=user.id,
            details=client_info
        )
        
        access_token = auth_core.create_access_token(data={"sub": str(user.id)})
        refresh_token = auth_core.create_refresh_token(user.id)
        
        expires_at = datetime.utcnow() + timedelta(days=auth_core.refresh_token_expire_days)
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
    async def logout(request: Request, refresh_token: str, access_token: str):
        # Blacklist access token per logout immediato
        auth_core.blacklist_token(access_token)
        
        # Revoca refresh token
        success = await auth_core.user_service.revoke_refresh_token(refresh_token)
        if not success:
            raise HTTPException(status_code=404, detail="Token not found")
        
        # Log logout
        token_data = await auth_core.verify_token(access_token)
        if token_data:
            client_info = get_client_info(request)
            await auth_core.user_service.log_security_event(
                event_type="LOGOUT",
                user_id=token_data.user_id,
                details=client_info
            )
        
        return {"message": "Successfully logged out"}

    @router.post("/logout-all")
    async def logout_all(request: Request, current_user: UserResponse = Depends(get_current_active_user)):
        await auth_core.user_service.revoke_all_user_tokens(current_user.id)
        
        # Log logout from all devices
        client_info = get_client_info(request)
        await auth_core.user_service.log_security_event(
            event_type="LOGOUT_ALL_DEVICES",
            user_id=current_user.id,
            details=client_info
        )
        
        return {"message": "Logged out from all devices"}

    @router.get("/me", response_model=UserResponse)
    async def get_me(current_user: UserResponse = Depends(get_current_active_user)):
        return current_user

    @router.post("/password-reset-request")
    async def password_reset_request(reset_req: PasswordResetRequest, req: Request):
        user = await auth_core.user_service.get_user_by_email(reset_req.email)
        
        # Log request (anche se email non esiste)
        client_info = get_client_info(req)
        await auth_core.user_service.log_security_event(
            event_type="PASSWORD_RESET_REQUESTED",
            email=reset_req.email,
            details=client_info
        )
        
        if user:
            # Crea token reset con expiry
            reset_token = auth_core.create_password_reset_token(reset_req.email, expires_hours=1)
            # TODO: Invia email con reset_token
            # send_password_reset_email(reset_req.email, reset_token)
        
        # Non rivelare se email esiste
        return {"message": "If email exists, reset instructions sent"}

    @router.post("/password-reset-confirm")
    async def password_reset_confirm(confirm: PasswordResetConfirm, req: Request):
        # Verifica token reset password
        email = auth_core.verify_password_reset_token(confirm.token)
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token non valido o scaduto"
            )
        
        # Valida forza nuova password
        is_valid, error_msg = auth_core.validate_password_strength(confirm.new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )
        
        user = await auth_core.user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Utente non trovato"
            )
        
        # Hash nuova password e aggiorna
        hashed_password = auth_core.get_password_hash(confirm.new_password)
        await auth_core.user_service.update_user_password(user.email, hashed_password)
        
        # Log password reset
        client_info = get_client_info(req)
        await auth_core.user_service.log_security_event(
            event_type="PASSWORD_RESET",
            user_id=user.id,
            details=client_info
        )
        
        # Revoca tutti i token per forzare nuovo login
        await auth_core.user_service.revoke_all_user_tokens(user.id)
        
        return {"message": "Password reset successful"}

    return router