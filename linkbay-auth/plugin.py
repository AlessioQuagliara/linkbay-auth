# plugin.py
from dataclasses import dataclass
from fastapi import FastAPI
from .routes import get_auth_router
from .service import UserServiceProtocol

@dataclass
class AuthConfig:
    user_service: UserServiceProtocol
    secret_key: str
    access_token_minutes: int = 15
    refresh_token_days: int = 30

class LinkBayAuthPlugin:
    def __init__(self, config: AuthConfig):
        self.config = config

    def install(self, app: FastAPI, prefix: str = "/auth"):
        router = get_auth_router(self.config)
        app.include_router(router, prefix=prefix)
