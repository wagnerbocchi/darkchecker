"""Ponto de entrada da API (FastAPI) do DarkChecker.

Expõe os endpoints de verificação e serve o frontend estático.

Executar (a partir da raiz do projeto):
    uvicorn backend.main:app --reload
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Settings, get_settings
from .schemas import (
    EmailCheckRequest,
    EmailCheckResponse,
    HealthResponse,
    PasswordCheckRequest,
    PasswordCheckResponse,
)
from .services import aggregator
from .services.aggregator import SourcesUnavailableError

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(
    title="DarkChecker",
    description=(
        "Aplicação acadêmica para verificar a exposição de e-mails e senhas "
        "em vazamentos de dados conhecidos, usando exclusivamente fontes "
        "legítimas e legais."
    ),
    version=__version__,
)

# Em desenvolvimento, liberamos CORS para facilitar testes locais do frontend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse, tags=["meta"])
async def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Retorna o estado da aplicação e quais integrações estão habilitadas."""
    email_sources = []
    if settings.xposedornot_enabled:
        email_sources.append("xposedornot")
    if settings.leakcheck_enabled:
        email_sources.append("leakcheck")
    if settings.hibp_enabled:
        email_sources.append("hibp")
    return HealthResponse(
        version=__version__,
        hibp_email_enabled=settings.hibp_enabled,
        demo_fallback=settings.demo_fallback,
        email_sources=email_sources,
    )


@app.post("/api/check/email", response_model=EmailCheckResponse, tags=["verificação"])
async def check_email(
    payload: EmailCheckRequest, settings: Settings = Depends(get_settings)
) -> EmailCheckResponse:
    """Verifica se um e-mail aparece em vazamentos de dados conhecidos."""
    try:
        result = await aggregator.check_email(payload.email, settings)
    except SourcesUnavailableError as exc:
        # Apagão total das fontes: 503 em vez de um falso "limpo".
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return EmailCheckResponse(**result)


@app.post(
    "/api/check/password", response_model=PasswordCheckResponse, tags=["verificação"]
)
async def check_password(
    payload: PasswordCheckRequest, settings: Settings = Depends(get_settings)
) -> PasswordCheckResponse:
    """Verifica se uma senha aparece em vazamentos, usando k-anonimato.

    A senha nunca deixa o servidor: apenas o prefixo (5 chars) do hash SHA-1
    é enviado à API do HIBP Pwned Passwords.
    """
    try:
        result = await aggregator.check_password(payload.password, settings)
    except SourcesUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return PasswordCheckResponse(**result)


# ---------------------------------------------------------------------------
# Frontend estático
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    """Serve a página principal da aplicação."""
    return FileResponse(FRONTEND_DIR / "index.html")


# Demais assets (CSS/JS) são servidos a partir de /static.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
