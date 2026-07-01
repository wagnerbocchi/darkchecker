"""Modelos de dados (Pydantic) usados nas requisições e respostas da API."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Requisições
# ---------------------------------------------------------------------------
class EmailCheckRequest(BaseModel):
    """Requisição de verificação de e-mail em vazamentos."""

    email: EmailStr = Field(..., description="E-mail a ser verificado.")


class PasswordCheckRequest(BaseModel):
    """Requisição de verificação de senha (via k-anonimato)."""

    password: str = Field(..., min_length=1, description="Senha a ser verificada.")


# ---------------------------------------------------------------------------
# Respostas
# ---------------------------------------------------------------------------
class Breach(BaseModel):
    """Um vazamento no qual o e-mail apareceu."""

    name: str = Field(..., description="Identificador/nome do vazamento.")
    title: str = Field(..., description="Título legível do vazamento.")
    domain: str | None = Field(None, description="Domínio da organização vazada.")
    breach_date: str | None = Field(None, description="Data do vazamento (YYYY-MM-DD).")
    pwn_count: int | None = Field(None, description="Nº de contas afetadas.")
    data_classes: list[str] = Field(
        default_factory=list,
        description="Tipos de dado expostos (e-mail, senha, etc.).",
    )
    description: str | None = Field(None, description="Descrição do vazamento.")
    source: str = Field(..., description="Fonte que reportou (hibp, xposedornot, demo).")
    is_verified: bool | None = Field(
        None, description="Se o vazamento foi verificado pela fonte."
    )


class EmailCheckResponse(BaseModel):
    """Resultado agregado da verificação de e-mail."""

    email: str
    breached: bool = Field(..., description="Se o e-mail apareceu em algum vazamento.")
    breach_count: int = Field(..., description="Quantidade de vazamentos encontrados.")
    breaches: list[Breach] = Field(default_factory=list)
    exposed_data: list[str] = Field(
        default_factory=list,
        description="União dos tipos de dado expostos entre todos os vazamentos.",
    )
    sources_queried: list[str] = Field(
        default_factory=list, description="Fontes consultadas nesta verificação."
    )
    is_demo: bool = Field(
        False, description="Se os dados são fictícios (modo demonstração)."
    )
    risk_level: str = Field("none", description="Nível de risco: none | low | medium | high")
    notes: list[str] = Field(default_factory=list, description="Avisos e observações.")


class PasswordCheckResponse(BaseModel):
    """Resultado da verificação de senha via k-anonimato (HIBP Pwned Passwords)."""

    pwned: bool = Field(..., description="Se a senha aparece em vazamentos conhecidos.")
    count: int = Field(0, description="Quantas vezes a senha foi vista em vazamentos.")
    prefix_sent: str = Field(
        ..., description="Prefixo SHA-1 (5 chars) efetivamente enviado à API."
    )
    method: str = Field(
        "k-anonymity",
        description="Técnica usada — a senha em si nunca deixa o servidor.",
    )
    advice: str = Field(..., description="Recomendação ao usuário.")
    is_demo: bool = Field(False, description="Se o resultado é do modo demonstração.")


class HealthResponse(BaseModel):
    """Estado da aplicação e das integrações."""

    status: str = "ok"
    version: str
    hibp_email_enabled: bool
    demo_fallback: bool
    email_sources: list[str] = Field(
        default_factory=list,
        description="Fontes de e-mail ativas (xposedornot, leakcheck, hibp).",
    )
