"""Orquestração das fontes de dados e cálculo do resultado final.

Combina as fontes legítimas disponíveis (XposedOrNot gratuito + HIBP opcional),
remove duplicatas, calcula o nível de risco e aplica o fallback de demonstração
quando as fontes externas falham.
"""

from __future__ import annotations

import logging

import httpx

from ..config import Settings
from . import demo_data, hibp, leakcheck, passwords, xposedornot

logger = logging.getLogger("darkchecker")


class SourcesUnavailableError(RuntimeError):
    """Nenhuma fonte externa respondeu e o modo demonstração está desativado.

    Sinaliza uma FALHA da verificação (para virar HTTP 503), evitando que um
    apagão total das fontes seja reportado como um resultado "limpo".
    """


# Erros que representam uma falha da fonte externa (rede OU corpo inválido).
# `ValueError` cobre `json.JSONDecodeError`, levantado por `response.json()`
# quando a fonte devolve HTTP 200 com um corpo que não é JSON (ex.: HTML de
# um proxy/portal cativo).
SOURCE_ERRORS: tuple[type[Exception], ...] = (httpx.HTTPError, ValueError)


def _dedupe(breaches: list[dict]) -> list[dict]:
    """Remove vazamentos duplicados entre fontes, priorizando o mais detalhado.

    A chave é o nome do vazamento em minúsculas. Quando o mesmo vazamento vem
    de duas fontes, mantém-se o registro com mais campos preenchidos.
    """
    by_key: dict[str, dict] = {}
    for b in breaches:
        key = (b.get("name") or "").strip().lower()
        if not key:
            continue
        existing = by_key.get(key)
        if existing is None or _richness(b) > _richness(existing):
            by_key[key] = b
    # Ordena por data (mais recente primeiro), depois por nome.
    return sorted(
        by_key.values(),
        key=lambda b: (b.get("breach_date") or "", b.get("name") or ""),
        reverse=True,
    )


def _richness(breach: dict) -> int:
    """Pontua o quão completo é um registro de vazamento (para desempate)."""
    score = 0
    for field in ("breach_date", "pwn_count", "description", "domain"):
        if breach.get(field):
            score += 1
    score += len(breach.get("data_classes") or [])
    return score


def _risk_level(breaches: list[dict], exposed: list[str]) -> str:
    """Deriva um nível de risco simples a partir dos vazamentos encontrados."""
    if not breaches:
        return "none"

    sensitive = {
        "senhas", "passwords", "password",
        "cartões de crédito", "credit cards",
        "cpf", "documentos", "government issued ids",
    }
    has_sensitive = any(dc.strip().lower() in sensitive for dc in exposed)

    if len(breaches) >= 4 or has_sensitive:
        return "high"
    if len(breaches) >= 2:
        return "medium"
    return "low"


def _collect_exposed(breaches: list[dict]) -> list[str]:
    """União ordenada de todas as categorias de dado expostas."""
    seen: dict[str, None] = {}
    for b in breaches:
        for dc in b.get("data_classes") or []:
            seen.setdefault(dc, None)
    return list(seen.keys())


async def check_email(email: str, settings: Settings) -> dict:
    """Verifica um e-mail contra todas as fontes disponíveis e agrega o resultado."""
    breaches: list[dict] = []
    sources_queried: list[str] = []
    notes: list[str] = []
    any_source_ok = False

    # 1) Fonte gratuita: XposedOrNot.
    if settings.xposedornot_enabled:
        try:
            xon = await xposedornot.check_email(email, timeout=settings.http_timeout)
            breaches.extend(xon)
            sources_queried.append("xposedornot")
            any_source_ok = True
        except SOURCE_ERRORS as exc:
            logger.warning("Falha no XposedOrNot: %s", exc)
            notes.append("Fonte XposedOrNot indisponível no momento.")

    # 1b) Fonte gratuita adicional: LeakCheck (cruza com o XposedOrNot).
    if settings.leakcheck_enabled:
        try:
            lc = await leakcheck.check_email(email, timeout=settings.http_timeout)
            breaches.extend(lc)
            sources_queried.append("leakcheck")
            any_source_ok = True
        except SOURCE_ERRORS as exc:
            logger.warning("Falha no LeakCheck: %s", exc)
            notes.append("Fonte LeakCheck indisponível no momento.")

    # 2) Fonte opcional (paga): HIBP, apenas se houver chave.
    if settings.hibp_enabled:
        try:
            hb = await hibp.check_email(
                email,
                api_key=settings.hibp_api_key or "",
                user_agent=settings.hibp_user_agent,
                timeout=settings.http_timeout,
            )
            breaches.extend(hb)
            sources_queried.append("hibp")
            any_source_ok = True
        except SOURCE_ERRORS as exc:
            logger.warning("Falha no HIBP: %s", exc)
            notes.append("Fonte HIBP indisponível ou chave inválida.")

    # 3) Fallback de demonstração, se nenhuma fonte respondeu.
    is_demo = False
    if not any_source_ok and settings.demo_fallback:
        breaches = demo_data.demo_breaches_for(email)
        sources_queried.append("demo")
        is_demo = True
        notes.append(
            "Nenhuma fonte externa respondeu — exibindo DADOS FICTÍCIOS de "
            "demonstração. Não representam vazamentos reais."
        )

    # 4) Apagão total sem demonstração: NÃO reportar "limpo". Sinalizar falha
    #    para que o endpoint responda 503 em vez de um falso resultado seguro.
    if not any_source_ok and not is_demo:
        raise SourcesUnavailableError(
            "Nenhuma fonte de vazamento respondeu e o modo demonstração está "
            "desativado; impossível determinar a exposição do e-mail."
        )

    breaches = _dedupe(breaches)
    exposed = _collect_exposed(breaches)
    risk = _risk_level(breaches, exposed)

    if not breaches and any_source_ok:
        notes.append("Boa notícia: este e-mail não foi encontrado nas fontes consultadas.")

    return {
        "email": email,
        "breached": bool(breaches),
        "breach_count": len(breaches),
        "breaches": breaches,
        "exposed_data": exposed,
        "sources_queried": sources_queried,
        "is_demo": is_demo,
        "risk_level": risk,
        "notes": notes,
    }


async def check_password(password: str, settings: Settings) -> dict:
    """Verifica uma senha via k-anonimato, com fallback de demonstração."""
    try:
        return await passwords.check_password(password, timeout=settings.http_timeout)
    except SOURCE_ERRORS as exc:
        logger.warning("Falha no Pwned Passwords: %s", exc)
        if settings.demo_fallback:
            return demo_data.demo_password_result(password)
        raise SourcesUnavailableError(
            "A API de verificação de senha está indisponível e o modo "
            "demonstração está desativado."
        ) from exc
