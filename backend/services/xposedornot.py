"""Integração com a API pública e GRATUITA do XposedOrNot.

O XposedOrNot (https://xposedornot.com) é um serviço legítimo, com uma API
pública e sem necessidade de chave, que informa em quais vazamentos conhecidos
um e-mail apareceu — assim como o HIBP, sem expor senhas ou dados pessoais.

É a fonte padrão desta aplicação, permitindo que ela funcione totalmente de
graça, o que é ideal para um projeto acadêmico.

Endpoints usados:
- Resumo:   https://api.xposedornot.com/v1/check-email/{email}
- Detalhes: https://api.xposedornot.com/v1/breach-analytics?email={email}
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

CHECK_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/{email}"
ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"


def _normalize_detail(raw: dict) -> dict:
    """Converte um item de `breaches_details` para o formato interno `Breach`."""
    # O campo xposed_data vem como "Email;Passwords;Usernames".
    xposed = raw.get("xposed_data") or ""
    data_classes = [p.strip() for p in xposed.replace(",", ";").split(";") if p.strip()]

    records = raw.get("xposed_records")
    try:
        pwn_count = int(records) if records is not None else None
    except (TypeError, ValueError):
        pwn_count = None

    name = raw.get("breach") or raw.get("Name") or "Desconhecido"
    return {
        "name": name,
        "title": name,
        "domain": raw.get("domain") or None,
        "breach_date": str(raw.get("xposed_date")) if raw.get("xposed_date") else None,
        "pwn_count": pwn_count,
        "data_classes": data_classes,
        "description": raw.get("details"),
        "source": "xposedornot",
        "is_verified": _to_bool(raw.get("verified")),
    }


def _to_bool(value) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1"}


async def check_email(email: str, *, timeout: float = 10.0) -> list[dict]:
    """Consulta o XposedOrNot e devolve os vazamentos no formato interno.

    Tenta primeiro o endpoint de análise detalhada; se este não trouxer
    detalhes, recorre ao endpoint de resumo (apenas nomes). Lista vazia
    significa nenhum vazamento encontrado.
    """
    headers = {"User-Agent": "DarkChecker-Academic-Project"}
    encoded = quote(email, safe="")

    async with httpx.AsyncClient(timeout=timeout) as client:
        # 1) Tenta a análise detalhada (traz datas, categorias, contagem).
        analytics = await client.get(
            ANALYTICS_URL, params={"email": email}, headers=headers
        )
        if analytics.status_code == 200:
            detailed = _parse_analytics(analytics.json())
            if detailed:
                return detailed

        # 2) Fallback: endpoint de resumo, que devolve só os nomes.
        summary = await client.get(
            CHECK_EMAIL_URL.format(email=encoded), headers=headers
        )
        # 404 = e-mail não encontrado (não é erro).
        if summary.status_code == 404:
            return []
        if summary.status_code == 200:
            return _parse_summary(summary.json())
        # Qualquer outro status (429 rate limit, 403, 5xx) é uma FALHA da fonte:
        # levanta erro para que o agregador registre e acione o modo demo,
        # em vez de reportar "sem vazamentos" indevidamente.
        summary.raise_for_status()

    return []


def _parse_analytics(payload: dict) -> list[dict]:
    """Extrai `ExposedBreaches.breaches_details` da resposta de análise."""
    if not isinstance(payload, dict):
        return []
    exposed = payload.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    if not isinstance(details, list):
        return []
    return [_normalize_detail(item) for item in details if isinstance(item, dict)]


def _parse_summary(payload: dict) -> list[dict]:
    """Extrai a lista de nomes de vazamentos do endpoint de resumo."""
    if not isinstance(payload, dict):
        return []
    raw = payload.get("breaches")
    # Formato observado: {"breaches": [["Tumblr", "LinkedIn", ...]]}
    names: list[str] = []
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, list):
                names.extend(str(n) for n in entry)
            elif isinstance(entry, str):
                names.append(entry)
    return [
        {
            "name": n,
            "title": n,
            "domain": None,
            "breach_date": None,
            "pwn_count": None,
            "data_classes": [],
            "description": None,
            "source": "xposedornot",
            "is_verified": None,
        }
        for n in names
    ]
