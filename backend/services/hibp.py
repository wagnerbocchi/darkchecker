"""Integração com a API do Have I Been Pwned (HIBP) para consulta de e-mail.

A consulta de e-mail em vazamentos (`breachedaccount`) exige assinatura paga
e uma chave de API. Este módulo só é acionado quando a chave está configurada.

Documentação: https://haveibeenpwned.com/API/v3
Endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{account}

Nota ética: o HIBP NÃO devolve senhas nem dados pessoais — apenas os METADADOS
do vazamento (nome, data, quais CATEGORIAS de dado foram expostas). É essa
abstração que o torna uma ferramenta defensiva e legal.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

HIBP_BREACHEDACCOUNT_URL = (
    "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
)


def _normalize(raw: dict) -> dict:
    """Converte um objeto de vazamento do HIBP para o formato interno `Breach`."""
    return {
        "name": raw.get("Name", raw.get("Title", "Desconhecido")),
        "title": raw.get("Title", raw.get("Name", "Desconhecido")),
        "domain": raw.get("Domain") or None,
        "breach_date": raw.get("BreachDate"),
        "pwn_count": raw.get("PwnCount"),
        "data_classes": raw.get("DataClasses", []) or [],
        "description": raw.get("Description"),
        "source": "hibp",
        "is_verified": raw.get("IsVerified"),
    }


async def check_email(
    email: str, *, api_key: str, user_agent: str, timeout: float = 10.0
) -> list[dict]:
    """Consulta o HIBP e devolve a lista de vazamentos (formato interno).

    - Lista vazia => e-mail não encontrado em nenhum vazamento (HTTP 404).
    - Levanta ``httpx.HTTPStatusError`` para erros de autenticação/limite.
    """
    url = HIBP_BREACHEDACCOUNT_URL.format(account=quote(email, safe=""))
    headers = {
        "hibp-api-key": api_key,
        "user-agent": user_agent,
        "Accept": "application/json",
    }
    params = {"truncateResponse": "false"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(url, headers=headers, params=params)

    # 404 é a forma do HIBP dizer "nenhum vazamento" — não é erro.
    if resp.status_code == 404:
        return []
    resp.raise_for_status()

    data = resp.json()
    if not isinstance(data, list):
        return []
    return [_normalize(item) for item in data]
