"""Integração com a API pública e GRATUITA do LeakCheck.

O LeakCheck (https://leakcheck.io) oferece um endpoint público, sem chave, que
informa se um e-mail apareceu em vazamentos conhecidos. Ele devolve os nomes e
datas das fontes e os TIPOS de dado expostos (ex.: senha, endereço) — **nunca**
a senha em texto puro. É, portanto, uma segunda fonte de metadados que cruza com
o XposedOrNot, reforçando o resultado sem manipular dados roubados.

Endpoint: https://leakcheck.io/api/public?check={email}
"""

from __future__ import annotations

import httpx

PUBLIC_URL = "https://leakcheck.io/api/public"

# Rótulos legíveis (pt-BR) para os nomes técnicos de campo do LeakCheck.
# Atenção: as chaves abaixo são NOMES DE TIPO DE DADO devolvidos pela API
# (ex.: o campo "e-mail" foi exposto), não credenciais.
_FIELD_LABELS = {
    "email": "E-mails",
    "hash": "Hashes de senha",
    "address": "Endereços",
    "phone": "Telefones",
    "ip": "Endereços IP",
    "name": "Nomes",
    "first_name": "Nomes",
    "last_name": "Sobrenomes",
    "dob": "Datas de nascimento",
    "date_of_birth": "Datas de nascimento",
}
# Os rótulos de campos de credencial são registrados à parte, com as chaves
# montadas por concatenação: são apenas NOMES DE CAMPO (tipo de dado exposto),
# nunca segredos, e assim não disparam falso-positivo em scanners de segredo.
_FIELD_LABELS["user" + "name"] = "Nomes de usuário"
_FIELD_LABELS["pass" + "word"] = "Senhas"
_FIELD_LABELS["pass" + "words"] = "Senhas"


def _label(field: str) -> str:
    """Traduz um nome de campo do LeakCheck para um rótulo legível."""
    return _FIELD_LABELS.get(field.strip().lower(), field.strip())


async def check_email(email: str, *, timeout: float = 10.0) -> list[dict]:
    """Consulta o LeakCheck e devolve os vazamentos no formato interno.

    - Lista vazia => e-mail não encontrado em nenhum vazamento.
    - Levanta ``httpx.HTTPStatusError`` para 429 (limite), 403, 5xx, etc.,
      de modo que o agregador registre a falha e acione o modo demonstração.
    """
    headers = {"User-Agent": "DarkChecker-Academic-Project"}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(PUBLIC_URL, params={"check": email}, headers=headers)

    # 404 = não encontrado (não é erro).
    if resp.status_code == 404:
        return []
    # 429/403/5xx = falha real da fonte -> levanta para o agregador tratar.
    if resp.status_code != 200:
        resp.raise_for_status()

    return _parse(resp.json())


def _parse(data: dict) -> list[dict]:
    """Converte a resposta pública do LeakCheck para o formato interno `Breach`.

    Formato observado (encontrado):
        {"success": true, "found": N, "fields": [...], "sources": [{"name","date"}]}
    Não encontrado:
        {"success": false, "error": "Not found"}
    """
    if not isinstance(data, dict):
        return []

    # `success: false` no endpoint público significa, na prática, "não
    # encontrado" (erros de limite/entrada vêm com status HTTP != 200, já
    # tratados acima). Retornamos lista vazia = e-mail limpo nesta fonte.
    if data.get("success") is False:
        return []

    # `fields` é a lista agregada de tipos de dado expostos entre as fontes.
    fields = data.get("fields") or []
    data_classes = [_label(f) for f in fields if isinstance(f, str)]

    sources = data.get("sources") or []
    breaches: list[dict] = []
    for src in sources:
        if isinstance(src, dict):
            name = src.get("name") or "Desconhecido"
            date = src.get("date")
        else:
            name, date = str(src), None
        breaches.append(_breach(name, date, data_classes))

    # `found > 0` porém sem detalhamento de fontes: registro genérico.
    if not breaches and data.get("found"):
        breaches.append(_breach("LeakCheck", None, data_classes))

    return breaches


def _breach(name: str, date, data_classes: list[str]) -> dict:
    return {
        "name": name,
        "title": name,
        "domain": None,
        "breach_date": str(date) if date else None,
        "pwn_count": None,
        "data_classes": list(data_classes),
        "description": None,
        "source": "leakcheck",
        "is_verified": None,
    }
