"""Verificação de senha vazada usando k-anonimato (HIBP Pwned Passwords).

Como funciona (privacidade por design):
1. Calcula-se o hash SHA-1 da senha.
2. Envia-se à API APENAS os 5 primeiros caracteres do hash (o "prefixo").
3. A API devolve TODOS os sufixos de hash que começam com esse prefixo,
   junto com a contagem de aparições em vazamentos.
4. A comparação final (sufixo) é feita LOCALMENTE, no nosso servidor.

Ou seja: a senha, e mesmo o hash completo, NUNCA são enviados à API externa.
Isso é o "k-anonimato": a API não consegue saber qual senha foi consultada,
pois centenas de hashes compartilham o mesmo prefixo.

Endpoint (gratuito, sem chave): https://api.pwnedpasswords.com/range/{prefixo}
"""

from __future__ import annotations

import hashlib

import httpx

PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def sha1_upper(password: str) -> str:
    """Retorna o SHA-1 da senha em hexadecimal maiúsculo (formato do HIBP)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_range_response(body: str, suffix: str) -> int:
    """Procura o sufixo na resposta da API e devolve a contagem de aparições.

    A resposta tem uma linha por candidato no formato ``SUFIXO:CONTAGEM``.
    Retorna 0 se o sufixo não estiver presente (senha não encontrada).
    """
    suffix = suffix.upper()
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def advice_for(count: int) -> str:
    """Gera uma recomendação textual conforme a exposição da senha."""
    if count == 0:
        return (
            "Esta senha não foi encontrada em vazamentos conhecidos. Ainda assim, "
            "use senhas únicas por serviço e um gerenciador de senhas."
        )
    if count < 100:
        return (
            "Esta senha já apareceu em vazamentos. Troque-a onde a utiliza e "
            "não a reutilize em outros serviços."
        )
    return (
        "Esta senha é muito comum e apareceu MILHARES de vezes em vazamentos. "
        "Ela é um alvo direto de ataques de força bruta e credential stuffing. "
        "Troque-a imediatamente em todos os serviços."
    )


async def check_password(
    password: str, *, timeout: float = 10.0, add_padding: bool = True
) -> dict:
    """Verifica uma senha via k-anonimato. Levanta httpx.HTTPError em falha de rede."""
    full_hash = sha1_upper(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    headers = {"User-Agent": "DarkChecker-Academic-Project"}
    # "Add-Padding" faz a API devolver resultados falsos de preenchimento,
    # dificultando análise de tráfego. Recurso oficial do HIBP.
    if add_padding:
        headers["Add-Padding"] = "true"

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(
            PWNED_PASSWORDS_URL.format(prefix=prefix), headers=headers
        )
        resp.raise_for_status()
        count = parse_range_response(resp.text, suffix)

    return {
        "pwned": count > 0,
        "count": count,
        "prefix_sent": prefix,
        "method": "k-anonymity",
        "advice": advice_for(count),
        "is_demo": False,
    }
