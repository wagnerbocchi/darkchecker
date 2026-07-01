"""Dados FICTÍCIOS para o modo demonstração.

Usados apenas quando as APIs externas estão indisponíveis (offline, rate limit)
e `DEMO_FALLBACK=true`. Servem para apresentar a aplicação em sala sem depender
de rede. TODOS os vazamentos aqui são inventados e claramente rotulados.

Nenhum dado real, roubado ou de terceiros é incluído — coerente com a proposta
ética do projeto.
"""

from __future__ import annotations

# Vazamentos de exemplo, inspirados em incidentes públicos famosos, porém
# com dados sintéticos. Servem só para ilustrar a interface.
_DEMO_BREACHES = [
    {
        "name": "ExemploSocial2019",
        "title": "ExemploSocial (demonstração)",
        "domain": "exemplo-social.com",
        "breach_date": "2019-05-01",
        "pwn_count": 164_000_000,
        "data_classes": ["E-mails", "Senhas", "Nomes de usuário", "Datas de nascimento"],
        "description": (
            "[DADO FICTÍCIO] Vazamento de demonstração usado para ilustrar como "
            "os metadados de um incidente aparecem na aplicação."
        ),
        "source": "demo",
        "is_verified": True,
    },
    {
        "name": "LojaExemplo2021",
        "title": "LojaExemplo (demonstração)",
        "domain": "loja-exemplo.com.br",
        "breach_date": "2021-11-20",
        "pwn_count": 8_300_000,
        "data_classes": ["E-mails", "Endereços físicos", "Telefones", "Compras"],
        "description": (
            "[DADO FICTÍCIO] Segundo vazamento de demonstração, mostrando como "
            "diferentes categorias de dado se somam ao perfil de exposição."
        ),
        "source": "demo",
        "is_verified": True,
    },
    {
        "name": "ForumExemplo2016",
        "title": "FórumExemplo (demonstração)",
        "domain": "forum-exemplo.net",
        "breach_date": "2016-02-10",
        "pwn_count": 12_000_000,
        "data_classes": ["E-mails", "Senhas", "Endereços IP"],
        "description": (
            "[DADO FICTÍCIO] Terceiro vazamento de demonstração para completar "
            "o cenário de exemplo."
        ),
        "source": "demo",
        "is_verified": False,
    },
]


def demo_breaches_for(email: str) -> list[dict]:
    """Retorna vazamentos fictícios de forma determinística a partir do e-mail.

    A quantidade varia conforme um hash simples do e-mail, então e-mails
    diferentes produzem cenários diferentes — mas sempre os mesmos para o
    mesmo e-mail (previsível para demonstração). Alguns e-mails retornam zero.
    """
    seed = sum(ord(c) for c in email.strip().lower())
    count = seed % (len(_DEMO_BREACHES) + 1)  # 0..len
    return [dict(b) for b in _DEMO_BREACHES[:count]]


# Resposta fictícia para a verificação de senha (modo demo).
def demo_password_result(password: str) -> dict:
    seed = sum(ord(c) for c in password)
    pwned = seed % 3 != 0
    count = (seed * 37) % 250_000 if pwned else 0
    from .passwords import advice_for, sha1_upper

    return {
        "pwned": pwned,
        "count": count,
        "prefix_sent": sha1_upper(password)[:5],
        "method": "k-anonymity (demonstração)",
        "advice": advice_for(count),
        "is_demo": True,
    }
