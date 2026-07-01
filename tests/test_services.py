"""Testes unitários dos serviços do DarkChecker.

As chamadas HTTP externas são simuladas com `respx`, de modo que os testes
rodam offline e de forma determinística.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
import respx

from backend.config import Settings
from backend.services import aggregator, demo_data, hibp, passwords, xposedornot
from backend.services.aggregator import SourcesUnavailableError


# ---------------------------------------------------------------------------
# passwords / k-anonimato
# ---------------------------------------------------------------------------
def test_sha1_upper_matches_hashlib():
    assert passwords.sha1_upper("senha123") == hashlib.sha1(b"senha123").hexdigest().upper()


def test_parse_range_response_found():
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:12\nAAA:3"
    assert passwords.parse_range_response(body, "0018A45C4D1DEF81644B54AB7F969B88D65") == 12


def test_parse_range_response_not_found():
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:12"
    assert passwords.parse_range_response(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0


def test_parse_range_response_case_insensitive():
    body = "abc123:7"
    assert passwords.parse_range_response(body, "ABC123") == 7


@respx.mock
async def test_check_password_pwned():
    full = passwords.sha1_upper("password")
    prefix, suffix = full[:5], full[5:]
    route = respx.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    route.mock(return_value=httpx.Response(200, text=f"{suffix}:99999\nDEADBEEF:2"))

    result = await passwords.check_password("password")
    assert result["pwned"] is True
    assert result["count"] == 99999
    assert result["prefix_sent"] == prefix
    assert result["is_demo"] is False


@respx.mock
async def test_check_password_clean():
    full = passwords.sha1_upper("uma-senha-bem-improvavel-!@#-2026")
    prefix = full[:5]
    respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
        return_value=httpx.Response(200, text="0000000000000000000000000000000000A:1")
    )
    result = await passwords.check_password("uma-senha-bem-improvavel-!@#-2026")
    assert result["pwned"] is False
    assert result["count"] == 0


# ---------------------------------------------------------------------------
# XposedOrNot
# ---------------------------------------------------------------------------
@respx.mock
async def test_xposedornot_analytics_parsing():
    payload = {
        "ExposedBreaches": {
            "breaches_details": [
                {
                    "breach": "TestBreach",
                    "domain": "test.com",
                    "xposed_date": "2019",
                    "xposed_records": 1000,
                    "xposed_data": "Email;Passwords;Usernames",
                    "details": "Um vazamento de teste.",
                    "verified": "true",
                }
            ]
        }
    }
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(200, json=payload)
    )
    result = await xposedornot.check_email("vitima@test.com")
    assert len(result) == 1
    b = result[0]
    assert b["name"] == "TestBreach"
    assert b["pwn_count"] == 1000
    assert b["data_classes"] == ["Email", "Passwords", "Usernames"]
    assert b["source"] == "xposedornot"
    assert b["is_verified"] is True


@respx.mock
async def test_xposedornot_summary_fallback():
    # análise sem detalhes -> cai no endpoint de resumo
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*").mock(
        return_value=httpx.Response(200, json={"breaches": [["Tumblr", "LinkedIn"]]})
    )
    result = await xposedornot.check_email("vitima@test.com")
    names = {b["name"] for b in result}
    assert names == {"Tumblr", "LinkedIn"}


@respx.mock
async def test_xposedornot_not_found():
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*").mock(
        return_value=httpx.Response(404, json={"Error": "Not found"})
    )
    result = await xposedornot.check_email("limpo@test.com")
    assert result == []


# ---------------------------------------------------------------------------
# HIBP
# ---------------------------------------------------------------------------
@respx.mock
async def test_hibp_parsing():
    payload = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "PwnCount": 152445165,
            "DataClasses": ["Emails", "Passwords"],
            "Description": "Vazamento da Adobe.",
            "IsVerified": True,
        }
    ]
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(200, json=payload)
    )
    result = await hibp.check_email("a@b.com", api_key="k", user_agent="ua")
    assert result[0]["name"] == "Adobe"
    assert result[0]["source"] == "hibp"
    assert result[0]["pwn_count"] == 152445165


@respx.mock
async def test_hibp_404_means_clean():
    respx.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(
        return_value=httpx.Response(404)
    )
    result = await hibp.check_email("clean@b.com", api_key="k", user_agent="ua")
    assert result == []


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------
def test_dedupe_keeps_richest():
    breaches = [
        {"name": "Adobe", "data_classes": [], "breach_date": None},
        {
            "name": "adobe",
            "data_classes": ["Emails", "Passwords"],
            "breach_date": "2013-10-04",
            "description": "x",
            "domain": "adobe.com",
            "pwn_count": 1,
        },
    ]
    result = aggregator._dedupe(breaches)
    assert len(result) == 1
    assert result[0]["data_classes"] == ["Emails", "Passwords"]


def test_risk_level_scaling():
    assert aggregator._risk_level([], []) == "none"
    assert aggregator._risk_level([{"name": "a"}], []) == "low"
    assert aggregator._risk_level([{"name": "a"}, {"name": "b"}], []) == "medium"
    # dados sensíveis elevam o risco mesmo com um único vazamento
    assert aggregator._risk_level([{"name": "a"}], ["Passwords"]) == "high"


def test_collect_exposed_union():
    breaches = [
        {"data_classes": ["Emails", "Passwords"]},
        {"data_classes": ["Emails", "IP addresses"]},
    ]
    exposed = aggregator._collect_exposed(breaches)
    assert exposed == ["Emails", "Passwords", "IP addresses"]


@respx.mock
async def test_aggregator_demo_fallback_when_sources_fail():
    # XposedOrNot falha (erro de rede) e não há chave HIBP -> modo demo.
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        side_effect=httpx.ConnectError("down")
    )
    settings = Settings(hibp_api_key=None, demo_fallback=True)
    result = await aggregator.check_email("demo-user@example.com", settings)
    assert result["is_demo"] is True
    assert "demo" in result["sources_queried"]


@respx.mock
async def test_aggregator_no_demo_when_source_ok_and_clean():
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*").mock(
        return_value=httpx.Response(404, json={"Error": "Not found"})
    )
    settings = Settings(hibp_api_key=None, demo_fallback=True)
    result = await aggregator.check_email("clean@example.com", settings)
    assert result["is_demo"] is False
    assert result["breached"] is False


# --- Regressões: achados da revisão adversarial -----------------------------
@respx.mock
async def test_aggregator_raises_when_all_fail_and_no_demo():
    """Apagão total sem demo NÃO pode virar 'limpo' — deve sinalizar falha."""
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        side_effect=httpx.ConnectError("down")
    )
    settings = Settings(hibp_api_key=None, demo_fallback=False)
    with pytest.raises(SourcesUnavailableError):
        await aggregator.check_email("user@example.com", settings)


@respx.mock
async def test_aggregator_demo_fallback_on_non_json_body():
    """HTTP 200 com corpo não-JSON (proxy/portal) não deve virar 500."""
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(200, text="<html>captive portal</html>")
    )
    settings = Settings(hibp_api_key=None, demo_fallback=True)
    result = await aggregator.check_email("user@example.com", settings)
    assert result["is_demo"] is True


@respx.mock
async def test_xposedornot_analytics_error_raises_not_silently_clean():
    """429 na análise deve levantar (para acionar o demo), não cair no resumo."""
    respx.get("https://api.xposedornot.com/v1/breach-analytics").mock(
        return_value=httpx.Response(429, text="rate limited")
    )
    with pytest.raises(httpx.HTTPStatusError):
        await xposedornot.check_email("user@test.com")


async def test_check_password_reraises_as_sources_unavailable_without_demo():
    settings = Settings(demo_fallback=False)
    with respx.mock:
        respx.get(url__regex=r"https://api\.pwnedpasswords\.com/range/.*").mock(
            side_effect=httpx.ConnectError("down")
        )
        with pytest.raises(SourcesUnavailableError):
            await aggregator.check_password("qualquer-senha", settings)


def test_demo_password_count_never_zero_when_pwned():
    """Achado low: pwned=True com count=0 é contraditório; count deve ser >= 1."""
    # Senha patológica cujo soma de ords = 250000 (múltiplo que zerava o módulo).
    pathological = "z" * 2049 + chr(22)  # 2049*122 + 22 == 250000
    result = demo_data.demo_password_result(pathological)
    if result["pwned"]:
        assert result["count"] >= 1
