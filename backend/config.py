"""Configuração central da aplicação, carregada de variáveis de ambiente/.env."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações da aplicação.

    Todos os campos têm padrões seguros: a app roda sem nenhuma chave,
    apoiando-se em fontes gratuitas e, opcionalmente, no modo demonstração.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Have I Been Pwned (opcional — só é usado se a chave estiver presente).
    hibp_api_key: str | None = None
    hibp_user_agent: str = "DarkChecker-Academic-Project"

    # Fontes gratuitas de e-mail (podem ser desativadas se a API mudar/instabilizar).
    xposedornot_enabled: bool = True
    leakcheck_enabled: bool = True

    # Comportamento de fallback e rede.
    demo_fallback: bool = True
    http_timeout: float = 10.0

    @property
    def hibp_enabled(self) -> bool:
        """Indica se a consulta paga de e-mail no HIBP está habilitada."""
        return bool(self.hibp_api_key)


@lru_cache
def get_settings() -> Settings:
    """Retorna as configurações (cacheadas) da aplicação."""
    return Settings()
