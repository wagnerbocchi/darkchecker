#!/usr/bin/env bash
# DarkChecker — script de execução.
# Cria o ambiente virtual (se necessário), instala as dependências e sobe a app.
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"

# 1. Ambiente virtual
if [ ! -d ".venv" ]; then
  echo "==> Criando ambiente virtual (.venv)…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# 2. Dependências
echo "==> Instalando dependências…"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# 3. Arquivo de configuração
if [ ! -f ".env" ]; then
  echo "==> Criando .env a partir de .env.example (a app funciona sem chaves)."
  cp .env.example .env
fi

# 4. Sobe o servidor
echo ""
echo "==> DarkChecker rodando em: http://${HOST}:${PORT}"
echo "    (Ctrl+C para encerrar)"
echo ""
exec uvicorn backend.main:app --host "${HOST}" --port "${PORT}" --reload
