.PHONY: help install dev test lint format mypy clean docker-build docker-up

help:
	@echo "Comandos disponíveis:"
	@echo "  make install      - Instala dependências em modo de produção"
	@echo "  make dev          - Instala dependências de desenvolvimento"
	@echo "  make test         - Executa todos os testes com pytest"
	@echo "  make lint         - Executa análise estática com ruff"
	@echo "  make format       - Formata o código com ruff"
	@echo "  make mypy         - Valida tipagem estática"
	@echo "  make clean        - Remove caches e arquivos temporários"
	@echo "  make docker-build - Constrói a imagem Docker"
	@echo "  make docker-up    - Executa o contêiner com compose"

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check .

format:
	ruff format .

mypy:
	mypy src

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +

docker-build:
	docker compose build

docker-up:
	docker compose up -d

