# Atajos de desarrollo — OSINT EYE
# Espejo de PROTOCOLO §0 y del CI (.github/workflows/ci.yml).
# Los tests son 100 % offline: nunca requieren red, nmap ni Ollama.

PYTHON ?= python3

.PHONY: help install test coverage lint docker clean

help: ## Muestra los objetivos disponibles
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Crea venv e instala dependencias + paquete editable (paridad 1:1 con requirements.txt)
	$(PYTHON) -m venv venv
	. venv/bin/activate && pip install --upgrade pip && pip install -e . pytest

test: ## Suite offline completa
	. venv/bin/activate && PYTHONPATH=. pytest -q tests/

coverage: ## Suite con cobertura (term-missing + coverage.xml)
	. venv/bin/activate && pip install -q pytest-cov && PYTHONPATH=. pytest -q tests/ --cov=core --cov=modules --cov=graph --cov=reporting --cov=ui --cov=ai --cov=osint_eye --cov-report=term-missing --cov-report=xml

lint: ## Puerta ruff actual (E9), la misma de CI
	. venv/bin/activate && pip install -q ruff && ruff check --select E9 --no-fix .

docker: ## Build de la imagen + smoke test --help
	docker build -t osint-eye:local .
	docker run --rm osint-eye:local --help

clean: ## Borra caches y artefactos de build (no toca output/ ni venv/)
	rm -rf .pytest_cache .coverage coverage.xml build dist *.egg-info
