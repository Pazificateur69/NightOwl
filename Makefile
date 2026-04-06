.PHONY: install dev test lint run dashboard clean docker bench-up bench-down bench-status bench-results bench-run-dvwa bench-run-juice-shop bench-run-webgoat bench-run-nightowl-lab bench-run-cors-lab bench-run-all bench-preflight bench-summary

install:
	python -m pip install -e .

full:
	python -m pip install -e ".[full]"

dev:
	python -m pip install -e ".[dev,full]"

test:
	python -m pytest tests/ -v

lint:
	ruff check nightowl/
	ruff format nightowl/

run:
	nightowl --help

recon:
	nightowl recon $(TARGET) --full

scan-web:
	nightowl scan web $(TARGET) --all

dashboard:
	nightowl dashboard --port 8080

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info .pytest_cache nightowl.db

docker:
	docker-compose -f docker/docker-compose.yml up --build

bench-up:
	@if command -v docker >/dev/null 2>&1; then \
		docker compose -f docker/docker-compose.yml --profile benchmarks up -d dvwa juice-shop webgoat nightowl-lab cors-lab; \
	else \
		echo "docker not found. Install Docker Desktop or run benchmarks against an existing local target."; \
		exit 1; \
	fi

bench-down:
	@if command -v docker >/dev/null 2>&1; then \
		docker compose -f docker/docker-compose.yml --profile benchmarks down; \
	else \
		echo "docker not found. Nothing to stop."; \
		exit 1; \
	fi

bench-status:
	@if command -v docker >/dev/null 2>&1; then \
		docker compose -f docker/docker-compose.yml --profile benchmarks ps; \
	else \
		echo "docker not found. Benchmark lab is unavailable on this machine."; \
		exit 1; \
	fi

bench-results:
	@echo "Benchmark workflow documented in benchmarks/README.md"

bench-preflight:
	-.venv/bin/python -m benchmarks.runner dvwa
	-.venv/bin/python -m benchmarks.runner juice-shop
	-.venv/bin/python -m benchmarks.runner webgoat
	-.venv/bin/python -m benchmarks.runner nightowl-lab
	-.venv/bin/python -m benchmarks.runner cors-lab

bench-run-dvwa:
	.venv/bin/python -m benchmarks.runner dvwa

bench-run-juice-shop:
	.venv/bin/python -m benchmarks.runner juice-shop

bench-run-webgoat:
	.venv/bin/python -m benchmarks.runner webgoat

bench-run-nightowl-lab:
	.venv/bin/python -m benchmarks.runner nightowl-lab

bench-run-cors-lab:
	.venv/bin/python -m benchmarks.runner cors-lab

bench-run-all:
	.venv/bin/python -m benchmarks.runner dvwa
	.venv/bin/python -m benchmarks.runner juice-shop
	.venv/bin/python -m benchmarks.runner webgoat
	.venv/bin/python -m benchmarks.runner nightowl-lab
	.venv/bin/python -m benchmarks.runner cors-lab

bench-summary:
	.venv/bin/python -m benchmarks.summary
