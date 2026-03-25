.PHONY: install dev test lint run dashboard clean docker

install:
	python -m pip install -e .

full:
	python -m pip install -e ".[full]"

dev:
	python -m pip install -e ".[dev,full]"

test:
	pytest tests/ -v

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
