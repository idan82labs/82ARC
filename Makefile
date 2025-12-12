.PHONY: install dev run test lint fmt check docker-build docker-run clean

# Install dependencies
install:
	pip install --upgrade pip
	pip install -e ".[dev]"

# Run development server with hot reload
dev:
	uvicorn arc_solver.main:app --reload --host 0.0.0.0 --port 8000

# Run production server
run:
	uvicorn arc_solver.main:app --host 0.0.0.0 --port 8000

# Run CLI
cli:
	python -m arc_solver.cli

# Run component tests
test:
	python -m arc_solver.cli test-components

# Run pytest
pytest:
	pytest -v tests/

# Check configuration
check:
	python -m arc_solver.cli check

# Lint code
lint:
	black --check arc_solver
	isort --check-only arc_solver

# Format code
fmt:
	black arc_solver
	isort arc_solver

# Build Docker image
docker-build:
	docker build -t arc-solver-unified .

# Run Docker container
docker-run:
	docker-compose up app

# Run Docker development
docker-dev:
	docker-compose up dev

# Solve a sample task
sample:
	python -m arc_solver.cli solve --sample horizontal_flip

# List sample tasks
samples:
	python -m arc_solver.cli list-samples

# Clean up
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache *.egg-info build dist
