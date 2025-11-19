.PHONY: install
install: ## Install the virtual environment
	@echo "Creating virtual environment using uv"
	@uv sync

.PHONY: check
check: ## Run code quality tools
	@echo "Checking lock file consistency with 'pyproject.toml'"
	@uv lock --locked
	@echo "Running ruff to lint code"
	@uv run ruff check src tests --fix
	@echo "Running black to format code"
	@uv run black src tests
	@echo "Static type checking: Running mypy"
	@uv run mypy src tests

.PHONY: check-no-fix
check-no-fix: ## Run code quality tools without fixing issues
	@echo "Checking lock file consistency with 'pyproject.toml'"
	@uv lock --check --offline
	@echo "Running ruff to lint code"
	@uv run ruff check src tests
	@echo "Running black to format code"
	@uv run black src tests --check
	@echo "Static type checking: Running mypy"
	@uv run mypy src tests

.PHONY: test
test: ## Test the code with pytest
	@echo "Testing code: Running pytest"
	@uv run pytest tests --disable-warnings -v

.PHONY: run
run: ## Run locust load test
	@echo "Running locust load test"
	@uv run locust -f src/locust_pkg --headless --autostart --run-time 1m TestUser

.PHONY: build
build: clean-build ## Create requirements.txt file in /dist
	@echo "Creating requirements.txt in /dist"
	@mkdir -p dist
	@uv export --no-dev --no-hashes -o dist/requirements.txt
	@echo "Copying wheel files to /dist"
	@cp wheels/* dist/ 2>/dev/null || true
	@echo "Updating requirements.txt to remove wheels folder path"
	@sed -i 's|./wheels/|./|g' dist/requirements.txt

.PHONY: wheel
wheel: ## Build wheel file using uv build
	@echo "Creating wheel file with uv build"
	@uv build --wheel

.PHONY: clean-build
clean-build: ## Clean build artifacts
	@echo "Removing build artifacts"
	@uv run python -c "import shutil; import os; shutil.rmtree('dist') if os.path.exists('dist') else None"

.PHONY: help
help:
	@uv run python -c "import re; \
	[[print(f'\033[36m{m[0]:<20}\033[0m {m[1]}') for m in re.findall(r'^([a-zA-Z_-]+):.*?## (.*)$$', open(makefile).read(), re.M)] for makefile in ('$(MAKEFILE_LIST)').strip().split()]"

.DEFAULT_GOAL := help
