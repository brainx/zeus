# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx

.PHONY: install-dev test coverage check build wheel-smoke release-check doctor run-api strict-doctor repo-check verify-real-hermes fresh-vps-verify clean clean-vps

install-dev:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install -e ".[dev]"

test:
	sh scripts/test.sh

coverage:
	coverage erase
	coverage run -m unittest discover -s tests
	coverage report

check:
	sh scripts/test.sh
	coverage erase
	coverage run -m unittest discover -s tests
	coverage report
	sh scripts/repo_check.sh
	ruff format --check .
	ruff check .
	mypy zeus
	bandit -r zeus

build:
	python -m build
	twine check dist/*

wheel-smoke:
	sh scripts/wheel_smoke.sh

release-check:
	sh scripts/test.sh
	coverage erase
	coverage run -m unittest discover -s tests
	coverage report
	sh scripts/repo_check.sh
	ruff format --check .
	ruff check .
	mypy zeus
	bandit -r zeus
	shellcheck scripts/*.sh
	rm -rf dist
	python -m build
	ZEUS_WHEEL_SMOKE_BUILD=0 sh scripts/wheel_smoke.sh
	twine check dist/*
	sh scripts/generate_checksums.sh dist

doctor:
	python3 -B -m zeus.cli doctor --json

run-api:
	ZEUS_API_KEY=change-me sh scripts/start.sh

strict-doctor:
	python3 -B -m zeus.cli doctor --strict --json

repo-check:
	sh scripts/repo_check.sh

verify-real-hermes:
	sh scripts/verify_real_hermes.sh

fresh-vps-verify:
	bash scripts/fresh_vps_verify.sh

clean:
	rm -rf .zeus .zeus-real-hermes-check zeus/__pycache__ tests/__pycache__

clean-vps:
	rm -rf .zeus .zeus-real-hermes-check .zeus-vps-multi .zeus-vps-api .tmp/fresh-vps-verify
