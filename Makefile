.PHONY: setup test lint type audit sbom gui run

setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt && pip install -e .

test:
	. .venv/bin/activate && pytest -q

lint:
	. .venv/bin/activate && ruff check bounty_hive

type:
	. .venv/bin/activate && mypy bounty_hive

audit:
	. .venv/bin/activate && pip-audit

sbom:
	. .venv/bin/activate && cyclonedx-py -o sbom.json

gui:
	. .venv/bin/activate && python -m bounty_hive gui --user local --role lead

run:
	. .venv/bin/activate && python -m bounty_hive run "https://example.com" --dry-run --user local --role lead
