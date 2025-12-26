FROM python:3.12-slim

RUN useradd -m -u 10001 appuser

WORKDIR /app

RUN apt-get update              && apt-get install -y --no-install-recommends ca-certificates whois              && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md requirements.txt requirements-dev.txt /app/
COPY bounty_hive /app/bounty_hive
COPY policy_overrides.json /app/policy_overrides.json
COPY docs /app/docs

RUN python -m pip install --upgrade pip              && pip install -e .

USER appuser

ENTRYPOINT ["python", "-m", "bounty_hive"]
CMD ["--help"]
