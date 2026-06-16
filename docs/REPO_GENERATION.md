# Repository Generation Checklist

Use this checklist when turning this workspace into a published repository.

## Required Before First Commit

1. Choose the canonical repository name and remote URL.
2. Update package metadata in `pyproject.toml` if the repository URL, author, or package name changes.
3. Review `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CHANGELOG.md`.
4. Copy `.env.example` only as an example; do not create or commit `.env`.
5. Run:

```bash
sh scripts/test.sh
sh scripts/repo_check.sh
```

6. Confirm no generated runtime state is present:

```bash
find . -maxdepth 3 -name '__pycache__' -o -name '.zeus' -o -name '.tmp'
```

## Required Before Release

Run real-Hermes verification in an environment with Hermes installed:

```bash
sh scripts/verify_real_hermes.sh
```

If gateway startup should be part of the release gate:

```bash
ZEUS_VERIFY_START_GATEWAY=1 sh scripts/verify_real_hermes.sh
```

## Repository Settings

Recommended settings after publishing:

- Enable branch protection for `main`.
- Require CI before merge.
- Enable private vulnerability reporting.
- Add repository topics: `hermes-agent`, `agents`, `orchestration`, `bots`, `automation`.
- Configure a real security contact or advisory workflow before accepting external users.

