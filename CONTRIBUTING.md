# Contributing to OSINT EYE

Thanks for your interest in contributing. This guide covers everything you need to open a useful issue or land a clean pull request. For what the tool does, see the [README](README.md); for the changelog, see [CHANGELOG.md](CHANGELOG.md).

## What you need

- Python **3.10 or newer** (3.10, 3.11 and 3.12 are tested in CI)
- `make` (optional but recommended — every command below has a Makefile shortcut)
- `docker` (only if you want to build/run the container)
- No API keys required: every source that would need one is optional and silently skipped without it. Do not introduce features that hard-require a key.

## Development setup

```bash
make install        # creates venv/, installs deps + the osint-eye entry point
make test           # full offline suite (pytest)
make lint           # ruff gate (same as CI)
make coverage       # suite with coverage report
make docker         # image build + --help smoke test
```

Optional but recommended — git hooks that catch trailing whitespace, missing
newlines at EOF and syntax errors before you commit:

```bash
pip install pre-commit
pre-commit install
```

Manual equivalent of `make install`, if you prefer:

```bash
python -m venv venv && . venv/bin/activate
pip install -e . pytest
```

## Ground rules

These keep the project fast to audit and safe to run. They are enforced in review.

1. **Tests are 100% offline.** No test may hit the network, require nmap or require Ollama. Use pytest fixtures, `monkeypatch`, or recorded responses. If you need a fake service, build it on `localhost` inside the test.
2. **Manual testing only against `example.com`, `localhost` or fixtures.** Never scan third-party domains, IPs or accounts while developing, debugging or capturing screenshots. OSINT EYE is an authorized-recon tool; we hold contributors to that standard too.
3. **Standard library first.** New dependencies need a justification in the commit/PR, must come from the official PyPI registry, and must be added to `requirements.txt` (or the matching `[extras]` group in `pyproject.toml` if optional) in the same change.
4. **Conventional Commits.** `feat(dns): ...`, `fix(dashboard): ...`, `docs: ...`, `test: ...`, `chore: ...`.
5. **User-visible changes get a changelog line.** Add one entry under `## [Unreleased]` in `CHANGELOG.md` in the same PR.
6. **No secrets, no personal data.** Don't commit API keys, tokens, scan results against real targets, or screenshots of anything you don't own.
7. **Keep the docs honest.** If your change alters flags, exit codes, module names or the directory layout, update `README.md` / `docs/USAGE.md` in the same PR.

## Pull request checklist

- [ ] `make test` passes locally (the full offline suite)
- [ ] `python -m compileall -q osint_eye.py core graph ai modules ui reporting tests` is clean
- [ ] `make lint` passes
- [ ] New tests are offline and cover the change
- [ ] `CHANGELOG.md` has a line under `## [Unreleased]` (if user-visible)
- [ ] Docs updated when flags/behavior/layout changed
- [ ] No real third-party data, secrets or keys in the diff

## Reporting bugs

Open a [bug report](.github/ISSUE_TEMPLATE/bug_report.yml). Reproduce against `example.com` or `localhost` and paste the **full command** you ran plus the relevant output. If the bug only reproduces against a real target, describe the trigger pattern without including the target's identity.

## Suggesting features

Open a [feature request](.github/ISSUE_TEMPLATE/feature_request.yml). Explain the recon problem you are trying to solve first — implementation details come second. Mention explicitly if the idea requires an API key or external service: features that work with zero configuration are preferred.

## Security issues

Please do **not** open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
