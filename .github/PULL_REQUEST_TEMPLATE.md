## Summary

<!-- What does this PR change and why? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New feature (module, flag, export, dashboard)
- [ ] Refactor (no behavior change)
- [ ] Docs only
- [ ] Tests only

## Checklist

- [ ] `make test` passes locally (full offline suite)
- [ ] `python -m compileall -q osint_eye.py core graph ai modules ui reporting tests` is clean
- [ ] `make lint` passes
- [ ] New tests are **100% offline** (fixtures / monkeypatch / localhost)
- [ ] Manual testing was done only against `example.com`, `localhost` or fixtures
- [ ] `CHANGELOG.md` got a line under `## [Unreleased]` (if user-visible)
- [ ] Docs (`README.md`, `docs/USAGE.md`) updated if flags, exit codes or layout changed
- [ ] No secrets, keys or real third-party data in the diff

## Evidence

<!-- Paste the command you ran (example.com/localhost) and the relevant output, or a screenshot of your own dashboard. -->
