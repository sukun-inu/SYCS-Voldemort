# Contributing

The full guide is in Japanese: **[CONTRIBUTING.ja.md](CONTRIBUTING.ja.md)**.
The codebase, its comments and its commit messages are all written in Japanese.

This page is a summary. Where the two disagree, the Japanese one is authoritative.

## Setup, once

```bash
pip install -r requirements.txt -r requirements-dev.txt

# keep formatting-only commits out of git blame
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

## Workflow

Branch, commit, then `git merge --no-ff` into `main` and push. Commit messages are
written in Japanese and follow one order: **what was happening → why it happened →
how it was fixed → how that was verified.** Do not skip the "why" — it is the part
that stops the same mistake from coming back.

## Tests

`pytest` is not installed. Use `unittest`:

```bash
python -m unittest discover -s tests -t .
```

Every test's docstring explains, in Japanese, *why the test exists* — what breaks in
the product if this stops holding.

**Verify a new test by breaking what it guards.** A coverage number proves nothing:
code that is called but never asserted on still counts as covered. Take a copy of the
production file, change exactly one thing (invert a condition, shift a bound by one,
delete a guard), confirm that only the intended tests fail, then restore it and check
`git status`. A test that keeps passing guards nothing — rewrite it or delete it.

**Before splitting a long function, write the invariant test first — and make it
pass on the *unsplit* code.** The order is the whole point: a test written after the
split is shaped by the split, so it cannot say whether behaviour stayed the same.
Fix what the test pins to the kind of function it is: for assembly (`create_app`, the
`register` family) pin what got registered and in what order; for computation, pin
golden values for fixed inputs; for procedures, pin the sequence of outward effects.
Then break the unsplit code once and confirm the test fails — a test that does not
catch that has not captured the invariant, and carrying it into a refactor is worse
than carrying nothing. When 787 docstrings were added, stripping docstrings from the
AST and diffing proved nothing else had moved; **splitting a function has no such
tool**, so you build one before you start. Three earlier splits, done without one,
left the over-100-line count at 26 → 26: the length only moved.

Tests must not reach the network or a real database. Everything passes without
Postgres. Note that `patch()` on a module attribute does **not** affect FastAPI
`Depends()` — those are bound at import time; use `app.dependency_overrides`.

## Lint, format, types

```bash
python -m ruff check .
python -m black .
python -m mypy -p webapp -p events -p services -p webapp_admin -p commands
```

CI runs all three and fails on any of them.

**Never remove a runtime guard to satisfy the type checker.** This has actually
happened here: `int(result.rowcount or 0)` lost its `or 0` while keeping the
`# type: ignore`, which silenced the checker and dropped the protection at the same
time. When you need to satisfy mypy, you may only: add an annotation, add
`# type: ignore[code]` *with a one-line reason*, bind to a narrowed local, or `cast`.
Never change a condition, a statement order, an exception handler, a default, or a
signature. When in doubt, choose `# type: ignore` — nothing changes at runtime.

Before reaching for `# type: ignore`, look for an equivalent spelling that is not
flagged at all. **Error codes differ between environments** — a `[call-arg]` locally
(Python 3.13) can surface as `[misc]` in CI (3.11), and that has already broken a
build here. A local `Success` from mypy is not proof that CI will pass.

## Thresholds are ceilings, not targets

`fail_under` in `.coveragerc`, `max-complexity` in `pyproject.toml`, the package list
passed to mypy, and `FLOOR_PERCENT` in `tools/check_docstrings.py` all exist to stop
things getting worse. Tighten them whenever you improve the thing they measure.

The docstring floor is at 100, but it counts only whether a docstring is present —
never whether it says anything. A docstring that paraphrases the signature passes.
Green there is not evidence that the "comment the why" rule was followed.

## Handing work to an agent

An agent is filled up by what it reads: one 1,600-line file plus its tests is most of
a sitting. Decide the target before handing it over, rather than asking it to survey
and then decide.

One piece of work per sitting, carried through to the merge — stopping halfway can
leave production code that was edited for a mutation test still edited, which has
happened here. Keep the files it must read closed to that one target. Start from a
clean `git status`. And say the procedure, not just the goal: *write the invariant
test first, make it pass before the split, break it once to prove it bites, then
split and keep it passing.* Handing over only "split this" makes the agent re-derive
the procedure every time.

## CI must never pass vacuously

A check that is present but silently skips is worse than no check at all. That is why
`tools/check_admin_ui.py` is not in CI: without playwright installed it fails to
import, skips, and exits 0 — proving nothing while looking green.
