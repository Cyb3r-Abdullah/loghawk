# Contributing to LogHawk

The architecture exists to make two things easy: adding a detection rule, and
adding a log source. Neither should require touching anything else.

## Getting set up

```bash
git clone https://github.com/Cyb3r-Abdullah/loghawk.git
cd loghawk
python run_tests.py          # no dependencies needed
```

The engine, parsers, scoring, storage and reporting are standard library only.
Install `requirements.txt` solely if you are working on the dashboard.

## Adding a detection rule

1. Subclass `BaseDetection` in the fitting `loghawk/detections/` module.
2. Set `rule_id`, `title`, `description`, `base_score`, `max_score`, `mitre`
   and `recommendation`.
3. Implement `run(events)` and yield alerts via `self.make_alert(...)`.
4. Register the class in `loghawk/detections/__init__.py` (import it and append
   it to `ALL_DETECTIONS`).
5. Regenerate the catalog: `python docs/generate_catalog.py > docs/DETECTIONS.md`

**Every rule needs two tests, not one.** One proving it fires on the attack it
was written for, and one proving it stays silent on benign activity that looks
similar. The second is the one that matters — see `tests/test_detections.py`
for the pattern.

Pick `max_score` deliberately. It encodes how serious the rule can ever be:
an *attempt* must never outrank a *confirmed* compromise in the triage queue.

## Adding a log source

1. Subclass `BaseParser` in `loghawk/parsers/`.
2. Implement `sniff(sample_lines)` — cheap confidence score, 0.0 to 1.0.
3. Implement `parse_line(line, line_no)` — return an `Event`, or `None` to skip.
4. Register it in `available_parsers()` in `loghawk/parsers/__init__.py`.

Emit the normalised `Event` and every existing rule works on your source
immediately. Never let a malformed line raise; return `None` instead.

## Style

- Python 3.10+, `from __future__ import annotations` at the top of each module.
- Type hints on public functions.
- Comments explain *why*, not *what*. If a threshold or a score ceiling is a
  judgement call, say what the judgement was.
- No third-party imports outside `loghawk/api.py`.

## Before opening a pull request

```bash
python run_tests.py
python -m loghawk scan samples --year 2026 --no-color
```

Both must pass. CI runs them on Python 3.10, 3.11 and 3.12.
