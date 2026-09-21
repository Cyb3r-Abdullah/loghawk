## What this changes

<!-- One or two sentences. -->

## Type

- [ ] New detection rule
- [ ] New log source parser
- [ ] Bug fix
- [ ] False-positive reduction
- [ ] Documentation
- [ ] Other

## Checklist

- [ ] `python run_tests.py` passes
- [ ] `python -m loghawk scan samples --year 2026 --no-color` still works
- [ ] No third-party imports added outside `loghawk/api.py`

### If this adds or changes a detection rule

- [ ] A test proving it **fires** on the attack it targets
- [ ] A test proving it **stays silent** on benign activity that looks similar
- [ ] `max_score` chosen deliberately — an *attempt* must not outrank a
      *confirmed* compromise in the queue
- [ ] Mapped to a MITRE ATT&CK technique
- [ ] `python docs/generate_catalog.py > docs/DETECTIONS.md` re-run

## Notes for the reviewer

<!-- Anything you are unsure about, or a judgement call worth a second opinion. -->
