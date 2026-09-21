# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-21

First public release.

### Added

- **Ten detection rules**, each mapped to MITRE ATT&CK: SSH brute force
  (LH-001), password spraying (LH-002), account enumeration (LH-003),
  successful login after a failed-login burst (LH-004), impossible travel
  (LH-005), off-hours privileged logon (LH-006), suspicious sudo activity
  (LH-007), privileged account change (LH-008), web exploitation (LH-009),
  automated web scanning (LH-010).
- **Three parsers** with format auto-detection: Linux `auth.log`, nginx/Apache
  combined access logs, Windows Security events exported as JSON.
- **Layered scoring** — a base score plus context modifiers, clamped to a
  per-rule ceiling so an attempt can never outrank a confirmed compromise.
- **Burst merging** so one attack yields one alert rather than one per event.
- **Stable alert fingerprints**, making rescans idempotent and preserving
  analyst triage state across runs.
- **SQLite persistence** with a triage workflow.
- **CLI** with console, JSON, CSV and Markdown output, rule include/exclude,
  and a `--fail-on` exit code for CI gating.
- **FastAPI service** and a single-file SOC dashboard with a 3D attack globe
  built from live enrichment data.
- **Windows launchers** (`run-dashboard.bat`, `loghawk.bat`) that bootstrap a
  virtual environment and detect a missing Python.
- **105 tests**, roughly half of which assert that benign activity produces
  *no* alert.
- Offline IP enrichment: private-range classification, coarse geolocation and
  a static threat-feed netblock list — no API keys, no outbound requests.

### Known limitations

- Detections are stateless per scan; there is no per-entity baseline of normal
  behaviour, so impossible travel cannot learn a genuine commuter.
- Log files are read in batches rather than tailed live.
- Geolocation uses a small bundled demo table, not a full GeoIP database.
- Windows events are read from a JSON export rather than EVTX directly.
