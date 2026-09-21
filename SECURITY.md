# Security Policy

LogHawk is a defensive tool that reads log files. This document covers what it
does with your data, what it deliberately does not do, and how to report a
problem.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead — **Security → Report a vulnerability**
on this repository — or contact the maintainer directly through the profile at
[@Cyb3r-Abdullah](https://github.com/Cyb3r-Abdullah).

Please include the affected version, reproduction steps, and what an attacker
gains. I will acknowledge within 72 hours and aim to have a fix or a clear
decision within 14 days. I will credit you in the changelog unless you ask me
not to.

## Threat model

LogHawk parses untrusted input by design: log files are written by whatever
touched the system, including an attacker. The parsing layer is built with that
in mind.

**What the code does to stay safe**

- **Parsers never execute anything.** They are pure regex and `json.loads`; no
  `eval`, no `exec`, no shell, no deserialisation of pickles.
- **A malformed line can never abort a scan.** Every line is parsed inside a
  `try/except` and skipped on failure, so a crafted log entry cannot deny
  analysis of the rest of the file.
- **A failing rule cannot blind the engine.** Detections run isolated; an
  exception is recorded in `result.errors` and the remaining rules still run.
- **No log-derived value ever reaches SQL as text.** Filters are assembled from
  `?` placeholders only and every value is bound separately by sqlite3, so a
  hostname or username lifted from a log cannot alter a statement.
- **Output is escaped.** Evidence lines are rendered through HTML escaping in
  the dashboard, so a log line containing markup cannot inject script.
- **No outbound network calls.** No HTTP client is imported anywhere in the
  package — `urllib.parse` appears only to URL-decode request paths before
  signature matching. Geolocation reads a bundled offline table, so the tool
  never phones home and needs no API keys.

**Known limitations, stated plainly**

- **The API has no authentication.** It is intended for `127.0.0.1` during
  analysis. Do not expose it to a network without putting authentication and
  TLS in front of it.
- **`/api/scan` reads server-side paths supplied by the caller.** Combined with
  the point above, anyone who can reach the API can ask it to read files the
  process can read. Bind to localhost.
- **Uploads are capped at 25 MB** but are otherwise processed as supplied.
- This is a portfolio and learning project. It has not been through an external
  security review or a production deployment.

## Handling your log data

Logs are sensitive. LogHawk is built so that using it does not leak them.

- Everything runs locally. Nothing is transmitted anywhere.
- Alerts are stored in a local SQLite file, ignored by git.
- The repository's `.gitignore` blocks `*.log`, `*.db`, and generated reports,
  so scanning real logs inside a clone cannot accidentally commit them.
- The bundled sample logs under `samples/` are **synthetic**, produced by
  `samples/generate_samples.py`. They contain no real systems or people.
