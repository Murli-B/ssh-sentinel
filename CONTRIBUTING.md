# Contributing

Thanks for helping improve SSH Sentinel. It is intentionally a small, defensive log-analysis project.

## Before opening a change

- Keep the tool read-only and offline by default.
- Keep detection rules explainable and document any new assumptions.
- Do not commit real authentication logs, credentials, private IP inventories, or personal data. Use synthetic examples or redact them fully.
- Keep the runtime dependency list empty unless a dependency is essential and clearly justified.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
ssh-sentinel examples/sample_auth.log
```

Please include tests for parsing or detection-rule changes. Use the demo log as a format reference, not as production telemetry.
