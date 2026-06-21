# Hackathon Requirement-Aligned Dataset

This generated dataset is designed for the Identity Sprawl and Privileged Access Abuse Detection challenge.

## Contents

| File | Rows | Purpose |
| --- | ---: | --- |
| `employees.csv` | 350 | Canonical identity records across departments and lifecycle states |
| `platform_accounts.csv` | 1750 | AD, AWS, Okta, Salesforce, and GitHub account snapshots |
| `role_assignments.csv` | 1750 | Direct platform role assignments |
| `group_membership.csv` | 769 | Group memberships, including groups that grant inherited privilege |
| `audit_events.csv` | 8000 | Dashboard-compatible audit telemetry |
| `audit_events_enriched.csv` | 8000 | Audit telemetry with `source_ip` and `ip_type` for challenge documentation |
| `employee_role_history.csv` | 100 | Recent role changes and privilege spikes |
| `api_tokens.csv` | 542 | API token age data |
| `offboarding_records.csv` | 50 | Offboarding gaps for lifecycle testing |
| `risk_findings.csv` | 162 | Ground-truth labels for demo validation |

## Anomaly Mix

| Scenario | Count | Percent |
| --- | ---: | ---: |
| Offboarding/orphaned account gaps | 50 | 14.3% |
| Cross-platform admin | 40 | 11.4% |
| Privilege spike | 25 | 7.1% |
| Token abuse | 17 | 4.9% |
| Legitimate privileged users | 70 | 20.0% |

## Load Into The App

From `C:\hackathon`:

```powershell
$env:IDENTITY_DATASET_DIR='dataset_hackathon_full'
python src\ingest.py
python src\risk_engine.py
python src\graph_engine.py
python app.py
```

Open `http://127.0.0.1:8080`.
