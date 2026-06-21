import csv
import random
import shutil
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dataset_hackathon_full"
ZIP_BASE = ROOT / "identity_sprawl_hackathon_full"
SEED = 20260620

random.seed(SEED)

DEPARTMENTS = ["Engineering", "Security", "Finance", "Risk", "Operations", "HR", "Data"]
PLATFORMS = ["AD", "AWS", "Okta", "Salesforce", "GitHub"]
BASE_ROLES = {
    "AD": ["User", "HelpdeskOperator", "DomainAdmin"],
    "AWS": ["ReadOnlyAccess", "Developer", "PowerUser", "AdministratorAccess"],
    "Okta": ["User", "AppAdmin", "SuperAdmin"],
    "Salesforce": ["StandardUser", "SalesOps", "SystemAdministrator"],
    "GitHub": ["Reader", "Developer", "RepositoryAdmin", "OrgOwner"],
}
ADMIN_ROLES = {
    "AD": "DomainAdmin",
    "AWS": "AdministratorAccess",
    "Okta": "SuperAdmin",
    "Salesforce": "SystemAdministrator",
    "GitHub": "OrgOwner",
}
GROUPS = [
    "SecurityAdmins",
    "CloudOps",
    "DevOps",
    "FinanceUsers",
    "RiskTeam",
    "HR-Privileged",
    "DataPlatform",
    "Contractors",
]
GROUP_PRIVILEGES = {
    "SecurityAdmins": ("AD", "DomainAdmin"),
    "CloudOps": ("AWS", "AdministratorAccess"),
    "DevOps": ("GitHub", "RepositoryAdmin"),
}
EVENTS = ["Login", "Logout", "TokenUse", "RoleChange", "S3Access", "RepoAccess", "TicketUpdate", "DataExport"]


def write_csv(name, fieldnames, rows):
    path = OUT / f"{name}.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_dataset_readme(counts):
    content = f"""# Hackathon Requirement-Aligned Dataset

This generated dataset is designed for the Identity Sprawl and Privileged Access Abuse Detection challenge.

## Contents

| File | Rows | Purpose |
| --- | ---: | --- |
| `employees.csv` | {counts['employees']} | Canonical identity records across departments and lifecycle states |
| `platform_accounts.csv` | {counts['platform_accounts']} | AD, AWS, Okta, Salesforce, and GitHub account snapshots |
| `role_assignments.csv` | {counts['role_assignments']} | Direct platform role assignments |
| `group_membership.csv` | {counts['group_membership']} | Group memberships, including groups that grant inherited privilege |
| `audit_events.csv` | {counts['audit_events']} | Dashboard-compatible audit telemetry |
| `audit_events_enriched.csv` | {counts['audit_events_enriched']} | Audit telemetry with `source_ip` and `ip_type` for challenge documentation |
| `employee_role_history.csv` | {counts['employee_role_history']} | Recent role changes and privilege spikes |
| `api_tokens.csv` | {counts['api_tokens']} | API token age data |
| `offboarding_records.csv` | {counts['offboarding_records']} | Offboarding gaps for lifecycle testing |
| `risk_findings.csv` | {counts['risk_findings']} | Ground-truth labels for demo validation |

## Anomaly Mix

| Scenario | Count | Percent |
| --- | ---: | ---: |
| Offboarding/orphaned account gaps | 50 | 14.3% |
| Cross-platform admin | 40 | 11.4% |
| Privilege spike | 25 | 7.1% |
| Token abuse | 17 | 4.9% |
| Legitimate privileged users | 70 | 20.0% |

## Load Into The App

From `C:\\hackathon`:

```powershell
$env:IDENTITY_DATASET_DIR='dataset_hackathon_full'
python src\\ingest.py
python src\\risk_engine.py
python src\\graph_engine.py
python app.py
```

Open `http://127.0.0.1:8080`.
"""
    (OUT / "README.md").write_text(content, encoding="utf-8")


def employee_id(index):
    return f"EMP{index:04d}"


def account_id(platform, index):
    prefix = {"AD": "AD", "AWS": "AWS", "Okta": "OK", "Salesforce": "SF", "GitHub": "GH"}[platform]
    return f"{prefix}{index:04d}"


def username(platform, index):
    if platform == "AD":
        return f"user{index}.ad"
    if platform == "AWS":
        return f"u{index}_aws"
    if platform == "Okta":
        return f"user{index}@corp.com"
    if platform == "Salesforce":
        return f"sf_user{index}"
    return f"gh{index}"


def random_ip(kind):
    if kind == "corp":
        return f"10.{random.randint(0, 30)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    if kind == "vpn":
        return f"172.16.{random.randint(0, 40)}.{random.randint(1, 254)}"
    if kind == "suspicious":
        return f"203.0.113.{random.randint(1, 254)}"
    return f"198.51.100.{random.randint(1, 254)}"


def add_finding(findings, employee, finding, severity, score):
    findings.append(
        {
            "employee_id": employee,
            "finding": finding,
            "severity": severity,
            "risk_score": score,
        }
    )


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    total = 350
    terminated = set(range(1, 76))
    offboarding_gap = set(range(1, 51))
    cross_platform_admin = set(range(76, 116))
    privilege_spike = set(range(116, 141))
    token_abuse = set(range(141, 158))
    legitimate_privileged = set(range(158, 228))
    dormant_admin = set(range(228, 258))

    employees = []
    accounts = []
    roles = []
    groups = []
    events = []
    enriched_events = []
    history = []
    tokens = []
    offboarding = []
    findings = []

    base_time = datetime(2026, 6, 1, 9, 0, 0)

    for i in range(1, total + 1):
        eid = employee_id(i)
        status = "Terminated" if i in terminated else "Active"
        termination_date = (datetime(2026, 2, 1) + timedelta(days=i % 85)).date().isoformat() if status == "Terminated" else ""
        department = DEPARTMENTS[(i - 1) % len(DEPARTMENTS)]
        employees.append(
            {
                "employee_id": eid,
                "employee_name": f"Employee_{i}",
                "department": department,
                "employee_status": status,
                "termination_date": termination_date,
            }
        )

        for platform in PLATFORMS:
            if i in offboarding_gap and platform == "AD":
                account_status = "Disabled"
            elif i in offboarding_gap:
                account_status = "Active"
            elif status == "Terminated":
                account_status = "Disabled"
            else:
                account_status = "Active"

            accounts.append(
                {
                    "account_id": account_id(platform, i),
                    "employee_id": eid,
                    "platform": platform,
                    "username": username(platform, i),
                    "account_status": account_status,
                }
            )

            role = random.choice(BASE_ROLES[platform][:2])
            if i in cross_platform_admin and platform in {"AD", "AWS", "Okta"}:
                role = ADMIN_ROLES[platform]
            elif i in legitimate_privileged and platform in {"AD", "AWS"} and i % 3 == 0:
                role = ADMIN_ROLES[platform]
            elif i in dormant_admin and platform == "AWS":
                role = "AdministratorAccess"
            roles.append({"employee_id": eid, "platform": platform, "role": role})

        member_groups = random.sample(GROUPS, k=random.randint(1, 3))
        if i in cross_platform_admin or i in dormant_admin:
            member_groups.append(random.choice(["SecurityAdmins", "CloudOps", "DevOps"]))
        if i in legitimate_privileged and i % 4 == 0:
            member_groups.append("CloudOps")
        for group_name in sorted(set(member_groups)):
            groups.append({"employee_id": eid, "group_name": group_name})

        token_count = random.randint(1, 2)
        if i in token_abuse:
            token_count = 3
        for token_number in range(token_count):
            age = random.randint(20, 300)
            if i in token_abuse or (i % 11 == 0):
                age = random.randint(366, 720)
            tokens.append(
                {
                    "token_id": f"TOK{i:04d}{token_number + 1}",
                    "employee_id": eid,
                    "token_age_days": age,
                }
            )

        if i in offboarding_gap:
            offboarding.append(
                {
                    "employee_id": eid,
                    "issue": "AD disabled or HR terminated but AWS/Okta/SaaS accounts remain active",
                }
            )
            add_finding(findings, eid, "Offboarding Gap", "HIGH", 82)

        if i in cross_platform_admin:
            add_finding(findings, eid, "Cross Platform Admin", "CRITICAL", 95)

        if i in privilege_spike:
            for n in range(4):
                platform = random.choice(["AWS", "Okta", "GitHub"])
                new_role = ADMIN_ROLES[platform]
                history.append(
                    {
                        "employee_id": eid,
                        "platform": platform,
                        "old_role": "Developer",
                        "new_role": new_role,
                        "change_date": (datetime(2026, 5, 24) + timedelta(days=n)).date().isoformat(),
                    }
                )
            add_finding(findings, eid, "Privilege Spike", "HIGH", 78)

        if i in token_abuse:
            add_finding(findings, eid, "Token Abuse", "HIGH", 76)

        if i in dormant_admin:
            add_finding(findings, eid, "Dormant Admin", "HIGH", 74)

        event_total = random.randint(18, 28)
        if i in token_abuse:
            event_total += 12
        if i in privilege_spike:
            event_total += 8
        if i in dormant_admin:
            event_total = random.randint(1, 5)

        for _ in range(event_total):
            platform = random.choice(PLATFORMS)
            event_type = random.choice(EVENTS)
            if i in token_abuse and random.random() < 0.45:
                event_type = "TokenUse"
            if i in privilege_spike and random.random() < 0.35:
                event_type = "RoleChange"
            if i in offboarding_gap and random.random() < 0.25:
                event_type = random.choice(["S3Access", "DataExport", "TokenUse"])
            if i in dormant_admin:
                event_time = datetime(2026, 1, 1) + timedelta(days=random.randint(0, 20), hours=random.randint(0, 23))
            else:
                event_time = base_time - timedelta(days=random.randint(0, 160), hours=random.randint(0, 23), minutes=random.randint(0, 59))
            ip_kind = "corp"
            if event_type == "TokenUse" and (i in token_abuse or random.random() < 0.05):
                ip_kind = "suspicious"
            elif random.random() < 0.15:
                ip_kind = "vpn"
            event_id = f"EV{len(events) + 1:06d}"
            event_row = {
                "event_id": event_id,
                "employee_id": eid,
                "platform": platform,
                "event_type": event_type,
                "timestamp": event_time.isoformat(timespec="minutes"),
            }
            events.append(event_row)
            enriched = dict(event_row)
            enriched["source_ip"] = random_ip(ip_kind)
            enriched["ip_type"] = ip_kind
            enriched_events.append(enriched)

    while len(events) < 8000:
        i = random.randint(1, total)
        eid = employee_id(i)
        platform = random.choice(PLATFORMS)
        event_type = random.choice(EVENTS)
        event_time = base_time - timedelta(days=random.randint(0, 160), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        event_id = f"EV{len(events) + 1:06d}"
        event_row = {
            "event_id": event_id,
            "employee_id": eid,
            "platform": platform,
            "event_type": event_type,
            "timestamp": event_time.isoformat(timespec="minutes"),
        }
        events.append(event_row)
        enriched = dict(event_row)
        enriched["source_ip"] = random_ip("corp")
        enriched["ip_type"] = "corp"
        enriched_events.append(enriched)

    write_csv("employees", ["employee_id", "employee_name", "department", "employee_status", "termination_date"], employees)
    write_csv("platform_accounts", ["account_id", "employee_id", "platform", "username", "account_status"], accounts)
    write_csv("role_assignments", ["employee_id", "platform", "role"], roles)
    write_csv("group_membership", ["employee_id", "group_name"], groups)
    write_csv("audit_events", ["event_id", "employee_id", "platform", "event_type", "timestamp"], events)
    write_csv("audit_events_enriched", ["event_id", "employee_id", "platform", "event_type", "timestamp", "source_ip", "ip_type"], enriched_events)
    write_csv("employee_role_history", ["employee_id", "platform", "old_role", "new_role", "change_date"], history)
    write_csv("api_tokens", ["token_id", "employee_id", "token_age_days"], tokens)
    write_csv("offboarding_records", ["employee_id", "issue"], offboarding)
    write_csv("risk_findings", ["employee_id", "finding", "severity", "risk_score"], findings)

    counts = {
        "employees": len(employees),
        "platform_accounts": len(accounts),
        "role_assignments": len(roles),
        "group_membership": len(groups),
        "audit_events": len(events),
        "audit_events_enriched": len(enriched_events),
        "employee_role_history": len(history),
        "api_tokens": len(tokens),
        "offboarding_records": len(offboarding),
        "risk_findings": len(findings),
    }
    write_dataset_readme(counts)

    shutil.make_archive(str(ZIP_BASE), "zip", OUT)

    print(f"dataset: {OUT}")
    print(f"zip: {ZIP_BASE.with_suffix('.zip')}")
    print(f"employees: {len(employees)}")
    print(f"platform_accounts: {len(accounts)}")
    print(f"role_assignments: {len(roles)}")
    print(f"group_membership: {len(groups)}")
    print(f"audit_events: {len(events)}")
    print(f"audit_events_enriched: {len(enriched_events)}")
    print(f"employee_role_history: {len(history)}")
    print(f"api_tokens: {len(tokens)}")
    print(f"offboarding_records: {len(offboarding)}")
    print(f"risk_findings: {len(findings)}")


if __name__ == "__main__":
    main()
