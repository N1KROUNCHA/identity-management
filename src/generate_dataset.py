import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
SEED = 20260620

IDENTITY_COUNT = 350
PLATFORMS = ["AD", "AWS", "Okta", "Salesforce"]
DEPARTMENTS = [
    "Engineering",
    "Security",
    "Finance",
    "Operations",
    "HR",
    "Risk",
    "Data",
]

ROLE_BY_PLATFORM = {
    "AD": ["User", "HelpdeskOperator", "DomainAdmin"],
    "AWS": ["ReadOnlyAccess", "Developer", "AdministratorAccess", "S3FullAccess"],
    "Okta": ["User", "AppAdmin", "SuperAdmin"],
    "Salesforce": ["StandardUser", "ReportManager", "SystemAdministrator"],
}

ADMIN_ROLE_BY_PLATFORM = {
    "AD": "DomainAdmin",
    "AWS": "AdministratorAccess",
    "Okta": "SuperAdmin",
    "Salesforce": "SystemAdministrator",
}

USERNAME_SUFFIX = {
    "AD": "ad",
    "AWS": "aws",
    "Okta": "corp.com",
    "Salesforce": "sf",
}

GROUPS = {
    "SecurityAdmins": ("AD", "DomainAdmin"),
    "CloudOps": ("AWS", "AdministratorAccess"),
    "OktaAdmins": ("Okta", "SuperAdmin"),
    "SalesforceAdmins": ("Salesforce", "SystemAdministrator"),
    "FinanceUsers": (None, None),
    "RiskTeam": (None, None),
    "DataReaders": (None, None),
    "DevOps": (None, None),
}


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def pick_segments(employee_ids):
    random.shuffle(employee_ids)
    segments = {
        "orphaned": employee_ids[0:45],
        "overprivileged": employee_ids[45:80],
        "privilege_escalation": employee_ids[80:104],
        "token_abuse": employee_ids[104:120],
        "legit_high_privilege": employee_ids[120:180],
        "normal": employee_ids[180:350],
    }
    return segments


def username(employee_number, platform):
    if platform == "Okta":
        return f"user{employee_number}@corp.com"
    if platform == "Salesforce":
        return f"sf_user{employee_number}"
    return f"user{employee_number}.{USERNAME_SUFFIX[platform]}"


def build_dataset():
    random.seed(SEED)
    DATASET_DIR.mkdir(parents=True, exist_ok=True)

    employee_ids = [f"EMP{i:04d}" for i in range(1, IDENTITY_COUNT + 1)]
    segments = pick_segments(employee_ids[:])
    segment_by_employee = {
        employee_id: segment
        for segment, ids in segments.items()
        for employee_id in ids
    }

    employees = []
    platform_accounts = []
    role_assignments = []
    group_membership = []
    audit_events = []
    employee_role_history = []
    api_tokens = []
    offboarding_records = []
    risk_findings = []

    base_date = datetime(2026, 6, 1, 9, 0)
    departments_by_employee = {}
    account_seq = {platform: 1 for platform in PLATFORMS}

    for index, employee_id in enumerate(employee_ids, start=1):
        segment = segment_by_employee[employee_id]
        department = DEPARTMENTS[(index + len(segment)) % len(DEPARTMENTS)]
        departments_by_employee[employee_id] = department
        is_terminated = segment == "orphaned" or (segment == "normal" and index % 19 == 0)
        termination_date = ""
        if is_terminated:
            termination_date = (base_date.date() - timedelta(days=20 + index % 80)).isoformat()

        employees.append(
            {
                "employee_id": employee_id,
                "employee_name": f"Employee_{index}",
                "department": department,
                "employee_status": "Terminated" if is_terminated else "Active",
                "termination_date": termination_date,
            }
        )

        for platform in PLATFORMS:
            status = "Active"
            if segment == "orphaned":
                status = "Disabled" if platform == "AD" else "Active"
            elif is_terminated:
                status = "Disabled"
            elif segment == "normal" and platform == "Salesforce" and index % 11 == 0:
                status = "Disabled"

            platform_accounts.append(
                {
                    "account_id": f"{platform[:2].upper()}{account_seq[platform]:04d}",
                    "employee_id": employee_id,
                    "platform": platform,
                    "username": username(index, platform),
                    "account_status": status,
                }
            )
            account_seq[platform] += 1

        direct_admin_platforms = set()
        if segment == "overprivileged":
            direct_admin_platforms = set(random.sample(PLATFORMS, 2 + (index % 2)))
        elif segment == "privilege_escalation":
            direct_admin_platforms = {"AWS"}
        elif segment == "legit_high_privilege":
            direct_admin_platforms = {PLATFORMS[index % len(PLATFORMS)]}
        elif segment == "orphaned" and index % 3 == 0:
            direct_admin_platforms = {"AWS"}

        for platform in PLATFORMS:
            if platform in direct_admin_platforms:
                role = ADMIN_ROLE_BY_PLATFORM[platform]
            else:
                role = random.choice(ROLE_BY_PLATFORM[platform][0:2])
            role_assignments.append(
                {
                    "employee_id": employee_id,
                    "platform": platform,
                    "role": role,
                }
            )

        if segment != "normal":
            if segment == "overprivileged":
                group_name = random.choice(["SecurityAdmins", "CloudOps", "OktaAdmins"])
            elif segment == "privilege_escalation":
                group_name = "CloudOps"
            elif segment == "legit_high_privilege" and index % 2 == 0:
                group_name = random.choice(["SecurityAdmins", "CloudOps", "SalesforceAdmins"])
            else:
                group_name = random.choice(["FinanceUsers", "RiskTeam", "DataReaders", "DevOps"])
            group_membership.append({"employee_id": employee_id, "group_name": group_name})

        if segment == "privilege_escalation":
            change_date = (base_date.date() - timedelta(days=random.randint(0, 6))).isoformat()
            employee_role_history.append(
                {
                    "employee_id": employee_id,
                    "platform": "AWS",
                    "old_role": "Developer",
                    "new_role": "AdministratorAccess",
                    "change_date": change_date,
                }
            )
        elif segment == "legit_high_privilege" and index % 5 == 0:
            change_date = (base_date.date() - timedelta(days=random.randint(3, 20))).isoformat()
            employee_role_history.append(
                {
                    "employee_id": employee_id,
                    "platform": PLATFORMS[index % len(PLATFORMS)],
                    "old_role": "User",
                    "new_role": ADMIN_ROLE_BY_PLATFORM[PLATFORMS[index % len(PLATFORMS)]],
                    "change_date": change_date,
                }
            )

        token_count = 1 if segment not in {"token_abuse", "overprivileged"} else 2
        for token_index in range(token_count):
            if segment == "token_abuse":
                age = random.randint(370, 720)
            elif segment == "overprivileged" and token_index == 1:
                age = random.randint(260, 520)
            else:
                age = random.randint(10, 260)
            api_tokens.append(
                {
                    "token_id": f"TOK{len(api_tokens) + 1:05d}",
                    "employee_id": employee_id,
                    "token_age_days": age,
                }
            )

    offboarding_candidates = segments["orphaned"] + [
        employee["employee_id"]
        for employee in employees
        if employee["employee_status"] == "Terminated"
        and employee["employee_id"] not in segments["orphaned"]
    ]
    for candidate in employee_ids:
        if len(offboarding_candidates) >= 75:
            break
        if candidate not in offboarding_candidates:
            offboarding_candidates.append(candidate)

    for employee_id in offboarding_candidates[:75]:
        segment = segment_by_employee[employee_id]
        issue = "AD disabled but AWS/Okta/Salesforce active"
        if segment != "orphaned":
            issue = "Offboarding review required for stale or disabled platform accounts"
        offboarding_records.append({"employee_id": employee_id, "issue": issue})

    for employee_id in segments["orphaned"]:
        risk_findings.append(
            {
                "employee_id": employee_id,
                "finding": "Orphaned cross-platform account",
                "severity": "HIGH",
                "risk_score": 82,
            }
        )
    for employee_id in segments["overprivileged"]:
        risk_findings.append(
            {
                "employee_id": employee_id,
                "finding": "Cross-platform admin",
                "severity": "CRITICAL",
                "risk_score": 94,
            }
        )
    for employee_id in segments["privilege_escalation"]:
        risk_findings.append(
            {
                "employee_id": employee_id,
                "finding": "Privilege escalation",
                "severity": "HIGH",
                "risk_score": 86,
            }
        )
    for employee_id in segments["token_abuse"]:
        risk_findings.append(
            {
                "employee_id": employee_id,
                "finding": "Old API token with anomalous use",
                "severity": "MEDIUM",
                "risk_score": 68,
            }
        )

    event_id = 1
    event_types = ["Login", "Logout", "S3Access", "TokenUse", "TicketUpdate", "RepoAccess", "RoleChange"]
    weighted_events = ["Login"] * 24 + ["Logout"] * 12 + ["TicketUpdate"] * 18 + ["RepoAccess"] * 12 + ["S3Access"] * 12 + ["TokenUse"] * 10 + ["RoleChange"] * 4

    def add_event(employee_id, platform, event_type, timestamp):
        nonlocal event_id
        audit_events.append(
            {
                "event_id": f"EV{event_id:06d}",
                "employee_id": employee_id,
                "platform": platform,
                "event_type": event_type,
                "timestamp": timestamp.isoformat(timespec="minutes"),
            }
        )
        event_id += 1

    for employee_id in employee_ids:
        segment = segment_by_employee[employee_id]
        event_total = 2
        if segment == "normal":
            event_total = random.randint(1, 3)
        elif segment == "legit_high_privilege":
            event_total = random.randint(3, 5)
        elif segment in {"overprivileged", "privilege_escalation", "token_abuse"}:
            event_total = random.randint(4, 7)
        elif segment == "orphaned":
            event_total = random.randint(2, 4)

        for _ in range(event_total):
            platform = random.choice(PLATFORMS)
            if segment == "privilege_escalation" and random.random() < 0.35:
                event_type = "RoleChange"
                platform = "AWS"
            elif segment == "token_abuse" and random.random() < 0.5:
                event_type = "TokenUse"
            else:
                event_type = random.choice(weighted_events)
            hour = random.randint(0, 5) if segment in {"token_abuse", "privilege_escalation"} and random.random() < 0.35 else random.randint(8, 19)
            timestamp = base_date - timedelta(days=random.randint(0, 120), hours=base_date.hour - hour, minutes=random.randint(0, 59))
            add_event(employee_id, platform, event_type, timestamp)

    while len(audit_events) < 1000:
        employee_id = random.choice(employee_ids)
        segment = segment_by_employee[employee_id]
        platform = random.choice(PLATFORMS)
        event_type = random.choice(event_types)
        if segment == "token_abuse":
            event_type = random.choice(["TokenUse", "S3Access", "Login"])
        timestamp = base_date - timedelta(days=random.randint(0, 120), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        add_event(employee_id, platform, event_type, timestamp)

    audit_events = audit_events[:1000]

    write_csv(
        DATASET_DIR / "employees.csv",
        ["employee_id", "employee_name", "department", "employee_status", "termination_date"],
        employees,
    )
    write_csv(
        DATASET_DIR / "platform_accounts.csv",
        ["account_id", "employee_id", "platform", "username", "account_status"],
        platform_accounts,
    )
    write_csv(
        DATASET_DIR / "role_assignments.csv",
        ["employee_id", "platform", "role"],
        role_assignments,
    )
    write_csv(
        DATASET_DIR / "group_membership.csv",
        ["employee_id", "group_name"],
        group_membership,
    )
    write_csv(
        DATASET_DIR / "audit_events.csv",
        ["event_id", "employee_id", "platform", "event_type", "timestamp"],
        audit_events,
    )
    write_csv(
        DATASET_DIR / "employee_role_history.csv",
        ["employee_id", "platform", "old_role", "new_role", "change_date"],
        employee_role_history,
    )
    write_csv(
        DATASET_DIR / "api_tokens.csv",
        ["token_id", "employee_id", "token_age_days"],
        api_tokens,
    )
    write_csv(
        DATASET_DIR / "offboarding_records.csv",
        ["employee_id", "issue"],
        offboarding_records,
    )
    write_csv(
        DATASET_DIR / "risk_findings.csv",
        ["employee_id", "finding", "severity", "risk_score"],
        risk_findings,
    )

    return {
        "employees": len(employees),
        "platform_accounts": len(platform_accounts),
        "role_assignments": len(role_assignments),
        "group_membership": len(group_membership),
        "audit_events": len(audit_events),
        "employee_role_history": len(employee_role_history),
        "api_tokens": len(api_tokens),
        "offboarding_records": len(offboarding_records),
        "risk_findings": len(risk_findings),
        "segments": {name: len(ids) for name, ids in segments.items()},
    }


if __name__ == "__main__":
    result = build_dataset()
    for key, value in result.items():
        print(f"{key}: {value}")
