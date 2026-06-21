import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "identity_sprawl.db"

ADMIN_ROLES = {
    "DomainAdmin": "AD",
    "AdministratorAccess": "AWS",
    "SuperAdmin": "Okta",
    "Admin": "Generic",
    "Owner": "Generic",
}

GROUP_EFFECTIVE_PRIVILEGES = {
    "SecurityAdmins": ("AD", "DomainAdmin"),
    "CloudOps": ("AWS", "AdministratorAccess"),
    "DevOps": ("GitHub", "RepositoryAdmin"),
}

PLATFORM_USAGE_EVENTS = {
    "AD": {"Login", "RoleChange", "Logout"},
    "AWS": {"S3Access", "TokenUse", "RoleChange", "Login"},
    "Okta": {"Login", "Logout", "TokenUse"},
    "Salesforce": {"TicketUpdate", "TokenUse", "Login"},
    "GitHub": {"RepoAccess", "TokenUse", "Login"},
}


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def severity_for(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def add(remediations, employee_id, platform, action, priority):
    remediations.append(
        {
            "employee_id": employee_id,
            "platform": platform,
            "action": action,
            "priority": priority,
        }
    )


def compute_risks():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("DELETE FROM identity_risk_scores")
        conn.execute("DELETE FROM remediation_actions")

        employees = {
            row["employee_id"]: dict(row)
            for row in conn.execute("SELECT * FROM employees")
        }

        platform_accounts = defaultdict(list)
        for row in conn.execute("SELECT * FROM platform_accounts"):
            platform_accounts[row["employee_id"]].append(dict(row))

        roles = defaultdict(list)
        for row in conn.execute("SELECT * FROM role_assignments"):
            roles[row["employee_id"]].append(dict(row))

        groups = defaultdict(list)
        for row in conn.execute("SELECT * FROM group_membership"):
            groups[row["employee_id"]].append(row["group_name"])

        history = defaultdict(list)
        all_change_dates = []
        for row in conn.execute("SELECT * FROM employee_role_history"):
            item = dict(row)
            history[row["employee_id"]].append(item)
            if item["change_date"]:
                all_change_dates.append(date.fromisoformat(item["change_date"]))

        events = defaultdict(list)
        latest_event = None
        for row in conn.execute("SELECT * FROM audit_events"):
            item = dict(row)
            item_dt = parse_dt(item["timestamp"])
            item["dt"] = item_dt
            events[row["employee_id"]].append(item)
            if item_dt and (latest_event is None or item_dt > latest_event):
                latest_event = item_dt

        tokens = defaultdict(list)
        for row in conn.execute("SELECT * FROM api_tokens"):
            tokens[row["employee_id"]].append(dict(row))

        offboarding = defaultdict(list)
        for row in conn.execute("SELECT * FROM offboarding_records"):
            offboarding[row["employee_id"]].append(row["issue"])

        latest_change = max(all_change_dates) if all_change_dates else date.today()
        as_of = latest_event or datetime.now()

        score_rows = []
        remediation_rows = []

        for employee_id, employee in employees.items():
            account_rows = platform_accounts[employee_id]
            role_rows = roles[employee_id]
            event_rows = events[employee_id]
            token_rows = tokens[employee_id]
            history_rows = history[employee_id]

            platform_count = len({row["platform"] for row in account_rows})
            active_platforms = {
                row["platform"]
                for row in account_rows
                if row["account_status"].lower() == "active"
            }
            disabled_platforms = {
                row["platform"]
                for row in account_rows
                if row["account_status"].lower() != "active"
            }

            effective_roles = list(role_rows)
            inherited = []
            for group_name in groups[employee_id]:
                if group_name in GROUP_EFFECTIVE_PRIVILEGES:
                    platform, role = GROUP_EFFECTIVE_PRIVILEGES[group_name]
                    inherited.append(
                        {
                            "employee_id": employee_id,
                            "platform": platform,
                            "role": role,
                            "source": f"group:{group_name}",
                        }
                    )
            effective_roles.extend(inherited)

            admin_platforms = {
                row["platform"]
                for row in effective_roles
                if row["role"] in ADMIN_ROLES
                or "Admin" in row["role"]
                or "Owner" in row["role"]
            }

            last_seen = max((row["dt"] for row in event_rows if row["dt"]), default=None)
            dormancy_days = (as_of - last_seen).days if last_seen else 999
            max_token_age = max(
                (int(row["token_age_days"]) for row in token_rows if row["token_age_days"]),
                default=0,
            )
            recent_admin_changes = [
                row
                for row in history_rows
                if row["change_date"]
                and (latest_change - date.fromisoformat(row["change_date"])).days <= 7
                and (
                    row["new_role"] in ADMIN_ROLES
                    or "Admin" in row["new_role"]
                    or "Owner" in row["new_role"]
                )
            ]

            event_type_counts = Counter(row["event_type"] for row in event_rows)
            off_hour_events = sum(
                1
                for row in event_rows
                if row["dt"] and (row["dt"].hour < 6 or row["dt"].hour > 21)
            )
            off_hour_ratio = off_hour_events / max(len(event_rows), 1)
            behavioral_deviation = int(
                off_hour_ratio >= 0.35
                or event_type_counts["RoleChange"] >= 10
                or event_type_counts["TokenUse"] >= 12
            )

            offboarding_gap = int(
                bool(offboarding[employee_id])
                or (
                    employee["employee_status"].lower() == "terminated"
                    and bool(active_platforms)
                )
                or ("AD" in disabled_platforms and len(active_platforms) > 0)
            )

            unused_privileges = []
            for platform in admin_platforms:
                used_events = PLATFORM_USAGE_EVENTS.get(platform, {"Login"})
                has_platform_use = any(
                    row["platform"] == platform and row["event_type"] in used_events
                    for row in event_rows
                )
                if not has_platform_use:
                    unused_privileges.append(platform)

            findings = []
            score = 0

            if offboarding_gap:
                score += 30
                findings.append("Offboarding gap: disabled or terminated identity still has active accounts")
                for account in account_rows:
                    if account["account_status"].lower() == "active":
                        add(
                            remediation_rows,
                            employee_id,
                            account["platform"],
                            f"Disable active account {account['username']} after HR/offboarding review",
                            "P0",
                        )

            if len(admin_platforms) >= 2:
                score += 25
                findings.append(
                    f"Cross-platform admin across {', '.join(sorted(admin_platforms))}"
                )
                for platform in sorted(admin_platforms):
                    add(
                        remediation_rows,
                        employee_id,
                        platform,
                        "Review admin entitlement and remove unless an approved exception exists",
                        "P0",
                    )
            elif len(admin_platforms) == 1:
                score += 10
                findings.append(f"Single-platform admin on {next(iter(admin_platforms))}")

            if dormancy_days > 90 and admin_platforms:
                score += 20
                findings.append(f"Dormant privileged identity: {dormancy_days} days since last event")
                for platform in sorted(admin_platforms):
                    add(
                        remediation_rows,
                        employee_id,
                        platform,
                        "Suspend stale admin access or require manager re-certification",
                        "P1",
                    )
            elif dormancy_days > 90:
                score += 8
                findings.append(f"Dormant identity: {dormancy_days} days since last event")

            if recent_admin_changes:
                score += 15
                findings.append("Recent admin privilege spike in role history")
                for row in recent_admin_changes:
                    add(
                        remediation_rows,
                        employee_id,
                        row["platform"],
                        f"Validate recent role change {row['old_role']} -> {row['new_role']}",
                        "P1",
                    )

            if max_token_age > 365:
                score += 12
                findings.append(f"Unrotated API token age: {max_token_age} days")
                add(
                    remediation_rows,
                    employee_id,
                    "API",
                    "Rotate API token and enforce maximum token age policy",
                    "P1",
                )

            if behavioral_deviation:
                score += 10
                findings.append("Behavioral baseline deviation from off-hour or token/role activity")

            if unused_privileges:
                score += 8
                findings.append(
                    "Unused privileged access on " + ", ".join(sorted(unused_privileges))
                )
                for platform in sorted(unused_privileges):
                    add(
                        remediation_rows,
                        employee_id,
                        platform,
                        "Remove unused privileged entitlement or document business need",
                        "P2",
                    )

            score += min(platform_count * 3, 15)
            score += min(len(effective_roles), 10)
            score = min(score, 100)

            if not findings:
                findings.append("No material hygiene issue detected")

            evidence = {
                "platforms": sorted({row["platform"] for row in account_rows}),
                "active_platforms": sorted(active_platforms),
                "admin_platforms": sorted(admin_platforms),
                "groups": groups[employee_id],
                "inherited_privileges": inherited,
                "recent_admin_changes": recent_admin_changes,
                "event_counts": dict(event_type_counts),
                "offboarding_issues": offboarding[employee_id],
                "unused_privileged_platforms": sorted(unused_privileges),
            }

            score_rows.append(
                (
                    employee_id,
                    employee["employee_name"],
                    employee["department"],
                    severity_for(score),
                    score,
                    platform_count,
                    len(active_platforms),
                    len(effective_roles),
                    len(admin_platforms),
                    dormancy_days,
                    max_token_age,
                    offboarding_gap,
                    int(bool(recent_admin_changes)),
                    behavioral_deviation,
                    findings[0],
                    json.dumps({"findings": findings, "evidence": evidence}, default=str),
                )
            )

        conn.executemany(
            """
            INSERT INTO identity_risk_scores (
                employee_id, employee_name, department, severity, risk_score,
                platform_count, active_platform_count, role_count, admin_platform_count,
                dormancy_days, max_token_age_days, offboarding_gap, privilege_spike,
                behavioral_deviation, top_risk, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            score_rows,
        )

        conn.executemany(
            """
            INSERT INTO remediation_actions (employee_id, platform, action, priority)
            VALUES (:employee_id, :platform, :action, :priority)
            """,
            remediation_rows,
        )
        conn.commit()
        return len(score_rows), len(remediation_rows)
    finally:
        conn.close()


if __name__ == "__main__":
    scores, actions = compute_risks()
    print(f"risk scores: {scores}")
    print(f"remediation actions: {actions}")

