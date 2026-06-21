import json
import math
import sqlite3
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "identity_sprawl.db"

GROUP_EFFECTIVE_PRIVILEGES = {
    "SecurityAdmins": ("AD", "DomainAdmin"),
    "CloudOps": ("AWS", "AdministratorAccess"),
    "DevOps": ("GitHub", "RepositoryAdmin"),
}

ADMIN_HINTS = ("Admin", "Owner", "AdministratorAccess", "DomainAdmin", "SuperAdmin")


def node_id(kind, value):
    safe = str(value).replace(" ", "_").replace("/", "_")
    return f"{kind}:{safe}"


def is_admin(role):
    return any(hint in role for hint in ADMIN_HINTS)


class GraphBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node, node_type, label, platform=None, risk_score=0):
        current = self.nodes.get(node)
        if current:
            current["risk_score"] = max(current["risk_score"], risk_score)
            return
        self.nodes[node] = {
            "node_id": node,
            "node_type": node_type,
            "label": label,
            "platform": platform,
            "risk_score": risk_score,
        }

    def add_edge(self, source, target, edge_type, platform=None, weight=1, evidence=""):
        self.edges.append(
            {
                "source_id": source,
                "target_id": target,
                "edge_type": edge_type,
                "platform": platform,
                "weight": weight,
                "evidence": evidence,
            }
        )


def z_score(value, values):
    if not values:
        return 0
    mean = sum(values) / len(values)
    variance = sum((item - mean) ** 2 for item in values) / len(values)
    stdev = math.sqrt(variance)
    if stdev == 0:
        return 0
    return (value - mean) / stdev


def build_graph_intelligence():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("DELETE FROM graph_edges")
        conn.execute("DELETE FROM graph_nodes")
        conn.execute("DELETE FROM identity_graph_metrics")
        conn.execute("DELETE FROM risk_incidents")

        graph = GraphBuilder()
        employees = {
            row["employee_id"]: dict(row)
            for row in conn.execute("SELECT * FROM employees")
        }
        risks = {
            row["employee_id"]: dict(row)
            for row in conn.execute("SELECT * FROM identity_risk_scores")
        }

        roles_by_employee = defaultdict(list)
        for row in conn.execute("SELECT * FROM role_assignments"):
            roles_by_employee[row["employee_id"]].append(dict(row))

        groups_by_employee = defaultdict(list)
        for row in conn.execute("SELECT * FROM group_membership"):
            groups_by_employee[row["employee_id"]].append(row["group_name"])

        tokens_by_employee = defaultdict(list)
        for row in conn.execute("SELECT * FROM api_tokens"):
            tokens_by_employee[row["employee_id"]].append(dict(row))

        event_counts = defaultdict(lambda: defaultdict(int))
        for row in conn.execute(
            "SELECT employee_id, platform, event_type, COUNT(*) AS count FROM audit_events GROUP BY employee_id, platform, event_type"
        ):
            event_counts[row["employee_id"]][(row["platform"], row["event_type"])] = row["count"]

        for employee_id, employee in employees.items():
            risk_score = risks.get(employee_id, {}).get("risk_score", 0)
            identity_node = node_id("identity", employee_id)
            graph.add_node(
                identity_node,
                "identity",
                f"{employee_id} {employee['employee_name']}",
                risk_score=risk_score,
            )
            department_node = node_id("department", employee["department"])
            graph.add_node(department_node, "department", employee["department"])
            graph.add_edge(identity_node, department_node, "belongs_to")

        for row in conn.execute("SELECT * FROM platform_accounts"):
            identity_node = node_id("identity", row["employee_id"])
            account_node = node_id("account", row["account_id"])
            platform_node = node_id("platform", row["platform"])
            graph.add_node(platform_node, "platform", row["platform"], row["platform"])
            graph.add_node(
                account_node,
                "account",
                f"{row['username']} ({row['account_status']})",
                row["platform"],
                risks.get(row["employee_id"], {}).get("risk_score", 0),
            )
            graph.add_edge(identity_node, account_node, "has_account", row["platform"], evidence=row["account_status"])
            graph.add_edge(account_node, platform_node, "exists_on", row["platform"])

        for employee_id, role_rows in roles_by_employee.items():
            identity_node = node_id("identity", employee_id)
            for row in role_rows:
                role_node = node_id("role", f"{row['platform']}:{row['role']}")
                graph.add_node(role_node, "role", row["role"], row["platform"], 70 if is_admin(row["role"]) else 20)
                graph.add_edge(identity_node, role_node, "assigned_role", row["platform"], 3 if is_admin(row["role"]) else 1)
                graph.add_edge(role_node, node_id("platform", row["platform"]), "grants_on", row["platform"])

        for employee_id, group_names in groups_by_employee.items():
            identity_node = node_id("identity", employee_id)
            for group_name in group_names:
                group_node = node_id("group", group_name)
                graph.add_node(group_node, "group", group_name, risk_score=55 if group_name in GROUP_EFFECTIVE_PRIVILEGES else 10)
                graph.add_edge(identity_node, group_node, "member_of", evidence="group membership")
                if group_name in GROUP_EFFECTIVE_PRIVILEGES:
                    platform, role = GROUP_EFFECTIVE_PRIVILEGES[group_name]
                    role_node = node_id("role", f"{platform}:{role}")
                    graph.add_node(role_node, "role", role, platform, 80)
                    graph.add_edge(group_node, role_node, "inherits_role", platform, 4, "effective privilege through group")

        for employee_id, token_rows in tokens_by_employee.items():
            identity_node = node_id("identity", employee_id)
            for token in token_rows:
                token_node = node_id("token", token["token_id"])
                age = int(token["token_age_days"])
                graph.add_node(token_node, "token", f"{token['token_id']} ({age}d)", risk_score=min(age // 5, 100))
                graph.add_edge(identity_node, token_node, "owns_token", weight=2 if age > 365 else 1, evidence=f"{age} days old")

        for employee_id, counts in event_counts.items():
            identity_node = node_id("identity", employee_id)
            for (platform, event_type), count in counts.items():
                event_node = node_id("event", f"{platform}:{event_type}")
                graph.add_node(event_node, "event", event_type, platform, risk_score=45 if event_type in {"RoleChange", "TokenUse"} else 10)
                graph.add_edge(identity_node, event_node, "performed", platform, min(count / 10, 5), f"{count} events")

        conn.executemany(
            """
            INSERT INTO graph_nodes (node_id, node_type, label, platform, risk_score)
            VALUES (:node_id, :node_type, :label, :platform, :risk_score)
            """,
            list(graph.nodes.values()),
        )
        conn.executemany(
            """
            INSERT INTO graph_edges (source_id, target_id, edge_type, platform, weight, evidence)
            VALUES (:source_id, :target_id, :edge_type, :platform, :weight, :evidence)
            """,
            graph.edges,
        )

        adjacency = defaultdict(set)
        for edge in graph.edges:
            adjacency[edge["source_id"]].add(edge["target_id"])
            adjacency[edge["target_id"]].add(edge["source_id"])

        raw_metrics = {}
        for employee_id in employees:
            identity_node = node_id("identity", employee_id)
            direct_roles = roles_by_employee[employee_id]
            direct_admin_platforms = {row["platform"] for row in direct_roles if is_admin(row["role"])}
            inherited_admin_platforms = {
                GROUP_EFFECTIVE_PRIVILEGES[group][0]
                for group in groups_by_employee[employee_id]
                if group in GROUP_EFFECTIVE_PRIVILEGES
            }
            admin_platforms = direct_admin_platforms | inherited_admin_platforms
            inherited_count = len(inherited_admin_platforms)
            privilege_paths = len(direct_admin_platforms) + inherited_count
            lateral_paths = max(0, len(admin_platforms) * (len(admin_platforms) - 1) // 2)
            token_ages = [int(token["token_age_days"]) for token in tokens_by_employee[employee_id]]
            old_token_count = sum(1 for age in token_ages if age > 365)
            role_change_count = sum(
                count
                for (platform, event_type), count in event_counts[employee_id].items()
                if event_type == "RoleChange"
            )
            token_use_count = sum(
                count
                for (platform, event_type), count in event_counts[employee_id].items()
                if event_type == "TokenUse"
            )
            raw_metrics[employee_id] = {
                "degree": len(adjacency[identity_node]),
                "privilege_paths": privilege_paths,
                "inherited_count": inherited_count,
                "lateral_paths": lateral_paths,
                "old_token_count": old_token_count,
                "role_change_count": role_change_count,
                "token_use_count": token_use_count,
            }

        degrees = [metric["degree"] for metric in raw_metrics.values()]
        token_uses = [metric["token_use_count"] for metric in raw_metrics.values()]
        role_changes = [metric["role_change_count"] for metric in raw_metrics.values()]

        metric_rows = []
        for employee_id, metric in raw_metrics.items():
            reasons = []
            anomaly = 0
            degree_z = z_score(metric["degree"], degrees)
            token_z = z_score(metric["token_use_count"], token_uses)
            role_z = z_score(metric["role_change_count"], role_changes)
            if degree_z > 1.2:
                anomaly += 20
                reasons.append("unusually broad graph connectivity")
            if token_z > 1.2:
                anomaly += 20
                reasons.append("token usage above peer baseline")
            if role_z > 1.2:
                anomaly += 20
                reasons.append("role-change activity above peer baseline")
            if metric["lateral_paths"]:
                anomaly += min(metric["lateral_paths"] * 15, 35)
                reasons.append("cross-platform admin path enables lateral movement")
            if metric["inherited_count"]:
                anomaly += min(metric["inherited_count"] * 10, 20)
                reasons.append("hidden inherited privilege through group membership")
            if metric["old_token_count"]:
                anomaly += min(metric["old_token_count"] * 8, 20)
                reasons.append("long-lived API token exposure")

            metric_rows.append(
                (
                    employee_id,
                    metric["degree"],
                    metric["privilege_paths"],
                    metric["inherited_count"],
                    metric["lateral_paths"],
                    min(anomaly, 100),
                    json.dumps(reasons or ["within expected peer baseline"]),
                )
            )

        conn.executemany(
            """
            INSERT INTO identity_graph_metrics (
                employee_id, graph_degree, privilege_path_count, inherited_privilege_count,
                lateral_movement_paths, anomaly_score, anomaly_reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            metric_rows,
        )

        incidents = build_incidents(conn)
        conn.executemany(
            """
            INSERT INTO risk_incidents (
                incident_id, title, severity, incident_score, category,
                employee_ids, narrative, remediation
            ) VALUES (:incident_id, :title, :severity, :incident_score, :category,
                      :employee_ids, :narrative, :remediation)
            """,
            incidents,
        )
        conn.commit()
        return len(graph.nodes), len(graph.edges), len(metric_rows), len(incidents)
    finally:
        conn.close()


def build_incidents(conn):
    clusters = [
        {
            "incident_id": "INC-OFFBOARDING",
            "category": "Offboarding Gap",
            "title": "Terminated or disabled identities remain active across platforms",
            "where": "r.offboarding_gap = 1",
            "remediation": "Disable active platform accounts, confirm HR termination state, and require access owner sign-off before exceptions remain open.",
        },
        {
            "incident_id": "INC-LATERAL-ADMIN",
            "category": "Lateral Movement",
            "title": "Cross-platform admin paths create high blast radius",
            "where": "g.lateral_movement_paths > 0",
            "remediation": "Break cross-platform admin paths by removing inherited group admin access and separating AD, cloud, and SaaS emergency roles.",
        },
        {
            "incident_id": "INC-INHERITED-PRIVILEGE",
            "category": "Hidden Effective Privilege",
            "title": "Group membership grants hidden effective admin privilege",
            "where": "g.inherited_privilege_count > 0",
            "remediation": "Review nested group membership and remove identities from groups that indirectly grant admin rights.",
        },
        {
            "incident_id": "INC-TOKEN-ABUSE",
            "category": "Alternate Authentication Material",
            "title": "Long-lived tokens and token behavior exceed baseline",
            "where": "r.max_token_age_days > 365 OR g.anomaly_reasons LIKE '%token%'",
            "remediation": "Rotate old tokens, revoke unused tokens, and enforce maximum token age plus platform-specific token monitoring.",
        },
        {
            "incident_id": "INC-ROLE-CHANGE",
            "category": "Account Manipulation",
            "title": "Privilege changes and role activity exceed baseline",
            "where": "r.privilege_spike = 1 OR g.anomaly_reasons LIKE '%role-change%'",
            "remediation": "Validate role-change tickets, expire temporary exceptions, and review recent admin assignment history.",
        },
    ]

    incidents = []
    for cluster in clusters:
        members = [
            dict(row)
            for row in conn.execute(
                f"""
                SELECT r.employee_id, r.employee_name, r.department, r.risk_score,
                       r.severity, r.top_risk, g.anomaly_score, g.anomaly_reasons
                FROM identity_risk_scores r
                JOIN identity_graph_metrics g ON g.employee_id = r.employee_id
                WHERE {cluster['where']}
                ORDER BY r.risk_score DESC, g.anomaly_score DESC
                LIMIT 12
                """
            )
        ]
        if not members:
            continue
        score = max(row["risk_score"] for row in members)
        severity = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM"
        names = ", ".join(row["employee_id"] for row in members[:5])
        more = "" if len(members) <= 5 else f", plus {len(members) - 5} more"
        narrative = (
            f"{cluster['title']}. The graph links {len(members)} identities to related "
            f"accounts, roles, groups, tokens, or events. Highest priority examples: {names}{more}."
        )
        incidents.append(
            {
                "incident_id": cluster["incident_id"],
                "title": cluster["title"],
                "severity": severity,
                "incident_score": score,
                "category": cluster["category"],
                "employee_ids": json.dumps([row["employee_id"] for row in members]),
                "narrative": narrative,
                "remediation": cluster["remediation"],
            }
        )
    return incidents


if __name__ == "__main__":
    nodes, edges, metrics, incidents = build_graph_intelligence()
    print(f"graph nodes: {nodes}")
    print(f"graph edges: {edges}")
    print(f"identity graph metrics: {metrics}")
    print(f"risk incidents: {incidents}")
