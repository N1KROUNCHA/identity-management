import csv
import io
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.graph_engine import build_graph_intelligence
from src.ingest import DB_PATH, build_database
from src.risk_engine import compute_risks


ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8080


def ensure_ready():
    if not DB_PATH.exists():
        build_database()
        compute_risks()
        build_graph_intelligence()
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        existing = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='identity_risk_scores'"
        ).fetchone()
        graph_existing = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='risk_incidents'"
        ).fetchone()
        count = 0
        if existing:
            count = conn.execute("SELECT COUNT(*) FROM identity_risk_scores").fetchone()[0]
        incident_count = 0
        if graph_existing:
            incident_count = conn.execute("SELECT COUNT(*) FROM risk_incidents").fetchone()[0]
    finally:
        conn.close()
    if not existing or count == 0:
        build_database()
        compute_risks()
        build_graph_intelligence()
    elif not graph_existing or incident_count == 0:
        build_graph_intelligence()


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def rows(sql, params=()):
    conn = connect()
    try:
        return [dict(row) for row in conn.execute(sql, params)]
    finally:
        conn.close()


def one(sql, params=()):
    result = rows(sql, params)
    return result[0] if result else {}


def api_summary():
    summary = one(
        """
        SELECT
            COUNT(*) AS identities,
            SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) AS high_risk,
            SUM(offboarding_gap) AS offboarding_gaps,
            SUM(CASE WHEN max_token_age_days > 365 THEN 1 ELSE 0 END) AS old_tokens,
            ROUND(AVG(risk_score), 1) AS avg_score
        FROM identity_risk_scores
        """
    )
    severity = rows(
        """
        SELECT severity AS label, COUNT(*) AS value
        FROM identity_risk_scores
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 ELSE 4 END
        """
    )
    departments = rows(
        """
        SELECT department AS label, ROUND(AVG(risk_score), 1) AS value
        FROM identity_risk_scores
        GROUP BY department
        ORDER BY value DESC
        """
    )
    platforms = rows(
        """
        SELECT platform AS label, COUNT(*) AS value
        FROM remediation_actions
        GROUP BY platform
        ORDER BY value DESC
        LIMIT 8
        """
    )
    graph = one(
        """
        SELECT
            (SELECT COUNT(*) FROM graph_nodes) AS nodes,
            (SELECT COUNT(*) FROM graph_edges) AS edges,
            (SELECT COUNT(*) FROM risk_incidents) AS incidents,
            ROUND(AVG(anomaly_score), 1) AS avg_anomaly
        FROM identity_graph_metrics
        """
    )
    return {
        "summary": summary,
        "severity": severity,
        "departments": departments,
        "platforms": platforms,
        "graph": graph,
    }


def api_risks(query):
    params = parse_qs(query)
    severity = params.get("severity", [""])[0]
    department = params.get("department", [""])[0]
    search = params.get("search", [""])[0].strip()

    where = []
    values = []
    if severity:
        where.append("severity = ?")
        values.append(severity)
    if department:
        where.append("department = ?")
        values.append(department)
    if search:
        where.append("(employee_id LIKE ? OR employee_name LIKE ? OR top_risk LIKE ?)")
        values.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    where_sql = "WHERE " + " AND ".join(where) if where else ""

    return rows(
        f"""
        SELECT employee_id, employee_name, department, severity, risk_score,
               platform_count, active_platform_count, admin_platform_count,
               dormancy_days, max_token_age_days, top_risk
        FROM identity_risk_scores
        {where_sql}
        ORDER BY risk_score DESC, employee_id
        LIMIT 100
        """,
        values,
    )


def api_identity(query):
    employee_id = parse_qs(query).get("id", [""])[0]
    identity = one("SELECT * FROM identity_risk_scores WHERE employee_id = ?", (employee_id,))
    if not identity:
        return {"error": "Identity not found"}

    identity["evidence"] = json.loads(identity.pop("evidence_json"))
    identity["accounts"] = rows(
        "SELECT platform, username, account_status FROM platform_accounts WHERE employee_id = ? ORDER BY platform",
        (employee_id,),
    )
    identity["roles"] = rows(
        "SELECT platform, role FROM role_assignments WHERE employee_id = ? ORDER BY platform, role",
        (employee_id,),
    )
    identity["groups"] = rows(
        "SELECT group_name FROM group_membership WHERE employee_id = ? ORDER BY group_name",
        (employee_id,),
    )
    identity["actions"] = rows(
        "SELECT platform, action, priority FROM remediation_actions WHERE employee_id = ? ORDER BY priority, platform",
        (employee_id,),
    )
    identity["events"] = rows(
        """
        SELECT platform, event_type, COUNT(*) AS count, MAX(timestamp) AS last_seen
        FROM audit_events
        WHERE employee_id = ?
        GROUP BY platform, event_type
        ORDER BY count DESC
        """,
        (employee_id,),
    )
    graph_metric = one(
        "SELECT * FROM identity_graph_metrics WHERE employee_id = ?",
        (employee_id,),
    )
    if graph_metric:
        graph_metric["anomaly_reasons"] = json.loads(graph_metric["anomaly_reasons"])
    identity["graph_metrics"] = graph_metric
    return identity


def api_graph(query):
    employee_id = parse_qs(query).get("id", [""])[0]
    center = f"identity:{employee_id}"
    nodes_by_id = {}
    edge_rows = rows(
        """
        SELECT e.source_id, e.target_id, e.edge_type, e.platform, e.weight, e.evidence,
               s.node_type AS source_type, s.label AS source_label, s.risk_score AS source_risk,
               t.node_type AS target_type, t.label AS target_label, t.risk_score AS target_risk
        FROM graph_edges e
        JOIN graph_nodes s ON s.node_id = e.source_id
        JOIN graph_nodes t ON t.node_id = e.target_id
        WHERE e.source_id = ? OR e.target_id = ?
        ORDER BY e.weight DESC, e.edge_type
        LIMIT 42
        """,
        (center, center),
    )
    edges = []
    for edge in edge_rows:
        nodes_by_id[edge["source_id"]] = {
            "id": edge["source_id"],
            "type": edge["source_type"],
            "label": edge["source_label"],
            "risk": edge["source_risk"],
        }
        nodes_by_id[edge["target_id"]] = {
            "id": edge["target_id"],
            "type": edge["target_type"],
            "label": edge["target_label"],
            "risk": edge["target_risk"],
        }
        edges.append(
            {
                "source": edge["source_id"],
                "target": edge["target_id"],
                "type": edge["edge_type"],
                "platform": edge["platform"],
                "weight": edge["weight"],
                "evidence": edge["evidence"],
            }
        )
    return {"center": center, "nodes": list(nodes_by_id.values()), "edges": edges}


def api_incidents():
    incident_rows = rows(
        """
        SELECT incident_id, title, severity, incident_score, category,
               employee_ids, narrative, remediation
        FROM risk_incidents
        ORDER BY incident_score DESC, incident_id
        """
    )
    for incident in incident_rows:
        incident["employee_ids"] = json.loads(incident["employee_ids"])
    return incident_rows


def api_compliance():
    controls = [
        {
            "framework": "NIST SP 800-53",
            "control": "AC-2",
            "title": "Account Management",
            "evidence": "Offboarding gaps, disabled accounts active elsewhere, dormant identities",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores WHERE offboarding_gap = 1 OR dormancy_days > 90",
        },
        {
            "framework": "NIST SP 800-53",
            "control": "AC-6",
            "title": "Least Privilege",
            "evidence": "Cross-platform admin, unused privilege, inherited admin through groups",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores r JOIN identity_graph_metrics g ON g.employee_id = r.employee_id WHERE r.admin_platform_count > 0 OR g.inherited_privilege_count > 0",
        },
        {
            "framework": "MITRE ATT&CK",
            "control": "T1078",
            "title": "Valid Accounts",
            "evidence": "Active accounts on terminated or disabled identities",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores WHERE offboarding_gap = 1",
        },
        {
            "framework": "MITRE ATT&CK",
            "control": "T1098",
            "title": "Account Manipulation",
            "evidence": "Privilege spikes and role-change behavior above baseline",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores r JOIN identity_graph_metrics g ON g.employee_id = r.employee_id WHERE r.privilege_spike = 1 OR g.anomaly_reasons LIKE '%role-change%'",
        },
        {
            "framework": "MITRE ATT&CK",
            "control": "T1550",
            "title": "Alternate Authentication Material",
            "evidence": "Old API tokens and token behavior above baseline",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores r JOIN identity_graph_metrics g ON g.employee_id = r.employee_id WHERE r.max_token_age_days > 365 OR g.anomaly_reasons LIKE '%token%'",
        },
        {
            "framework": "GDPR",
            "control": "Article 5",
            "title": "Data Minimisation",
            "evidence": "Privilege breadth and unused privileged access",
            "query": "SELECT COUNT(*) AS value FROM identity_risk_scores WHERE admin_platform_count > 0 OR platform_count >= 5",
        },
        {
            "framework": "CIS Controls",
            "control": "5 and 6",
            "title": "Account and Access Control Management",
            "evidence": "Full identity coverage, risk-ranked backlog, remediation actions",
            "query": "SELECT COUNT(*) AS value FROM remediation_actions",
        },
    ]
    results = []
    for control in controls:
        item = dict(control)
        item["finding_count"] = one(control["query"]).get("value", 0)
        item.pop("query")
        results.append(item)
    return results


def report_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "employee_id",
            "employee_name",
            "department",
            "severity",
            "risk_score",
            "top_risk",
            "remediation_count",
        ]
    )
    for row in rows(
        """
        SELECT r.employee_id, r.employee_name, r.department, r.severity, r.risk_score,
               r.top_risk, COUNT(a.id) AS remediation_count
        FROM identity_risk_scores r
        LEFT JOIN remediation_actions a ON a.employee_id = r.employee_id
        GROUP BY r.employee_id
        ORDER BY r.risk_score DESC
        LIMIT 50
        """
    ):
        writer.writerow([row[key] for key in row.keys()])
    return output.getvalue()


def playbook_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "priority",
            "employee_id",
            "employee_name",
            "department",
            "severity",
            "risk_score",
            "platform",
            "action",
            "control_mapping",
        ]
    )
    action_rows = rows(
        """
        SELECT a.priority, r.employee_id, r.employee_name, r.department, r.severity,
               r.risk_score, a.platform, a.action,
               CASE
                 WHEN a.action LIKE '%Disable active account%' THEN 'NIST AC-2 / MITRE T1078'
                 WHEN a.action LIKE '%admin%' OR a.action LIKE '%Admin%' THEN 'NIST AC-6 / MITRE T1098'
                 WHEN a.action LIKE '%token%' OR a.platform = 'API' THEN 'MITRE T1550 / GDPR Article 32'
                 ELSE 'CIS 5 and 6'
               END AS control_mapping
        FROM remediation_actions a
        JOIN identity_risk_scores r ON r.employee_id = a.employee_id
        ORDER BY a.priority, r.risk_score DESC, a.platform
        """
    )
    for row in action_rows:
        writer.writerow([row[key] for key in row.keys()])
    return output.getvalue()


def executive_report_html():
    summary = api_summary()
    incidents = api_incidents()
    compliance = api_compliance()
    top_risks = rows(
        """
        SELECT employee_id, employee_name, department, severity, risk_score, top_risk
        FROM identity_risk_scores
        ORDER BY risk_score DESC, employee_id
        LIMIT 10
        """
    )
    def tr(cells):
        return "<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>"

    incident_rows = "".join(
        tr(
            [
                item["incident_id"],
                item["severity"],
                item["incident_score"],
                item["category"],
                item["narrative"],
            ]
        )
        for item in incidents
    )
    risk_rows = "".join(
        tr(
            [
                row["employee_id"],
                row["employee_name"],
                row["department"],
                row["severity"],
                row["risk_score"],
                row["top_risk"],
            ]
        )
        for row in top_risks
    )
    compliance_rows = "".join(
        tr(
            [
                item["framework"],
                item["control"],
                item["title"],
                item["finding_count"],
                item["evidence"],
            ]
        )
        for item in compliance
    )
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Risk Executive Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #17202a; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 28px; border-bottom: 1px solid #d8dee8; padding-bottom: 8px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
    .card {{ border: 1px solid #d8dee8; border-radius: 8px; padding: 14px; }}
    .label {{ color: #5d6978; font-size: 12px; text-transform: uppercase; font-weight: 700; }}
    .value {{ font-size: 28px; font-weight: 800; margin-top: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e8edf3; padding: 9px; text-align: left; vertical-align: top; }}
    th {{ background: #f7fafc; color: #5d6978; text-transform: uppercase; font-size: 11px; }}
    .actions a {{ display: inline-block; margin-right: 10px; color: #0f766e; font-weight: 700; }}
    @media print {{ .actions {{ display: none; }} body {{ margin: 18px; }} }}
  </style>
</head>
<body>
  <div class="actions">
    <a href="/">Back to dashboard</a>
    <a href="/download/report.csv">Risk CSV</a>
    <a href="/download/playbook.csv">Remediation playbook CSV</a>
  </div>
  <h1>Identity Risk Executive Report</h1>
  <p>Graph-based cross-platform identity intelligence for privileged access abuse detection.</p>
  <section class="cards">
    <div class="card"><div class="label">Identities assessed</div><div class="value">{summary["summary"]["identities"]}</div></div>
    <div class="card"><div class="label">Critical/high risk</div><div class="value">{summary["summary"]["high_risk"]}</div></div>
    <div class="card"><div class="label">Graph incidents</div><div class="value">{summary["graph"]["incidents"]}</div></div>
    <div class="card"><div class="label">Remediation actions</div><div class="value">{one("SELECT COUNT(*) AS value FROM remediation_actions")["value"]}</div></div>
  </section>
  <h2>Graph-Clustered Incidents</h2>
  <table><thead><tr><th>ID</th><th>Severity</th><th>Score</th><th>Category</th><th>Narrative</th></tr></thead><tbody>{incident_rows}</tbody></table>
  <h2>Top Risk Identities</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Department</th><th>Severity</th><th>Score</th><th>Finding</th></tr></thead><tbody>{risk_rows}</tbody></table>
  <h2>Compliance Evidence</h2>
  <table><thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Count</th><th>Evidence</th></tr></thead><tbody>{compliance_rows}</tbody></table>
</body>
</html>
"""


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Risk Governance Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17202a;
      --muted: #5d6978;
      --line: #d8dee8;
      --panel: #ffffff;
      --bg: #f4f7fb;
      --accent: #0f766e;
      --warn: #b45309;
      --danger: #b42318;
      --high: #7c2d12;
      --medium: #854d0e;
      --low: #166534;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Arial, sans-serif;
      color: var(--ink);
      background: var(--bg);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 22px 30px;
      background: #102027;
      color: white;
      border-bottom: 4px solid var(--accent);
    }
    h1 { margin: 0; font-size: 22px; font-weight: 750; letter-spacing: 0; }
    header p { margin: 4px 0 0; color: #c9d8dd; font-size: 13px; }
    main { padding: 24px 30px 34px; }
    .toolbar {
      display: grid;
      grid-template-columns: 180px 180px minmax(220px, 1fr) auto;
      gap: 10px;
      align-items: center;
      margin-bottom: 18px;
    }
    select, input, button, a.button {
      height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: white;
      color: var(--ink);
      padding: 0 12px;
      font: inherit;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
    }
    button, a.button {
      background: var(--accent);
      border-color: var(--accent);
      color: white;
      cursor: pointer;
      white-space: nowrap;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .card, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(16, 32, 39, .04);
    }
    .card { padding: 14px; min-height: 82px; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 700; }
    .value { font-size: 28px; line-height: 1.15; margin-top: 8px; font-weight: 800; }
    .grid {
      display: grid;
      grid-template-columns: 1.2fr .8fr;
      gap: 16px;
      align-items: start;
    }
    .panel { overflow: hidden; }
    .panel h2 {
      margin: 0;
      padding: 14px 16px;
      font-size: 15px;
      border-bottom: 1px solid var(--line);
      background: #f9fbfd;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #edf1f5; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 11px; text-transform: uppercase; background: #fbfcfe; }
    tbody tr { cursor: pointer; }
    tbody tr:hover { background: #f3faf8; }
    .pill { display: inline-flex; align-items: center; min-width: 78px; justify-content: center; padding: 3px 8px; border-radius: 999px; color: white; font-size: 11px; font-weight: 800; }
    .CRITICAL { background: var(--danger); }
    .HIGH { background: var(--high); }
    .MEDIUM { background: var(--medium); }
    .LOW { background: var(--low); }
    .charts { display: grid; gap: 14px; padding: 14px; }
    .chart h3, .detail h3 { margin: 0 0 9px; font-size: 13px; color: var(--muted); }
    .bars { display: grid; gap: 7px; }
    .bar-row { display: grid; grid-template-columns: 110px 1fr 46px; gap: 8px; align-items: center; font-size: 12px; }
    .bar { height: 11px; background: #e7edf4; border-radius: 999px; overflow: hidden; }
    .bar span { display: block; height: 100%; background: var(--accent); }
    .detail { padding: 14px 16px 16px; display: grid; gap: 14px; }
    .detail-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
    .mini { border: 1px solid var(--line); border-radius: 6px; padding: 10px; background: #fbfcfe; }
    .graph-wrap { min-height: 360px; border: 1px solid var(--line); border-radius: 8px; background: #ffffff; }
    .graph-wrap svg { width: 100%; height: 360px; display: block; }
    .incident-list { display: grid; gap: 10px; padding: 14px 16px 16px; }
    .incident { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fbfcfe; }
    .incident h3 { margin: 0 0 6px; font-size: 14px; }
    .incident p { margin: 7px 0 0; color: var(--muted); font-size: 13px; line-height: 1.45; }
    ul { margin: 8px 0 0; padding-left: 18px; }
    li { margin: 5px 0; }
    .empty { padding: 24px; color: var(--muted); }
    @media (max-width: 980px) {
      .toolbar, .cards, .grid, .detail-grid { grid-template-columns: 1fr; }
      header { align-items: flex-start; flex-direction: column; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Identity Risk Governance Dashboard</h1>
      <p>Cross-platform identity graph, privilege paths, behavioral baselines, and remediation backlog</p>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a class="button" href="/report">Executive report</a>
      <a class="button" href="/download/report.csv">Risk CSV</a>
      <a class="button" href="/download/playbook.csv">Playbook CSV</a>
    </div>
  </header>

  <main>
    <section class="toolbar">
      <select id="severity">
        <option value="">All severities</option>
        <option>CRITICAL</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
      </select>
      <select id="department"><option value="">All departments</option></select>
      <input id="search" placeholder="Search identity or finding">
      <button id="apply">Apply filters</button>
    </section>

    <section class="cards">
      <div class="card"><div class="label">Identities assessed</div><div class="value" id="identities">-</div></div>
      <div class="card"><div class="label">Critical/high risk</div><div class="value" id="highRisk">-</div></div>
      <div class="card"><div class="label">Offboarding gaps</div><div class="value" id="offboarding">-</div></div>
      <div class="card"><div class="label">Old API tokens</div><div class="value" id="tokens">-</div></div>
      <div class="card"><div class="label">Average score</div><div class="value" id="avgScore">-</div></div>
      <div class="card"><div class="label">Graph nodes</div><div class="value" id="graphNodes">-</div></div>
      <div class="card"><div class="label">Graph edges</div><div class="value" id="graphEdges">-</div></div>
      <div class="card"><div class="label">Risk incidents</div><div class="value" id="incidents">-</div></div>
      <div class="card"><div class="label">Avg anomaly</div><div class="value" id="avgAnomaly">-</div></div>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Risk-ranked identity backlog</h2>
        <table>
          <thead>
            <tr>
              <th>Identity</th><th>Dept</th><th>Severity</th><th>Score</th><th>Platforms</th><th>Top risk</th>
            </tr>
          </thead>
          <tbody id="riskRows"></tbody>
        </table>
      </div>
      <div class="panel">
        <h2>Risk distribution</h2>
        <div class="charts">
          <div class="chart"><h3>Severity</h3><div class="bars" id="severityBars"></div></div>
          <div class="chart"><h3>Average risk by department</h3><div class="bars" id="departmentBars"></div></div>
          <div class="chart"><h3>Remediation backlog by platform</h3><div class="bars" id="platformBars"></div></div>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top:16px">
      <h2>Graph-clustered incidents</h2>
      <div id="incidentList" class="incident-list"></div>
    </section>

    <section class="panel" style="margin-top:16px">
      <h2>Compliance evidence map</h2>
      <div class="charts">
        <table>
          <thead><tr><th>Framework</th><th>Control</th><th>Evidence count</th><th>What this proves</th></tr></thead>
          <tbody id="complianceRows"></tbody>
        </table>
      </div>
    </section>

    <section class="panel" style="margin-top:16px">
      <h2>Identity drill-down</h2>
      <div id="detail" class="detail">
        <div class="empty">Select a row to inspect evidence, effective privilege, and platform-specific actions.</div>
      </div>
    </section>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

    async function getJson(url) {
      const response = await fetch(url);
      return response.json();
    }

    function renderBars(id, rows) {
      const max = Math.max(...rows.map(r => Number(r.value || 0)), 1);
      $(id).innerHTML = rows.map(r => `
        <div class="bar-row">
          <div title="${esc(r.label)}">${esc(r.label)}</div>
          <div class="bar"><span style="width:${(Number(r.value || 0) / max) * 100}%"></span></div>
          <strong>${esc(r.value)}</strong>
        </div>
      `).join('');
    }

    async function loadSummary() {
      const data = await getJson('/api/summary');
      $('identities').textContent = data.summary.identities;
      $('highRisk').textContent = data.summary.high_risk;
      $('offboarding').textContent = data.summary.offboarding_gaps;
      $('tokens').textContent = data.summary.old_tokens;
      $('avgScore').textContent = data.summary.avg_score;
      $('graphNodes').textContent = data.graph.nodes;
      $('graphEdges').textContent = data.graph.edges;
      $('incidents').textContent = data.graph.incidents;
      $('avgAnomaly').textContent = data.graph.avg_anomaly;
      renderBars('severityBars', data.severity);
      renderBars('departmentBars', data.departments);
      renderBars('platformBars', data.platforms);
      $('department').innerHTML = '<option value="">All departments</option>' + data.departments.map(d => `<option>${esc(d.label)}</option>`).join('');
    }

    async function loadIncidents() {
      const data = await getJson('/api/incidents');
      $('incidentList').innerHTML = data.map(item => `
        <article class="incident">
          <h3><span class="pill ${esc(item.severity)}">${esc(item.severity)}</span> ${esc(item.title)}</h3>
          <p><strong>${esc(item.category)}</strong> | Score ${esc(item.incident_score)} | ${esc(item.employee_ids.length)} linked identities</p>
          <p>${esc(item.narrative)}</p>
          <p><strong>Remediation:</strong> ${esc(item.remediation)}</p>
        </article>
      `).join('');
    }

    async function loadCompliance() {
      const data = await getJson('/api/compliance');
      $('complianceRows').innerHTML = data.map(item => `
        <tr>
          <td><strong>${esc(item.framework)}</strong></td>
          <td>${esc(item.control)}<br>${esc(item.title)}</td>
          <td><strong>${esc(item.finding_count)}</strong></td>
          <td>${esc(item.evidence)}</td>
        </tr>
      `).join('');
    }

    async function loadRisks() {
      const qs = new URLSearchParams({
        severity: $('severity').value,
        department: $('department').value,
        search: $('search').value
      });
      const data = await getJson('/api/risks?' + qs.toString());
      $('riskRows').innerHTML = data.map(row => `
        <tr data-id="${esc(row.employee_id)}">
          <td><strong>${esc(row.employee_id)}</strong><br>${esc(row.employee_name)}</td>
          <td>${esc(row.department)}</td>
          <td><span class="pill ${esc(row.severity)}">${esc(row.severity)}</span></td>
          <td><strong>${esc(row.risk_score)}</strong></td>
          <td>${esc(row.active_platform_count)} active / ${esc(row.platform_count)} total</td>
          <td>${esc(row.top_risk)}</td>
        </tr>
      `).join('');
      document.querySelectorAll('#riskRows tr').forEach(row => {
        row.addEventListener('click', () => loadIdentity(row.dataset.id));
      });
      if (data[0]) loadIdentity(data[0].employee_id);
    }

    function list(items, mapper) {
      if (!items || !items.length) return '<p class="empty">No records.</p>';
      return '<ul>' + items.map(item => `<li>${mapper(item)}</li>`).join('') + '</ul>';
    }

    function renderGraph(graph) {
      if (!graph.nodes.length) return '<div class="empty">No graph edges available for this identity.</div>';
      const width = 820, height = 360;
      const center = graph.center;
      const others = graph.nodes.filter(n => n.id !== center).slice(0, 32);
      const centerNode = graph.nodes.find(n => n.id === center) || graph.nodes[0];
      const positioned = new Map();
      positioned.set(centerNode.id, { ...centerNode, x: width / 2, y: height / 2 });
      const radius = 132;
      others.forEach((node, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(others.length, 1);
        positioned.set(node.id, {
          ...node,
          x: width / 2 + Math.cos(angle) * radius,
          y: height / 2 + Math.sin(angle) * radius
        });
      });
      const color = (type) => ({
        identity: '#0f766e', account: '#2563eb', role: '#b42318',
        group: '#7c2d12', token: '#854d0e', event: '#6d28d9',
        platform: '#334155', department: '#64748b'
      }[type] || '#475569');
      const lines = graph.edges.map(edge => {
        const s = positioned.get(edge.source), t = positioned.get(edge.target);
        if (!s || !t) return '';
        return `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="#cbd5e1" stroke-width="${Math.max(1, edge.weight)}" />`;
      }).join('');
      const labels = Array.from(positioned.values()).map(node => `
        <g>
          <circle cx="${node.x}" cy="${node.y}" r="${node.id === center ? 19 : 13}" fill="${color(node.type)}"></circle>
          <text x="${node.x}" y="${node.y + (node.id === center ? 34 : 28)}" text-anchor="middle" font-size="10" fill="#17202a">${esc(node.label).slice(0, 18)}</text>
        </g>
      `).join('');
      return `<div class="graph-wrap"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Identity graph">${lines}${labels}</svg></div>`;
    }

    async function loadIdentity(id) {
      const [data, graph] = await Promise.all([
        getJson('/api/identity?id=' + encodeURIComponent(id)),
        getJson('/api/graph?id=' + encodeURIComponent(id))
      ]);
      const findings = data.evidence.findings || [];
      const evidence = data.evidence.evidence || {};
      const graphMetrics = data.graph_metrics || {};
      $('detail').innerHTML = `
        <div>
          <h3>${esc(data.employee_id)} - ${esc(data.employee_name)}</h3>
          <span class="pill ${esc(data.severity)}">${esc(data.severity)}</span>
          <strong style="margin-left:8px">Risk score ${esc(data.risk_score)}</strong>
          <strong style="margin-left:8px">Graph anomaly ${esc(graphMetrics.anomaly_score ?? 0)}</strong>
        </div>
        <div class="detail-grid">
          <div class="mini"><div class="label">Active platforms</div><div class="value">${esc(data.active_platform_count)}</div></div>
          <div class="mini"><div class="label">Admin platforms</div><div class="value">${esc(data.admin_platform_count)}</div></div>
          <div class="mini"><div class="label">Dormancy days</div><div class="value">${esc(data.dormancy_days)}</div></div>
        </div>
        <div class="detail-grid">
          <div class="mini"><div class="label">Graph degree</div><div class="value">${esc(graphMetrics.graph_degree ?? 0)}</div></div>
          <div class="mini"><div class="label">Privilege paths</div><div class="value">${esc(graphMetrics.privilege_path_count ?? 0)}</div></div>
          <div class="mini"><div class="label">Lateral paths</div><div class="value">${esc(graphMetrics.lateral_movement_paths ?? 0)}</div></div>
        </div>
        ${renderGraph(graph)}
        <div class="detail-grid">
          <div class="mini"><h3>Evidence</h3>${list(findings, f => esc(f))}</div>
          <div class="mini"><h3>Accounts</h3>${list(data.accounts, a => `${esc(a.platform)}: ${esc(a.username)} (${esc(a.account_status)})`)}</div>
          <div class="mini"><h3>Remediation</h3>${list(data.actions, a => `<strong>${esc(a.priority)}</strong> ${esc(a.platform)} - ${esc(a.action)}`)}</div>
        </div>
        <div class="detail-grid">
          <div class="mini"><h3>Direct roles</h3>${list(data.roles, r => `${esc(r.platform)}: ${esc(r.role)}`)}</div>
          <div class="mini"><h3>Inherited groups</h3>${list(data.groups, g => esc(g.group_name))}</div>
          <div class="mini"><h3>Anomaly reasons</h3>${list(graphMetrics.anomaly_reasons || [], reason => esc(reason))}</div>
        </div>
        <div class="mini"><h3>Audit event mix</h3>${list(data.events, e => `${esc(e.platform)} ${esc(e.event_type)}: ${esc(e.count)} events`)}</div>
      `;
    }

    $('apply').addEventListener('click', loadRisks);
    $('search').addEventListener('keydown', event => {
      if (event.key === 'Enter') loadRisks();
    });
    loadSummary().then(() => Promise.all([loadRisks(), loadIncidents(), loadCompliance()]));
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def send_text(self, text, content_type="text/html; charset=utf-8", status=200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value):
        self.send_text(json.dumps(value), "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_text(INDEX_HTML)
        elif parsed.path == "/report":
            self.send_text(executive_report_html())
        elif parsed.path == "/api/summary":
            self.send_json(api_summary())
        elif parsed.path == "/api/risks":
            self.send_json(api_risks(parsed.query))
        elif parsed.path == "/api/identity":
            self.send_json(api_identity(parsed.query))
        elif parsed.path == "/api/graph":
            self.send_json(api_graph(parsed.query))
        elif parsed.path == "/api/incidents":
            self.send_json(api_incidents())
        elif parsed.path == "/api/compliance":
            self.send_json(api_compliance())
        elif parsed.path == "/download/report.csv":
            self.send_response(200)
            body = report_csv().encode("utf-8")
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=identity_risk_report.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/download/playbook.csv":
            self.send_response(200)
            body = playbook_csv().encode("utf-8")
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=remediation_playbook.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_text("Not found", "text/plain; charset=utf-8", 404)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ensure_ready()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Dashboard running at http://{HOST}:{PORT}")
    server.serve_forever()
