DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS platform_accounts;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS group_membership;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS employee_role_history;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS offboarding_records;
DROP TABLE IF EXISTS risk_findings;
DROP TABLE IF EXISTS identity_risk_scores;
DROP TABLE IF EXISTS remediation_actions;
DROP TABLE IF EXISTS graph_nodes;
DROP TABLE IF EXISTS graph_edges;
DROP TABLE IF EXISTS identity_graph_metrics;
DROP TABLE IF EXISTS risk_incidents;

CREATE TABLE employees (
    employee_id TEXT PRIMARY KEY,
    employee_name TEXT,
    department TEXT,
    employee_status TEXT,
    termination_date TEXT
);

CREATE TABLE platform_accounts (
    account_id TEXT PRIMARY KEY,
    employee_id TEXT,
    platform TEXT,
    username TEXT,
    account_status TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE role_assignments (
    employee_id TEXT,
    platform TEXT,
    role TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE group_membership (
    employee_id TEXT,
    group_name TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    employee_id TEXT,
    platform TEXT,
    event_type TEXT,
    timestamp TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE employee_role_history (
    employee_id TEXT,
    platform TEXT,
    old_role TEXT,
    new_role TEXT,
    change_date TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE api_tokens (
    token_id TEXT PRIMARY KEY,
    employee_id TEXT,
    token_age_days INTEGER,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE offboarding_records (
    employee_id TEXT,
    issue TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE risk_findings (
    employee_id TEXT,
    finding TEXT,
    severity TEXT,
    risk_score INTEGER,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE identity_risk_scores (
    employee_id TEXT PRIMARY KEY,
    employee_name TEXT,
    department TEXT,
    severity TEXT,
    risk_score INTEGER,
    platform_count INTEGER,
    active_platform_count INTEGER,
    role_count INTEGER,
    admin_platform_count INTEGER,
    dormancy_days INTEGER,
    max_token_age_days INTEGER,
    offboarding_gap INTEGER,
    privilege_spike INTEGER,
    behavioral_deviation INTEGER,
    top_risk TEXT,
    evidence_json TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE remediation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT,
    platform TEXT,
    action TEXT,
    priority TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE graph_nodes (
    node_id TEXT PRIMARY KEY,
    node_type TEXT,
    label TEXT,
    platform TEXT,
    risk_score INTEGER DEFAULT 0
);

CREATE TABLE graph_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT,
    target_id TEXT,
    edge_type TEXT,
    platform TEXT,
    weight REAL DEFAULT 1,
    evidence TEXT,
    FOREIGN KEY (source_id) REFERENCES graph_nodes(node_id),
    FOREIGN KEY (target_id) REFERENCES graph_nodes(node_id)
);

CREATE TABLE identity_graph_metrics (
    employee_id TEXT PRIMARY KEY,
    graph_degree INTEGER,
    privilege_path_count INTEGER,
    inherited_privilege_count INTEGER,
    lateral_movement_paths INTEGER,
    anomaly_score INTEGER,
    anomaly_reasons TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE risk_incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    incident_score INTEGER,
    category TEXT,
    employee_ids TEXT,
    narrative TEXT,
    remediation TEXT
);
