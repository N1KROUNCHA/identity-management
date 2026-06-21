# Architecture And AI Approach

## Architecture

```text
CSV dataset
  -> SQLite ingestion
  -> deterministic privilege/risk engine
  -> identity graph builder
  -> graph anomaly metrics
  -> incident clustering
  -> browser dashboard and CSV export
```

## Data Flow

1. `src/ingest.py` loads the nine source CSV files into SQLite.
2. `src/risk_engine.py` computes effective privilege, risk scores, severity, evidence, and remediation actions.
3. `src/graph_engine.py` builds the graph model and computes graph metrics.
4. `app.py` exposes dashboard APIs for summaries, ranked identities, identity drill-down, graph neighbors, and incident clusters.

## Graph Model

| Node Type | Example |
| --- | --- |
| Identity | `EMP0006 Employee_6` |
| Account | `u6_aws (Active)` |
| Platform | `AWS` |
| Role | `AdministratorAccess` |
| Group | `CloudOps` |
| Token | `TOK00006 (589d)` |
| Event | `TokenUse` |
| Department | `Engineering` |

| Edge Type | Meaning |
| --- | --- |
| `has_account` | Identity owns a platform account |
| `exists_on` | Account belongs to a platform |
| `assigned_role` | Identity has a direct role |
| `member_of` | Identity belongs to a group |
| `inherits_role` | Group grants effective privilege |
| `owns_token` | Identity has an API token |
| `performed` | Identity generated audit event activity |

## Graph Intelligence

The prototype computes these per-identity graph metrics:

- `graph_degree`: number of directly connected graph neighbors
- `privilege_path_count`: direct or inherited paths into privileged roles
- `inherited_privilege_count`: hidden admin paths from group membership
- `lateral_movement_paths`: pairwise admin paths across multiple platforms
- `anomaly_score`: peer-baseline score from connectivity, token activity, role-change activity, inherited privilege, and lateral movement potential

## AI/ML Approach

The current implementation uses explainable, deterministic anomaly scoring because the demo environment has no extra Python packages installed. It mirrors the Option A ML idea by comparing each identity against peer baselines:

- broad graph connectivity above the population baseline
- token usage above the population baseline
- role-change activity above the population baseline
- hidden inherited privilege
- cross-platform admin paths
- long-lived API token exposure

In a production or package-enabled version, this can be upgraded directly:

- Load graph features into scikit-learn Isolation Forest.
- Use NetworkX centrality and shortest-path measures.
- Cluster incidents with connected components or community detection.
- Add an LLM-generated narrative layer that summarizes evidence and recommends platform-specific revocation commands.

## Incident Clustering

The prototype clusters individual findings into five response-ready incident groups:

- offboarding gaps
- lateral admin movement paths
- hidden inherited privilege
- token exposure
- role-change/account manipulation

Each incident includes severity, score, linked identities, narrative, and remediation guidance.
