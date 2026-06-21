# Data Dictionary

## Source Tables

### employees

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key used to correlate accounts across platforms |
| `employee_name` | Display name |
| `department` | Business department |
| `employee_status` | HR lifecycle state such as Active or Terminated |
| `termination_date` | Date the identity left the company, when available |

### platform_accounts

| Column | Meaning |
| --- | --- |
| `account_id` | Platform account identifier |
| `employee_id` | Canonical identity key |
| `platform` | AD, AWS, Okta, Salesforce, or GitHub |
| `username` | Platform-specific username |
| `account_status` | Active or Disabled |

### role_assignments

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key |
| `platform` | Platform that grants the role |
| `role` | Direct role such as User, Developer, DomainAdmin, AdministratorAccess, or SuperAdmin |

### group_membership

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key |
| `group_name` | Group that may imply inherited privilege |

Inherited privilege mapping used by the prototype:

| Group | Effective privilege |
| --- | --- |
| `SecurityAdmins` | AD `DomainAdmin` |
| `CloudOps` | AWS `AdministratorAccess` |
| `DevOps` | GitHub `RepositoryAdmin` |

### audit_events

| Column | Meaning |
| --- | --- |
| `event_id` | Audit event identifier |
| `employee_id` | Canonical identity key |
| `platform` | Source platform |
| `event_type` | Activity type such as Login, TokenUse, RoleChange, S3Access, RepoAccess |
| `timestamp` | Event timestamp |

### employee_role_history

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key |
| `platform` | Platform where the role changed |
| `old_role` | Previous role |
| `new_role` | New role |
| `change_date` | Date of change |

### api_tokens

| Column | Meaning |
| --- | --- |
| `token_id` | API token identifier |
| `employee_id` | Canonical identity key |
| `token_age_days` | Age of token since issue or rotation |

### offboarding_records

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key |
| `issue` | Known offboarding issue label |

### risk_findings

| Column | Meaning |
| --- | --- |
| `employee_id` | Canonical identity key |
| `finding` | Ground-truth or seed finding from the dataset |
| `severity` | Seed severity |
| `risk_score` | Seed score |

## Derived Tables

### identity_risk_scores

Stores the prototype's computed risk score, severity, evidence, privilege counts, dormancy, token age, and top finding for every identity.

### remediation_actions

Stores platform-specific recommended actions such as disabling active orphaned accounts, reviewing admin entitlements, rotating old API tokens, and validating recent admin changes.

### graph_nodes

Stores Option A graph nodes for identities, accounts, platforms, roles, groups, tokens, departments, and event types.

### graph_edges

Stores relationships between nodes, including account ownership, role assignment, group inheritance, token ownership, and audit behavior.

### identity_graph_metrics

Stores per-identity graph degree, privilege path counts, hidden inherited privilege counts, lateral movement path counts, anomaly score, and anomaly reasons.

### risk_incidents

Stores graph-clustered incidents with narrative and remediation guidance.
