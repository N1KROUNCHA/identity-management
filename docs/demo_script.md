# Demo Script

## Opening Pitch

This prototype detects identity sprawl and privileged access abuse across AD, AWS, Okta, Salesforce, and GitHub. The key idea is that one platform may look safe by itself, but the graph shows how accounts, roles, groups, tokens, and audit activity combine into risky access paths.

## Demo Steps

1. Open the dashboard at `http://127.0.0.1:8080`.
2. Show the summary cards: identities assessed, critical and high-risk identities, graph nodes, graph edges, and graph-clustered incidents.
3. Open the graph-clustered incidents section.
4. Explain that standalone findings are grouped into response-ready incidents such as offboarding gaps, lateral admin paths, hidden inherited privilege, token exposure, and account manipulation.
5. Filter the backlog to `CRITICAL`.
6. Click a top identity.
7. Show the local identity graph, graph anomaly score, privilege path count, lateral movement path count, direct roles, inherited groups, and remediation actions.
8. Show the compliance evidence map.
9. Open the executive report at `/report`.
10. Download the remediation playbook CSV.

## Judge-Friendly Talking Points

- Option B is the hygiene baseline: risk scoring, dormant privilege, offboarding gaps, tokens, and remediation backlog.
- Option A is the graph intelligence layer: identities connect to accounts, roles, groups, tokens, platforms, and event types.
- The graph turns noisy alerts into clustered incidents.
- The system explains every score with evidence, which is important for access review and audit approval.

## Expected Results

| Output | Expected Value |
| --- | ---: |
| Identities assessed | 300 |
| Platform accounts | 1,800 |
| Audit events | 15,000 |
| Graph nodes | 2,670 |
| Graph edges | 17,770 |
| Graph-clustered incidents | 5 |
| Remediation actions | 506 |

