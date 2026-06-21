# Sample Risk Report

## Executive Summary

The prototype assessed 300 identities across AD, AWS, Okta, Salesforce, and GitHub. It found high-risk privilege hygiene issues that single-platform reviews would miss, especially terminated identities with active accounts elsewhere, cross-platform administrative access, and old API tokens.

## Current Detection Snapshot

| Metric | Result |
| --- | ---: |
| Identities assessed | 300 |
| Platform accounts assessed | 1,800 |
| Audit events assessed | 15,000 |
| Remediation actions generated | 506 |
| Critical identities | 14 |
| High identities | 40 |
| Graph nodes | 2,670 |
| Graph edges | 17,770 |
| Graph-clustered incidents | 5 |

## Top Risk Themes

| Theme | Why It Matters | Example Remediation |
| --- | --- | --- |
| Offboarding gaps | A disabled or terminated identity can still be used through another platform | Disable remaining active accounts after HR validation |
| Cross-platform admin | One compromised identity has a larger blast radius across AD, cloud, and SaaS | Remove admin roles unless an approved exception exists |
| Old API tokens | Long-lived tokens can survive password resets and vendor breaches | Rotate tokens and enforce maximum token age |
| Privilege spikes | New admin access can indicate escalation or an unclosed temporary exception | Validate the role change ticket and expiry |
| Behavioral deviation | Repeated token use, role changes, or off-hour activity increases abuse likelihood | Review recent audit events before closing the finding |
| Hidden graph paths | Group membership can grant effective admin access without direct role assignment | Remove nested group membership or split high-risk groups |

## Audit Evidence

Each identity finding includes:

- active and disabled platform accounts
- direct roles and inherited group privileges
- local graph neighbors and anomaly score
- lateral movement and inherited privilege path counts
- audit event counts and latest activity
- token age and recent role history
- severity, score, and top finding
- platform-specific remediation actions

## Recommended Review Order

1. Work `CRITICAL` identities first.
2. Prioritize identities with offboarding gaps and cross-platform admin together.
3. Rotate tokens older than 365 days.
4. Validate recent admin changes against change tickets.
5. Export the dashboard CSV and track remediation status in the access review process.
