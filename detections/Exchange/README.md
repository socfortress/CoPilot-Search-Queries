# Microsoft Exchange Online

**Platform** `Cloud` · **Log source** Office 365 Management Activity API — `Exchange` workload · **5 rules**

Mailbox-level abuse: inbox rules, external forwarding and mass mail deletion used to hide activity or exfiltrate mail.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 4 · 🟡 medium 1 |
| Status | production 3, experimental 2 |
| ATT&CK techniques | 6 distinct |
| Provenance | 1 Sigma-derived, 4 written for this repo |

## Onboarding

Subscribe the Wazuh `office365` module to the `Exchange` workload. Mailbox auditing must be enabled on the tenant.

## Top ATT&CK techniques

[`T1114.003`](https://attack.mitre.org/techniques/T1114/003/) (2) · [`T1564.008`](https://attack.mitre.org/techniques/T1564/008/) (1) · [`T1070.008`](https://attack.mitre.org/techniques/T1070/008/) (1) · [`T1114`](https://attack.mitre.org/techniques/T1114/) (1) · [`T1114.002`](https://attack.mitre.org/techniques/T1114/002/) (1) · [`T1136.003`](https://attack.mitre.org/techniques/T1136/003/) (1)

## Rules (5)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| M365 Email Forwarding Created | 🟠 high | 70 | `T1114.003` | [`m365_email_forwarding_created.yaml`](./m365_email_forwarding_created.yaml) |
| M365 Inbox Rule Created | 🟠 high | 60 | `T1114.003`, `T1564.008` | [`m365_inbox_rule_created.yaml`](./m365_inbox_rule_created.yaml) |
| M365 Mass Email Deletion - Evidence Wipe | 🟠 high | 70 | `T1070.008`, `T1114` | [`m365_mass_email_deletion_evidence_wipe.yaml`](./m365_mass_email_deletion_evidence_wipe.yaml) |
| M365 One Identity Reading Many Mailboxes | 🟠 high | 70 | `T1114.002` | [`m365_one_identity_reading_many_mailboxes.yaml`](./m365_one_identity_reading_many_mailboxes.yaml) |
| New Federated Domain Added - Exchange | 🟡 medium | 50 | `T1136.003` | [`new_federated_domain_added_exchange.yaml`](./new_federated_domain_added_exchange.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
