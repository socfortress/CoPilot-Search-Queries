# Microsoft Entra ID (Azure AD)

**Platform** `Cloud` · **Log source** Office 365 Management Activity API — `AzureActiveDirectory` workload · **13 rules**

Identity-plane activity: conditional access bypass, MFA being disabled, federation and domain changes, and other tenant-level identity backdoors.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 6 · 🟡 medium 7 |
| Status | experimental 13 |
| ATT&CK techniques | 16 distinct |
| Provenance | 4 Sigma-derived, 9 written for this repo |

## Onboarding

Register an Entra ID application with Office 365 Management Activity API permissions and configure the Wazuh `office365` module to subscribe to the `AzureActiveDirectory` workload.

## Top ATT&CK techniques

[`T1098`](https://attack.mitre.org/techniques/T1098/) (2) · [`T1484.002`](https://attack.mitre.org/techniques/T1484/002/) (2) · [`T1098.003`](https://attack.mitre.org/techniques/T1098/003/) (2) · [`T1078`](https://attack.mitre.org/techniques/T1078/) (1) · [`T1556.006`](https://attack.mitre.org/techniques/T1556/006/) (1) · [`T1556.009`](https://attack.mitre.org/techniques/T1556/009/) (1) · [`T1484`](https://attack.mitre.org/techniques/T1484/) (1) · [`T1531`](https://attack.mitre.org/techniques/T1531/) (1)

## Rules (13)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Azure Login Bypassing Conditional Access Policies | 🟠 high | 75 | `T1078` | [`azure_login_bypassing_conditional_access_policies.yaml`](./azure_login_bypassing_conditional_access_policies.yaml) |
| Disabling Multi Factor Authentication | 🟠 high | 75 | `T1556.006` | [`disabling_multi_factor_authentication.yaml`](./disabling_multi_factor_authentication.yaml) |
| M365 Directory Role Assigned | 🟠 high | 70 | `T1098.003` | [`m365_privileged_role_assignment.yaml`](./m365_privileged_role_assignment.yaml) |
| M365 OAuth Consent or App Permission Granted | 🟠 high | 65 | `T1528`, `T1098.003` | [`m365_oauth_consent_or_app_permission_granted.yaml`](./m365_oauth_consent_or_app_permission_granted.yaml) |
| M365 Password Spray From One IP | 🟠 high | 70 | `T1110.003` | [`m365_password_spray_single_ip.yaml`](./m365_password_spray_single_ip.yaml) |
| M365 Service Principal or Application Credentials Added | 🟠 high | 75 | `T1098.001` | [`m365_service_principal_credentials_added.yaml`](./m365_service_principal_credentials_added.yaml) |
| M365 Application or Service Principal Owner Added | 🟡 medium | 50 | `T1098` | [`m365_application_owner_added.yaml`](./m365_application_owner_added.yaml) |
| M365 Bulk Admin Password Resets by One Actor | 🟡 medium | 55 | `T1098`, `T1531` | [`m365_bulk_admin_password_resets.yaml`](./m365_bulk_admin_password_resets.yaml) |
| M365 Conditional Access or Authentication Policy Changed | 🟡 medium | 55 | `T1556.009`, `T1484` | [`m365_authentication_policy_changed.yaml`](./m365_authentication_policy_changed.yaml) |
| M365 Cross-Tenant Access or Partner Relationship Changed | 🟡 medium | 60 | `T1484.002`, `T1199` | [`m365_cross_tenant_or_partner_relationship_changed.yaml`](./m365_cross_tenant_or_partner_relationship_changed.yaml) |
| M365 Failed Sign-in Burst Against One Account | 🟡 medium | 50 | `T1110.001`, `T1110.004` | [`m365_failed_signin_burst_single_account.yaml`](./m365_failed_signin_burst_single_account.yaml) |
| New Federated Domain Added | 🟡 medium | 50 | `T1484.002` | [`new_federated_domain_added.yaml`](./new_federated_domain_added.yaml) |
| Suspicious Email Delivered In Microsoft 365 | 🟡 medium | 50 | `T1566.001`, `T1566.002` | [`suspicious_email_delivered_in_microsoft_365.yaml`](./suspicious_email_delivered_in_microsoft_365.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
