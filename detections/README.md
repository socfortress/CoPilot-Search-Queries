# Detection Library

**3,067 detection rules** for OpenSearch / Wazuh Indexer, one YAML file each.

Rules are filed by **the log source their query actually reads** — the `data_win_system_eventID`,
Windows channel, or `data_*` field family the search filters on. Not by tactic, not by threat name.
If you know which telemetry you have onboarded, you know exactly which folders are live for you,
and every rule has exactly one home.

## At a glance

| | |
| --- | --- |
| Rules | **3,067** across 33 log sources |
| Severity | 🔴 critical 150 · 🟠 high 1527 · 🟡 medium 1310 · 🔵 low 80 |
| Status | experimental 2473, production 594 |
| ATT&CK coverage | 368 distinct techniques |
| Provenance | 2524 Sigma-derived, 543 written for this repo |

## Where to start

Pick the folder matching the telemetry you collect. The three that carry most of the value:

| If you have… | Go to | Rules |
| --- | --- | --- |
| Sysmon | [`eid_01_process_creation`](./eid_01_process_creation/) — process creation, the richest single source | 1496 |
| PowerShell logging | [`eid_4104_script_block_logging`](./eid_4104_script_block_logging/) — de-obfuscated script text | 250 |
| Windows audit policy | [`security_eventlog`](./security_eventlog/) — logon, account and object access auditing | 141 |

## All log sources

### Sysmon <sub>· Windows · 2282 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`eid_01_process_creation`](./eid_01_process_creation/) | 1496 | **Process Creation** — Every process launched on the host, with full command line, parent process, hashes and signature status. |
| [`eid_03_network_connection`](./eid_03_network_connection/) | 38 | **Network Connection** — Outbound and inbound TCP/UDP connections attributed to the initiating process. |
| [`eid_06_driver_loaded`](./eid_06_driver_loaded/) | 7 | **Driver Loaded** — Kernel driver loads with signature status — the primary source for bring-your-own-vulnerable-driver (BYOVD) detection. |
| [`eid_07_image_loaded`](./eid_07_image_loaded/) | 113 | **Image Loaded** — DLL and module loads into a process, used to catch DLL side-loading, hijacking and in-memory tooling. |
| [`eid_08_create_remote_thread`](./eid_08_create_remote_thread/) | 12 | **CreateRemoteThread** — A thread created in another process — a direct signal of classic code injection. |
| [`eid_10_process_access`](./eid_10_process_access/) | 24 | **Process Access** — One process opening a handle to another, with the requested access mask. |
| [`eid_11_file_created`](./eid_11_file_created/) | 201 | **File Created** — File creation events, used for dropper, staging, startup-folder persistence and ransomware note detection. |
| [`eid_12_13_14_registry_events`](./eid_12_13_14_registry_events/) | 40 | **Registry Events** — Rules that search key creation, value set and key rename together, because the technique can surface as any of the three. |
| [`eid_12_registry_key_created_deleted`](./eid_12_registry_key_created_deleted/) | 14 | **Registry Key Created / Deleted** — Registry key creation and deletion, distinct from value writes. |
| [`eid_13_registry_value_set`](./eid_13_registry_value_set/) | 266 | **Registry Value Set** — Registry value writes — the main persistence, defence-evasion and configuration-tampering source. |
| [`eid_15_file_create_stream_hash`](./eid_15_file_create_stream_hash/) | 8 | **FileCreateStreamHash** — Alternate data stream creation, including the `Zone.Identifier` mark-of-the-web that reveals a file's download origin. |
| [`eid_16_sysmon_config_changed`](./eid_16_sysmon_config_changed/) | 1 | **Sysmon Configuration Changed** — Sysmon's own configuration being changed — tampering with the sensor itself. |
| [`eid_17_18_pipe_events`](./eid_17_18_pipe_events/) | 17 | **Named Pipe Events** — Named pipe creation (17) and connection (18). |
| [`eid_19_20_21_wmi_events`](./eid_19_20_21_wmi_events/) | 4 | **WMI Events** — WMI permanent event filters (19), consumers (20) and filter-to-consumer bindings (21) — the classic fileless persistence triad. |
| [`eid_22_dns_query`](./eid_22_dns_query/) | 25 | **DNS Query** — DNS lookups attributed to the requesting process, used for C2 beaconing, exfiltration domains and tooling fingerprints. |
| [`eid_23_26_file_delete`](./eid_23_26_file_delete/) | 11 | **File Delete** — File deletion with archiving (23) and deletion detected without archiving (26) — anti-forensics and ransomware cleanup. |
| [`eid_27_28_29_file_block`](./eid_27_28_29_file_block/) | 3 | **File Block & Executable Detected** — Blocked executable writes (27), blocked file shredding (28) and executable file detection (29) — Sysmon acting as a preventive control. |
| [`multi_event`](./multi_event/) | 2 | **Multi-Event Rules** — Rules whose query spans more than one Sysmon event ID without matching one of the canonical event families above. |

### PowerShell <sub>· Windows · 270 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`eid_4103_module_logging`](./eid_4103_module_logging/) | 20 | **Module Logging** — Pipeline execution details: the commands and parameter bindings PowerShell actually invoked, after aliases and obfuscation are resolved. |
| [`eid_4104_script_block_logging`](./eid_4104_script_block_logging/) | 250 | **Script Block Logging** — The de-obfuscated text of every script block PowerShell compiles — the highest-fidelity view of what a script actually does, regardless of encoding or obfuscation. |

### Windows event logs <sub>· Windows · 252 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`application_eventlog`](./application_eventlog/) | 25 | **Windows Application Event Log** — Application-provider records: MsiInstaller, ESENT, Application Error crash events, Windows Backup, software restriction policies and MSSQL auditing. |
| [`defender_operational`](./defender_operational/) | 15 | **Microsoft Defender Operational Log** — Defender's own telemetry: malware detections and remediation outcomes, exclusion changes, and real-time protection being disabled. |
| [`security_eventlog`](./security_eventlog/) | 141 | **Windows Security Event Log** — Native Windows audit records: logon and account activity, account and group management, object access, directory service changes, privilege use and audit policy changes. |
| [`system_eventlog`](./system_eventlog/) | 67 | **Windows System Event Log** — Service Control Manager, Kerberos KDC, NetLogon, LSA, DHCP and driver providers. |
| [`task_scheduler_operational`](./task_scheduler_operational/) | 4 | **Windows Task Scheduler Operational Log** — Scheduled task registration and execution, complementary to Security 4698 and Sysmon process creation. |

### Linux <sub>· Linux · 227 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`auditd`](./auditd/) | 16 | **Linux Auditd** — Kernel audit records — syscall execution, file access and privilege changes — decoded into `data_audit_*` fields. |
| [`syslog`](./syslog/) | 94 | **Linux Syslog & auth.log** — Rules that match the raw log line via `full_log`, covering distributions and daemons without structured decoders. |
| [`tetragon`](./tetragon/) | 117 | **Cilium Tetragon** — eBPF-based process execution events from Cilium Tetragon, giving Linux endpoints Sysmon-grade process telemetry with binary, arguments, parent and credentials. |

### Microsoft 365 <sub>· Cloud · 34 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`Entra_id`](./Entra_id/) | 13 | **Microsoft Entra ID (Azure AD)** — Identity-plane activity: conditional access bypass, MFA being disabled, federation and domain changes, and other tenant-level identity backdoors. |
| [`Exchange`](./Exchange/) | 5 | **Microsoft Exchange Online** — Mailbox-level abuse: inbox rules, external forwarding and mass mail deletion used to hide activity or exfiltrate mail. |
| [`sharepoint_onedrive`](./sharepoint_onedrive/) | 4 | **SharePoint & OneDrive** — File-plane activity: mass download, mass deletion and mass external sharing — the strongest data-exfiltration signals in M365. |
| [`threat_intelligence`](./threat_intelligence/) | 12 | **Microsoft 365 Threat Intelligence** — Verdicts raised by Defender for Office 365: malicious mail, URLs and attachments detected in the tenant. |

### Web <sub>· Web · 2 rules</sub>

| Folder | Rules | What it covers |
| --- | --- | --- |
| [`web`](./web/) | 2 | **Web Server Access Logs** — Requests to internet-facing applications, used to catch exploitation of public-facing services and scripted tooling by user agent. |

## How a rule is filed

Placement is derived from the query itself, first match wins:

| # | Test on the rule's `search:` block | Destination |
| --- | --- | --- |
| 1 | `data_office365_*` fields, or an Office 365 `workload:` | the matching M365 workload folder |
| 2 | `data_process_exec_*` / `data_audit_*` fields | `tetragon` / `auditd` |
| 3 | PowerShell operational event ID 4103 or 4104 | `eid_4103_*` / `eid_4104_*` |
| 4 | query touches only Sysmon event IDs | `eid_<nn>_<event>` |
| 5 | `data_source` names a Windows channel | `security_` / `system_` / `application_eventlog`, `defender_`/`task_scheduler_operational` |
| 6 | matches on `full_log` / `rule_groups` only | `syslog` |
| 7 | web server fields | `web` |

Sysmon event IDs that form one logical family share a folder — **12/13/14** (registry),
**17/18** (named pipes), **19/20/21** (WMI subscriptions), **23/26** (file delete) and
**27/28/29** (file block). Rules routinely search all members of a family at once, so
splitting them per ID would file the same detection arbitrarily.

> **Note on folder names.** After flattening, Sysmon and PowerShell folders both start with
> `eid_`. Sysmon IDs are 1–29; PowerShell IDs are 4103 and 4104. The **Platform** and
> **Log source** line at the top of each folder README always states which product it is.

## Conventions

- One rule per file, filename in lowercase `snake_case` matching the rule's subject.
- Where two distinct rules (different `id:`) shared a filename, the one carrying a UUID `id:`
  keeps the plain name and the other gains an `_alt` suffix.
- Every folder has a generated `README.md` indexing its rules with severity, risk score and
  ATT&CK techniques.
- Rule schema is documented in [`../docs/SCHEMA.md`](../docs/SCHEMA.md).

## Adding a rule

1. Write the YAML against [`../docs/SCHEMA.md`](../docs/SCHEMA.md); copy a neighbour in the
   target folder to inherit its field naming and exclusion patterns.
2. File it by the routing table above — the folder must match what `search.query` reads.
3. Validate: `python src/detection_loader.py validate detections/<folder>/<rule>.yaml`
4. Regenerate the folder index so the rule appears in the table.

---

<sub>Generated index — regenerate after adding, moving or editing rules.</sub>
