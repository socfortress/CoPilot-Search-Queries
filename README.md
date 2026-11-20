# CoPilot-Search-Queries

A version-controlled detection library and rule framework for **OpenSearch / Wazuh Indexer**.

Every detection is a single self-contained YAML file: the OpenSearch query, the parameters it
takes, the alert it raises, its MITRE ATT&CK mapping, and the notes an analyst needs to deploy
and tune it. The YAML query structure maps 1:1 onto OpenSearch Query DSL, so what you read is
what gets executed.

| | |
| --- | --- |
| **Detection rules** | **3,067** — see [`detections/README.md`](detections/README.md) |
| Log sources covered | 33 — Sysmon, PowerShell, Windows event logs, Linux (Tetragon / auditd / syslog), Microsoft 365, web |
| ATT&CK coverage | 368 distinct techniques |
| Severity mix | 🔴 critical 150 · 🟠 high 1,527 · 🟡 medium 1,310 · 🔵 low 80 |
| Backend | OpenSearch / Wazuh Indexer (Query DSL), with a parallel Graylog query on most rules |

---

## The detection library

Rules are filed by **the log source their query actually reads** — not by tactic or threat name.
Onboard a telemetry source, and the folder named after it is immediately relevant to you.

```
detections/
├── eid_01_process_creation/            1496   Sysmon — process creation
├── eid_13_registry_value_set/           266   Sysmon — registry writes
├── eid_4104_script_block_logging/       250   PowerShell — script block text
├── eid_11_file_created/                 201   Sysmon — file creation
├── security_eventlog/                   141   Windows Security audit records
├── tetragon/                            117   Linux — eBPF process execution
│   … 27 more log sources
```

**→ [Browse the full index](detections/README.md)** — every folder has its own README listing
its rules with severity, risk score and ATT&CK techniques, plus the onboarding steps for that
telemetry source.

---

## Quick start

### Requirements

- Python 3.10+
- `pyyaml` — required, for loading rules
- `opensearch-py` — optional, only needed to execute rules against a cluster

```bash
pip install pyyaml opensearch-py
```

> **Windows:** the CLI prints `✓` / `✗`, which crashes on the default `cp1252` console.
> Run `set PYTHONIOENCODING=utf-8` (cmd) or `$env:PYTHONIOENCODING='utf-8'` (PowerShell) first.

### Validate a rule

```bash
python src/detection_loader.py validate detections/eid_08_create_remote_thread/password_dumper_remote_thread_in_lsass.yaml
```
```
✓ Valid rule: Password Dumper Remote Thread in LSASS (v1)
  ID: f239b326-2f41-4d6b-9dfa-c846a60ef505
  Status: production
  Parameters: ['AGENT_NAME', 'CUSTOMER_CODE', 'INDEX_PATTERN', 'START_TIME', 'END_TIME']
```

### Other commands

```bash
# Inspect a rule (add --json for the raw YAML as JSON)
python src/detection_loader.py show detections/<folder>/<rule>.yaml

# List every rule in a folder, with status and ATT&CK mapping
python src/detection_loader.py list detections/eid_22_dns_query/

# Render a ready-to-run curl command with parameters substituted
python src/detection_loader.py curl detections/<folder>/<rule>.yaml \
    --host https://wazuh-indexer:9200 --user admin --password secret \
    -p AGENT_NAME "DESKTOP-AM0HLGE" \
    -p CUSTOMER_CODE "lab" \
    -p INDEX_PATTERN "wazuh-lab_*"
```

### Python API

```python
from detection_loader import DetectionRule, OpenSearchExecutor, RuleLoader

rule = DetectionRule.from_file('detections/eid_22_dns_query/dns_query_by_finger_utility.yaml')

executor = OpenSearchExecutor(host='https://wazuh-indexer:9200', auth=('admin', 'password'))
results = executor.execute(rule, parameters={
    'AGENT_NAME': 'DESKTOP-AM0HLGE',
    'CUSTOMER_CODE': 'lab',
    'INDEX_PATTERN': 'wazuh-lab_*',
    'START_TIME': 'now-24h',
    'END_TIME': 'now',
})
print(f"{results['total']} matches in {results['took_ms']}ms")

# ...or get formatted alerts instead of raw hits
alerts = executor.execute_with_alert(rule, parameters={...})

# Load a whole folder and query it by ATT&CK technique
loader = RuleLoader('detections/')
loader.load_all()
lsass_rules = loader.get_rules_by_mitre('T1003.001')
```

---

## Anatomy of a rule

Trimmed from
[`password_dumper_remote_thread_in_lsass.yaml`](detections/eid_08_create_remote_thread/password_dumper_remote_thread_in_lsass.yaml):

```yaml
# --- identity -------------------------------------------------------------
name: Password Dumper Remote Thread in LSASS
id: f239b326-2f41-4d6b-9dfa-c846a60ef505      # stable; UUID v4 preferred
version: 1
schema_version: "1.0"
date: "2021-06-21"
author: Thomas Patzke
status: production                             # production | experimental | deprecated
type: TTP                                      # TTP | Anomaly | Correlation | Hunting

source:                                        # optional — provenance for converted rules
  format: sigma
  repository: SigmaHQ/sigma
  license: DRL-1.1

description: >
  Detects password dumper activity by monitoring remote thread creation EventID 8
  in combination with the lsass.exe process as TargetImage.

data_source:
  - Sysmon EventID 8 - CreateRemoteThread

# --- the search -----------------------------------------------------------
search:
  index_pattern: "${INDEX_PATTERN}"
  size: 100
  sort:
    - timestamp: desc
  query:                                       # verbatim OpenSearch Query DSL
    bool:
      must:
        - term:
            agent_name: "${AGENT_NAME}"
        - term:
            data_win_system_eventID: "8"
        - wildcard:
            data_win_eventdata_targetImage:
              value: "*\\\\lsass.exe"
              case_insensitive: true
        - range:
            timestamp: { gte: "${START_TIME}", lte: "${END_TIME}" }
  _source:                                     # fields returned with each hit
    - timestamp
    - agent_name
    - data_win_eventdata_targetImage

# --- runtime inputs -------------------------------------------------------
parameters:
  AGENT_NAME:
    description: "Target agent/host name"
    type: string
    required: true
    example: "DESKTOP-AM0HLGE"
  START_TIME:
    type: datetime
    default: "now-24h"

# --- analyst context ------------------------------------------------------
how_to_implement: >
  Requires Sysmon EventID 8 enabled and the Microsoft-Windows-Sysmon/Operational
  channel collected by the Wazuh agent.
known_false_positives: >
  Antivirus products. Baseline expected activity before automating response.
references:
  - https://attack.mitre.org/techniques/T1003/001/

# --- what fires -----------------------------------------------------------
response:
  message: >                                   # $field$ is filled from the hit
    Password Dumper Remote Thread in LSASS detected on host $agent_name$.
  risk_score: 75                               # 0–100
  severity: high                               # low | medium | high | critical
  risk_objects:                                # entities that accrue risk
    - field: agent_name
      type: system
      score: 75
  threat_objects:                              # observables to pivot on
    - field: data_win_eventdata_targetImage
      type: process

# --- classification -------------------------------------------------------
tags:
  asset_type: Endpoint
  security_domain: endpoint                    # endpoint | network | access | identity
  mitre_attack_id:
    - T1003.001
  custom_tags: [password, dumper, credential_access]
  product: [Wazuh]

# --- parallel backend -----------------------------------------------------
graylog:
  query: 'data_win_system_eventID:"8" AND data_win_eventdata_targetImage:/.*lsass\.exe/'
```

Full field reference: [`docs/SCHEMA.md`](docs/SCHEMA.md).

### Standard parameters

Nearly every rule (3,002 of 3,067) takes the same five, so one parameter set drives the
whole library:

| Parameter | Type | Purpose | Typical value |
| --- | --- | --- | --- |
| `INDEX_PATTERN` | string | Index to search | `wazuh-lab_*` |
| `AGENT_NAME` | string | Host to scope to | `DESKTOP-AM0HLGE` |
| `CUSTOMER_CODE` | string | Tenant label for multi-customer deployments | `lab` |
| `START_TIME` | datetime | Window start | `now-24h` |
| `END_TIME` | datetime | Window end | `now` |

Parameter types: `string`, `datetime`, `integer`, `list`, `bool`. A placeholder that is the
entire value (`"${SIZE}"`) keeps its native type; inline placeholders are stringified.

### Why YAML

The `search.query` block *is* the Query DSL, just in YAML. Nothing is translated:

<table>
<tr><th>OpenSearch JSON</th><th>Rule YAML</th></tr>
<tr><td>

```json
{
  "bool": {
    "must": [
      { "term": { "agent_name": "Amine" } },
      { "wildcard": { "full_log": "*useradd*" } }
    ]
  }
}
```

</td><td>

```yaml
bool:
  must:
    - term:
        agent_name: "Amine"
    - wildcard:
        full_log: "*useradd*"
```

</td></tr>
</table>

---

## Repository layout

```
CoPilot-Search-Queries/
├── detections/              3,067 rules in 33 log-source folders (each with a README)
│   └── README.md            ← the detection library index
├── docs/
│   └── SCHEMA.md            full YAML schema reference
├── examples/
│   └── linux_user_creation.yaml   annotated starter rule
├── src/
│   └── detection_loader.py  loader, validator, executor and CLI
└── README.md
```

---

## Contributing

1. **Write** the rule against [`docs/SCHEMA.md`](docs/SCHEMA.md). Copy a neighbour from the
   folder you are targeting — it will already have the right field names and the environment
   exclusions (`must_not`) that keep false positives down.
2. **File** it by log source, using the routing table in
   [`detections/README.md`](detections/README.md#how-a-rule-is-filed). The folder must match
   what `search.query` actually reads.
3. **Name** the file in lowercase `snake_case`, matching the rule's subject.
4. **Validate**: `python src/detection_loader.py validate detections/<folder>/<rule>.yaml`
5. **Fill in** `how_to_implement` and `known_false_positives` — a rule without tuning guidance
   is not deployable. Mark it `status: experimental` until it has run against real data.
6. **Regenerate** the folder index so the rule shows up in its README table.

Rule provenance is tracked in the optional `source:` block — 2,524 rules here are converted
from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under DRL-1.1, and 543 were written
for this repository.

## Licence

See [LICENSE](LICENSE). Sigma-derived rules retain the licence recorded in their `source:` block.
