# CoPilot-Search-Queries

A modular, version-controlled detection rule framework for OpenSearch (Wazuh-Indexer) environments.

## Features

- **YAML-based rules**: Human-readable, version-controllable detection rules
- **Parameter substitution**: Runtime parameters with `${PARAM}` syntax
- **Direct JSON mapping**: YAML query structure maps 1:1 to OpenSearch (Wazuh-Indexer) Query DSL
- **Metadata-rich**: Full context including MITRE ATT&CK mapping, risk scoring, and implementation notes
- **CLI tools**: Validate, test, and generate curl commands from rules

## Quick Start

### 1. Install Dependencies

```bash
pip install pyyaml OpenSearch (Wazuh-Indexer)-py
```

### 2. Create a Rule

```yaml
# rules/my_detection.yaml
name: My Detection Rule
id: 12345678-1234-1234-1234-123456789012
version: 1
schema_version: "1.0"
date: "2026-01-29"
author: Your Name
status: experimental
type: TTP

description: What this detection finds.

data_source:
  - Wazuh Agent Logs

search:
  index_pattern: "wazuh-*"
  query:
    bool:
      must:
        - term:
            agent_name: "${AGENT_NAME}"
        - range:
            timestamp:
              gte: "${START_TIME}"
              lte: "${END_TIME}"

parameters:
  AGENT_NAME:
    description: "Target agent"
    type: string
    required: true
  START_TIME:
    description: "Start time"
    type: datetime
    default: "now-24h"
  END_TIME:
    description: "End time"
    type: datetime
    default: "now"

how_to_implement: Setup instructions here.
known_false_positives: Expected false positive scenarios.

response:
  message: "Alert on $agent_name$"
  risk_score: 50
  severity: medium

tags:
  asset_type: Linux
  mitre_attack_id:
    - T1234
  security_domain: endpoint
```

### 3. Use the Rule

#### Via Python

```python
from detection_loader import DetectionRule, OpenSearch (Wazuh-Indexer)Executor

# Load rule
rule = DetectionRule.from_file('rules/my_detection.yaml')

# Execute against OpenSearch (Wazuh-Indexer)
executor = OpenSearch (Wazuh-Indexer)Executor(
    host='https://OpenSearch (Wazuh-Indexer):9200',
    auth=('admin', 'password')
)

results = executor.execute(rule, parameters={
    'AGENT_NAME': 'my-host',
    'START_TIME': '2026-01-28 00:00:00.000',
    'END_TIME': '2026-01-28 23:59:59.999'
})

print(f"Found {results['total']} matches")
```

#### Via CLI

```bash
# Validate a rule
python detection_loader.py validate rules/my_detection.yaml

# Generate curl command for testing
python detection_loader.py curl rules/my_detection.yaml \
    --host https://OpenSearch (Wazuh-Indexer):9200 \
    --user admin \
    --password secret \
    -p AGENT_NAME "my-host" \
    -p START_TIME "2026-01-28 00:00:00.000"

# List all rules in directory
python detection_loader.py list rules/
```

## YAML to JSON Query Mapping

The key insight is that YAML's nested structure maps directly to JSON. Here's how your original curl command translates:

### Original JSON Query
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

### Equivalent YAML
```yaml
query:
  bool:
    must:
      - term:
          agent_name: "Amine"
      - wildcard:
          full_log: "*useradd*"
```

## Directory Structure

```
OpenSearch (Wazuh-Indexer)-detection-framework/
├── docs/
│   └── SCHEMA.md           # Full schema documentation
├── rules/
│   ├── examples/
│   │   └── minimal_rule.yaml
│   ├── linux_user_creation.yaml
│   └── lsass_memory_access.yaml
├── src/
│   └── detection_loader.py  # Python loader module
└── README.md
```

## Schema Reference

See [docs/SCHEMA.md](docs/SCHEMA.md) for the complete schema specification.

### Key Sections

| Section | Purpose |
|---------|---------|
| `search.query` | OpenSearch (Wazuh-Indexer) Query DSL in YAML format |
| `parameters` | Runtime variables with `${NAME}` syntax |
| `response` | Alert message templates with `$field$` placeholders |
| `tags.mitre_attack_id` | MITRE ATT&CK technique mapping |

## Parameter Types

| Type | Description | Example |
|------|-------------|---------|
| `string` | Text value | `"Amine"` |
| `datetime` | ISO 8601 or relative | `"now-24h"`, `"2026-01-28 00:00:00"` |
| `integer` | Numeric value | `100` |
| `list` | Array of values | `["prod", "lab"]` |
| `bool` | Boolean | `true` / `false` |

## Contributing

1. Create rules in `rules/` directory
2. Follow the schema in `docs/SCHEMA.md`
3. Validate with `python detection_loader.py validate <file>`
4. Submit PR for review

