# OpenSearch (Wazuh-Indexer) Detection Rule YAML Schema

## Overview

This document defines the YAML schema for OpenSearch (Wazuh-Indexer) detection rules. The schema is designed to be:
- **Modular**: Each detection rule is a self-contained YAML file
- **Version-controlled**: Easy to track changes via Git
- **Extensible**: Add new fields without breaking existing parsers
- **Human-readable**: Clear structure for analysts to author and review

## Schema Version

Current Schema Version: `1.0`

---

## Top-Level Structure

```yaml
# === METADATA ===
name: string                    # Required: Human-readable name
id: string                      # Required: Unique identifier (UUID recommended)
version: integer                # Required: Rule version number
schema_version: string          # Required: Schema version (e.g., "1.0")
date: string                    # Required: Last modified date (YYYY-MM-DD)
author: string                  # Required: Rule author
status: enum                    # Required: production | experimental | deprecated
type: enum                      # Required: TTP | Anomaly | Correlation | Hunting

# === DESCRIPTION ===
description: string             # Required: What this detection finds
data_source: list[string]       # Required: Data sources used

# === OpenSearch (Wazuh-Indexer) QUERY ===
search:
  index_pattern: string         # Required: Index pattern to search
  size: integer                 # Optional: Number of results (default: 100)
  sort: list[object]            # Optional: Sort configuration
  query: object                 # Required: OpenSearch (Wazuh-Indexer) query DSL
  _source: list[string]         # Optional: Fields to return

# === IMPLEMENTATION ===
how_to_implement: string        # Required: Setup instructions
known_false_positives: string   # Required: Expected FP scenarios
references: list[string]        # Optional: Reference URLs

# === RESPONSE ===
response:
  message: string               # Required: Alert message template
  risk_score: integer           # Required: Risk score (0-100)
  severity: enum                # Required: low | medium | high | critical
  
# === CLASSIFICATION ===
tags:
  analytic_story: list[string]  # Optional: Related analytic stories
  asset_type: string            # Required: Asset type (e.g., "Linux", "Windows")
  mitre_attack_id: list[string] # Optional: MITRE ATT&CK technique IDs
  security_domain: string       # Required: endpoint | network | access | identity
  
# === TESTING ===
tests: list[object]             # Optional: Test cases
```

---

## Query DSL in YAML

The key innovation is representing OpenSearch (Wazuh-Indexer) Query DSL in YAML format. YAML's native support for nested structures maps directly to JSON.

### Basic Query Types

#### Term Query
```yaml
query:
  term:
    field_name: "value"
```

#### Match Query
```yaml
query:
  match:
    field_name: "search text"
```

#### Wildcard Query
```yaml
query:
  wildcard:
    field_name: "*pattern*"
```

#### Range Query
```yaml
query:
  range:
    timestamp:
      gte: "now-24h"
      lte: "now"
```

### Compound Queries

#### Bool Query
```yaml
query:
  bool:
    must:
      - term:
          agent_name: "Amine"
      - term:
          agent_labels_customer: "lab"
    should:
      - wildcard:
          full_log: "*useradd*"
      - wildcard:
          full_log: "*adduser*"
    must_not:
      - exists:
          field: "data_win_system_eventID"
    minimum_should_match: 1
```

### Dynamic Parameters

Use `${PARAMETER_NAME}` syntax for runtime substitution:

```yaml
query:
  bool:
    must:
      - term:
          agent_name: "${AGENT_NAME}"
      - range:
          timestamp:
            gte: "${START_TIME}"
            lte: "${END_TIME}"
```

### Time-Based Parameters

Common time parameters with defaults:

```yaml
parameters:
  START_TIME:
    description: "Query start time"
    type: datetime
    default: "now-24h"
  END_TIME:
    description: "Query end time"  
    type: datetime
    default: "now"
  AGENT_NAME:
    description: "Target agent name"
    type: string
    required: true
```

---

## Field Reference

### Metadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable detection name |
| `id` | string | Yes | Unique identifier (UUID v4 recommended) |
| `version` | integer | Yes | Rule version, increment on changes |
| `schema_version` | string | Yes | Schema version for parser compatibility |
| `date` | string | Yes | Last modification date (ISO 8601) |
| `author` | string | Yes | Rule author name/handle |
| `status` | enum | Yes | `production`, `experimental`, `deprecated` |
| `type` | enum | Yes | `TTP`, `Anomaly`, `Correlation`, `Hunting` |

### Search Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `index_pattern` | string | Yes | OpenSearch (Wazuh-Indexer) index pattern |
| `size` | integer | No | Max results to return (default: 100) |
| `sort` | list | No | Sort order specification |
| `query` | object | Yes | OpenSearch (Wazuh-Indexer) Query DSL |
| `_source` | list | No | Fields to include in results |

### Response Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | string | Yes | Alert message with `$field$` placeholders |
| `risk_score` | integer | Yes | Risk score 0-100 |
| `severity` | enum | Yes | `low`, `medium`, `high`, `critical` |

---

## Complete Example

See `examples/linux_user_creation.yaml` for a complete working example.
