"""
OpenSearch Detection Rule Loader

A modular Python library for loading YAML-based detection rules and executing
them against OpenSearch clusters.

Usage:
    from detection_loader import DetectionRule, OpenSearchExecutor
    
    # Load a single rule
    rule = DetectionRule.from_file('rules/linux_user_creation.yaml')
    
    # Execute with parameters
    executor = OpenSearchExecutor(host='https://opensearch:9200', auth=('admin', 'password'))
    results = executor.execute(rule, parameters={
        'AGENT_NAME': 'Amine',
        'CUSTOMER': 'lab',
        'START_TIME': '2026-01-28 00:00:00.000',
        'END_TIME': '2026-01-28 23:59:59.999'
    })
"""

import yaml
import json
import re
import copy
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime
import logging

# Optional: opensearch-py for execution
try:
    from opensearchpy import OpenSearch
    HAS_OPENSEARCH = True
except ImportError:
    HAS_OPENSEARCH = False


logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Parameter:
    """Definition of a runtime parameter."""
    name: str
    description: str
    param_type: str  # string, datetime, integer, list, bool
    required: bool = False
    default: Any = None
    example: Any = None
    
    @classmethod
    def from_dict(cls, name: str, data: dict) -> 'Parameter':
        return cls(
            name=name,
            description=data.get('description', ''),
            param_type=data.get('type', 'string'),
            required=data.get('required', False),
            default=data.get('default'),
            example=data.get('example')
        )


@dataclass
class SearchConfig:
    """OpenSearch query configuration."""
    index_pattern: str
    query: dict
    size: int = 100
    sort: list = field(default_factory=list)
    source_fields: list = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SearchConfig':
        return cls(
            index_pattern=data['index_pattern'],
            query=data['query'],
            size=data.get('size', 100),
            sort=data.get('sort', []),
            source_fields=data.get('_source', [])
        )
    
    def to_opensearch_body(self) -> dict:
        """Convert to OpenSearch request body (JSON-compatible dict)."""
        body = {
            'size': self.size,
            'query': self.query
        }
        
        if self.sort:
            body['sort'] = self.sort
            
        if self.source_fields:
            body['_source'] = self.source_fields
            
        return body


@dataclass
class ResponseConfig:
    """Alert response configuration."""
    message: str
    risk_score: int
    severity: str
    risk_objects: list = field(default_factory=list)
    threat_objects: list = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ResponseConfig':
        return cls(
            message=data.get('message', ''),
            risk_score=data.get('risk_score', 0),
            severity=data.get('severity', 'medium'),
            risk_objects=data.get('risk_objects', []),
            threat_objects=data.get('threat_objects', [])
        )


@dataclass
class DetectionRule:
    """Complete detection rule loaded from YAML."""
    
    # Metadata
    name: str
    id: str
    version: int
    schema_version: str
    date: str
    author: str
    status: str
    rule_type: str
    
    # Description
    description: str
    data_source: list
    
    # Search configuration
    search: SearchConfig
    
    # Parameters
    parameters: dict  # name -> Parameter
    
    # Implementation
    how_to_implement: str
    known_false_positives: str
    references: list
    
    # Response
    response: ResponseConfig
    
    # Tags
    tags: dict
    
    # Raw YAML for reference
    _raw: dict = field(default_factory=dict, repr=False)
    
    @classmethod
    def from_file(cls, filepath: str | Path) -> 'DetectionRule':
        """Load a detection rule from a YAML file."""
        filepath = Path(filepath)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DetectionRule':
        """Create a DetectionRule from a dictionary."""
        
        # Parse parameters
        parameters = {}
        for name, param_data in data.get('parameters', {}).items():
            parameters[name] = Parameter.from_dict(name, param_data)
        
        return cls(
            name=data['name'],
            id=data['id'],
            version=data['version'],
            schema_version=data.get('schema_version', '1.0'),
            date=data['date'],
            author=data['author'],
            status=data['status'],
            rule_type=data['type'],
            description=data['description'],
            data_source=data.get('data_source', []),
            search=SearchConfig.from_dict(data['search']),
            parameters=parameters,
            how_to_implement=data.get('how_to_implement', ''),
            known_false_positives=data.get('known_false_positives', ''),
            references=data.get('references', []),
            response=ResponseConfig.from_dict(data.get('response', {})),
            tags=data.get('tags', {}),
            _raw=data
        )
    
    def validate_parameters(self, provided: dict) -> list[str]:
        """
        Validate provided parameters against rule requirements.
        Returns list of error messages (empty if valid).
        """
        errors = []
        
        for name, param in self.parameters.items():
            if param.required and name not in provided:
                if param.default is None:
                    errors.append(f"Required parameter '{name}' not provided")
        
        return errors
    
    def get_resolved_query(self, parameters: dict) -> dict:
        """
        Return the query with all parameters substituted.
        
        Parameters use ${PARAM_NAME} syntax in the YAML.
        """
        # Merge defaults with provided parameters
        resolved_params = {}
        for name, param in self.parameters.items():
            if name in parameters:
                resolved_params[name] = parameters[name]
            elif param.default is not None:
                resolved_params[name] = param.default
        
        # Deep copy the query to avoid modifying the original
        query = copy.deepcopy(self.search.query)
        
        # Recursively substitute parameters
        return self._substitute_params(query, resolved_params)
    
    def _substitute_params(self, obj: Any, params: dict) -> Any:
        """Recursively substitute ${PARAM} placeholders in the query."""
        if isinstance(obj, str):
            # Find all ${PARAM} patterns
            pattern = r'\$\{(\w+)\}'
            
            def replacer(match):
                param_name = match.group(1)
                if param_name in params:
                    value = params[param_name]
                    # If the entire string is just the placeholder, return the raw value
                    # This preserves types for lists, integers, etc.
                    if match.group(0) == obj:
                        return value
                    return str(value)
                return match.group(0)  # Keep original if not found
            
            # Check if entire string is a single parameter
            single_match = re.fullmatch(pattern, obj)
            if single_match and single_match.group(1) in params:
                return params[single_match.group(1)]
            
            return re.sub(pattern, replacer, obj)
        
        elif isinstance(obj, dict):
            return {k: self._substitute_params(v, params) for k, v in obj.items()}
        
        elif isinstance(obj, list):
            return [self._substitute_params(item, params) for item in obj]
        
        return obj
    
    def to_curl_command(
        self, 
        parameters: dict,
        host: str = "https://localhost:9200",
        username: str = "admin",
        password: str = "admin"
    ) -> str:
        """Generate a curl command for testing."""
        query = self.get_resolved_query(parameters)
        
        body = {
            'size': self.search.size,
            'query': query
        }
        
        if self.search.sort:
            body['sort'] = self.search.sort
        
        if self.search.source_fields:
            body['_source'] = self.search.source_fields
        
        json_body = json.dumps(body, indent=2)
        
        return f'''curl -k -u '{username}:{password}' \\
  -X POST "{host}/{self.search.index_pattern}/_search?pretty" \\
  -H "Content-Type: application/json" \\
  -d '{json_body}'
'''


# =============================================================================
# Rule Loader (loads multiple rules from directory)
# =============================================================================

class RuleLoader:
    """Load and manage multiple detection rules from a directory."""
    
    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self._rules: dict[str, DetectionRule] = {}
    
    def load_all(self) -> dict[str, DetectionRule]:
        """Load all YAML rules from the rules directory."""
        self._rules = {}
        
        for yaml_file in self.rules_dir.glob('**/*.yaml'):
            try:
                rule = DetectionRule.from_file(yaml_file)
                self._rules[rule.id] = rule
                logger.info(f"Loaded rule: {rule.name} ({rule.id})")
            except Exception as e:
                logger.error(f"Failed to load {yaml_file}: {e}")
        
        for yml_file in self.rules_dir.glob('**/*.yml'):
            try:
                rule = DetectionRule.from_file(yml_file)
                self._rules[rule.id] = rule
                logger.info(f"Loaded rule: {rule.name} ({rule.id})")
            except Exception as e:
                logger.error(f"Failed to load {yml_file}: {e}")
        
        return self._rules
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)
    
    def get_rules_by_tag(self, tag_key: str, tag_value: str) -> list[DetectionRule]:
        """Find rules matching a specific tag."""
        matching = []
        for rule in self._rules.values():
            tag_values = rule.tags.get(tag_key, [])
            if isinstance(tag_values, list) and tag_value in tag_values:
                matching.append(rule)
            elif tag_values == tag_value:
                matching.append(rule)
        return matching
    
    def get_rules_by_mitre(self, technique_id: str) -> list[DetectionRule]:
        """Find rules matching a MITRE ATT&CK technique."""
        return self.get_rules_by_tag('mitre_attack_id', technique_id)
    
    @property
    def rules(self) -> dict[str, DetectionRule]:
        return self._rules


# =============================================================================
# OpenSearch Executor
# =============================================================================

class OpenSearchExecutor:
    """Execute detection rules against an OpenSearch cluster."""
    
    def __init__(
        self,
        host: str,
        auth: tuple[str, str] = None,
        verify_certs: bool = False,
        **kwargs
    ):
        if not HAS_OPENSEARCH:
            raise ImportError(
                "opensearch-py is required for execution. "
                "Install with: pip install opensearch-py"
            )
        
        self.client = OpenSearch(
            hosts=[host],
            http_auth=auth,
            verify_certs=verify_certs,
            ssl_show_warn=False,
            **kwargs
        )
    
    def execute(
        self, 
        rule: DetectionRule, 
        parameters: dict,
        raw_response: bool = False
    ) -> dict:
        """
        Execute a detection rule with the given parameters.
        
        Args:
            rule: The detection rule to execute
            parameters: Runtime parameters to substitute
            raw_response: If True, return raw OpenSearch response
            
        Returns:
            Dict with 'hits', 'total', and optionally 'aggregations'
        """
        # Validate parameters
        errors = rule.validate_parameters(parameters)
        if errors:
            raise ValueError(f"Parameter validation failed: {errors}")
        
        # Build the query
        resolved_query = rule.get_resolved_query(parameters)
        
        body = {
            'size': rule.search.size,
            'query': resolved_query
        }
        
        if rule.search.sort:
            body['sort'] = rule.search.sort
        
        if rule.search.source_fields:
            body['_source'] = rule.search.source_fields
        
        # Execute
        response = self.client.search(
            index=rule.search.index_pattern,
            body=body
        )
        
        if raw_response:
            return response
        
        # Parse response
        return {
            'rule_id': rule.id,
            'rule_name': rule.name,
            'total': response['hits']['total']['value'],
            'hits': [hit['_source'] for hit in response['hits']['hits']],
            'took_ms': response['took']
        }
    
    def execute_with_alert(
        self, 
        rule: DetectionRule, 
        parameters: dict
    ) -> list[dict]:
        """
        Execute a rule and generate alert messages for each hit.
        
        Returns list of alerts with formatted messages.
        """
        results = self.execute(rule, parameters)
        alerts = []
        
        for hit in results['hits']:
            # Format the alert message with hit data
            message = rule.response.message
            for field_match in re.finditer(r'\$(\w+)\$', message):
                field_name = field_match.group(1)
                field_value = hit.get(field_name, f'<{field_name} not found>')
                message = message.replace(f'${field_name}$', str(field_value))
            
            alerts.append({
                'rule_id': rule.id,
                'rule_name': rule.name,
                'severity': rule.response.severity,
                'risk_score': rule.response.risk_score,
                'message': message,
                'raw_event': hit,
                'mitre_attack': rule.tags.get('mitre_attack_id', [])
            })
        
        return alerts


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for testing rules."""
    import argparse
    
    parser = argparse.ArgumentParser(description='OpenSearch Detection Rule Tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate a rule file')
    validate_parser.add_argument('file', help='YAML rule file to validate')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show rule details')
    show_parser.add_argument('file', help='YAML rule file')
    show_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # Curl command
    curl_parser = subparsers.add_parser('curl', help='Generate curl command')
    curl_parser.add_argument('file', help='YAML rule file')
    curl_parser.add_argument('--host', default='https://localhost:9200')
    curl_parser.add_argument('--user', default='admin')
    curl_parser.add_argument('--password', default='admin')
    curl_parser.add_argument('-p', '--param', action='append', nargs=2, 
                             metavar=('NAME', 'VALUE'), help='Set parameter')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List rules in directory')
    list_parser.add_argument('directory', help='Rules directory')
    
    args = parser.parse_args()
    
    if args.command == 'validate':
        try:
            rule = DetectionRule.from_file(args.file)
            print(f"✓ Valid rule: {rule.name} (v{rule.version})")
            print(f"  ID: {rule.id}")
            print(f"  Status: {rule.status}")
            print(f"  Parameters: {list(rule.parameters.keys())}")
        except Exception as e:
            print(f"✗ Invalid rule: {e}")
            exit(1)
    
    elif args.command == 'show':
        rule = DetectionRule.from_file(args.file)
        if args.json:
            print(json.dumps(rule._raw, indent=2))
        else:
            print(f"Name: {rule.name}")
            print(f"ID: {rule.id}")
            print(f"Version: {rule.version}")
            print(f"Status: {rule.status}")
            print(f"Type: {rule.rule_type}")
            print(f"\nDescription:\n{rule.description}")
            print(f"\nIndex Pattern: {rule.search.index_pattern}")
            print(f"\nParameters:")
            for name, param in rule.parameters.items():
                req = "required" if param.required else f"default: {param.default}"
                print(f"  - {name}: {param.description} ({req})")
    
    elif args.command == 'curl':
        rule = DetectionRule.from_file(args.file)
        
        # Parse parameters
        params = {}
        if args.param:
            for name, value in args.param:
                # Try to parse as JSON for complex types
                try:
                    params[name] = json.loads(value)
                except json.JSONDecodeError:
                    params[name] = value
        
        print(rule.to_curl_command(
            params,
            host=args.host,
            username=args.user,
            password=args.password
        ))
    
    elif args.command == 'list':
        loader = RuleLoader(args.directory)
        rules = loader.load_all()
        
        print(f"Found {len(rules)} rules:\n")
        for rule in rules.values():
            print(f"  [{rule.status}] {rule.name}")
            print(f"           ID: {rule.id}")
            print(f"           MITRE: {rule.tags.get('mitre_attack_id', 'N/A')}")
            print()
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
