"""OpenSearch Detection Framework - Modular detection rules for OpenSearch."""

from .detection_loader import (
    DetectionRule,
    SearchConfig,
    ResponseConfig,
    Parameter,
    RuleLoader,
    OpenSearchExecutor,
)

__version__ = "1.0.0"
__all__ = [
    "DetectionRule",
    "SearchConfig", 
    "ResponseConfig",
    "Parameter",
    "RuleLoader",
    "OpenSearchExecutor",
]
