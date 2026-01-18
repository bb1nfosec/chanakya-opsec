"""
CHANAKYA Framework Core Module

This module provides the foundation for OPSEC analysis across layers.
"""

__version__ = "0.1.0"
__author__ = "CHANAKYA-OPSEC Project"

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class OpsecLayer(Enum):
    """OPSEC Analysis Layers"""
    USERLAND = "userland"
    KERNEL = "kernel"
    DNS = "dns"
    NETWORK = "network"
    METADATA = "metadata"


class CorrelationStrength(Enum):
    """Correlation potential classification"""
    SOLO = "solo"  # Attributable alone
    PAIR = "pair"  # Requires 2 signals
    MULTI = "multi"  # Requires 3+ signals
    WEAK = "weak"  # Rarely sufficient


class DetectabilityLevel(Enum):
    """How easy for adversary to observe"""
    TRIVIAL = "trivial"  # Passive observation
    MODERATE = "moderate"  # Requires infrastructure access
    HARD = "hard"  # Requires active probing
    RESEARCH = "research"  # Requires novel techniques


@dataclass
class Signal:
    """Represents an observable OPSEC signal"""
    signal_id: str
    layer: OpsecLayer
    description: str
    value: Any
    timestamp: datetime
    correlation_potential: CorrelationStrength
    detectability: DetectabilityLevel
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'signal_id': self.signal_id,
            'layer': self.layer.value,
            'description': self.description,
            'value': str(self.value),
            'timestamp': self.timestamp.isoformat(),
            'correlation_potential': self.correlation_potential.value,
            'detectability': self.detectability.value,
            'metadata': self.metadata
        }


@dataclass
class CorrelationResult:
    """Result of correlating multiple signals"""
    signals: List[Signal]
    correlation_score: float  # 0.0 - 1.0
    attribution_confidence: str  # LOW, MEDIUM, HIGH, CRITICAL
    correlation_type: str
    explanation: str
    risk_level: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'signal_count': len(self.signals),
            'signal_layers': [s.layer.value for s in self.signals],
            'correlation_score': self.correlation_score,
            'attribution_confidence': self.attribution_confidence,
            'correlation_type': self.correlation_type,
            'explanation': self.explanation,
            'risk_level': self.risk_level,
            'signals': [s.to_dict() for s in self.signals]
        }


class OpsecAnalyzer:
    """Base class for layer-specific OPSEC analyzers"""

    def __init__(self, layer: OpsecLayer):
        self.layer = layer
        self.signals: List[Signal] = []

    def add_signal(self, signal: Signal):
        """Add a detected signal"""
        if signal.layer != self.layer:
            raise ValueError(f"Signal layer {signal.layer} doesn't match analyzer layer {self.layer}")
        self.signals.append(signal)

    def get_signals(self) -> List[Signal]:
        """Get all detected signals"""
        return self.signals

    def analyze(self, data: Any) -> List[Signal]:
        """Analyze data and extract signals (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement analyze()")

    def clear_signals(self):
        """Clear all signals"""
        self.signals = []


def calculate_correlation_score(signals: List[Signal]) -> float:
    """
    Calculate correlation score based on signal count and characteristics
    
    Formula: score = (1 - (1 - base)^n) where n = number of signals
    """
    if not signals:
        return 0.0

    # Base individual signal strength
    base_scores = {
        CorrelationStrength.SOLO: 0.8,
        CorrelationStrength.PAIR: 0.4,
        CorrelationStrength.MULTI: 0.2,
        CorrelationStrength.WEAK: 0.1
    }

    # Multi-layer bonus
    unique_layers = len(set(s.layer for s in signals))
    layer_multiplier = 1.0 + (unique_layers - 1) * 0.3  # 30% bonus per additional layer

    # Calculate combined score
    avg_strength = sum(base_scores[s.correlation_potential] for s in signals) / len(signals)
    
    # Exponential correlation: More signals = exponentially higher confidence
    n = len(signals)
    combined_score = (1 - (1 - avg_strength) ** n) * layer_multiplier

    return min(combined_score, 1.0)


def assess_attribution_confidence(correlation_score: float) -> str:
    """Convert correlation score to attribution confidence level"""
    if correlation_score >= 0.9:
        return "CRITICAL"
    elif correlation_score >= 0.7:
        return "HIGH"
    elif correlation_score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"


def assess_risk_level(attribution_confidence: str, signal_count: int) -> str:
    """Assess operational risk based on attribution confidence and signal count"""
    if attribution_confidence == "CRITICAL" or signal_count >= 4:
        return "CRITICAL - OPSEC COMPROMISED"
    elif attribution_confidence == "HIGH" or signal_count >= 3:
        return "HIGH - ATTRIBUTION LIKELY"
    elif attribution_confidence == "MEDIUM":
        return "MEDIUM - CORRELATION POSSIBLE"
    else:
        return "LOW - INSUFFICIENT CORRELATION"
