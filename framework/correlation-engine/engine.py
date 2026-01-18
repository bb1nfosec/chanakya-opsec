"""
Correlation Engine

Multi-layer signal correlation for OPSEC failure detection.

This engine takes signals from multiple analyzers and identifies
correlation patterns that indicate attribution risks.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from itertools import combinations
import json

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework import (
    Signal, OpsecLayer, CorrelationResult,
    calculate_correlation_score, assess_attribution_confidence, assess_risk_level
)


class CorrelationEngine:
    """
    Multi-layer OPSEC signal correlation engine
    
    Identifies patterns across signals that could lead to attribution
    """

    def __init__(self):
        self.signals: List[Signal] = []
        self.correlations: List[CorrelationResult] = []

    def add_signals(self, signals: List[Signal]):
        """Add signals from various analyzers"""
        self.signals.extend(signals)

    def clear(self):
        """Clear all signals and correlations"""
        self.signals = []
        self.correlations = []

    def correlate_all(self) -> List[CorrelationResult]:
        """Run all correlation analyses"""
        self.correlations = []

        # Temporal correlation
        temporal_corrs = self._correlate_temporal()
        self.correlations.extend(temporal_corrs)

        # Layer cross-correlation
        cross_layer_corrs = self._correlate_cross_layer()
        self.correlations.extend(cross_layer_corrs)

        # Multi-signal correlation (3+ signals)
        multi_corrs = self._correlate_multi_signal()
        self.correlations.extend(multi_corrs)

        return self.correlations

    def _correlate_temporal(self, time_window_seconds: int = 300) -> List[CorrelationResult]:
        """Correlate signals that occur within a time window"""
        correlations = []
        
        # Group signals by time window
        time_buckets = defaultdict(list)
        for signal in self.signals:
            bucket_key = int(signal.timestamp.timestamp() / time_window_seconds)
            time_buckets[bucket_key].append(signal)

        # Find buckets with multiple signals from different layers
        for bucket_key, bucket_signals in time_buckets.items():
            if len(bucket_signals) < 2:
                continue

            layers = set(s.layer for s in bucket_signals)
            if len(layers) < 2:  # Need signals from at least 2 different layers
                continue

            score = calculate_correlation_score(bucket_signals)
            confidence = assess_attribution_confidence(score)

            correlations.append(CorrelationResult(
                signals=bucket_signals,
                correlation_score=score,
                attribution_confidence=confidence,
                correlation_type="TEMPORAL",
                explanation=f"{len(bucket_signals)} signals from {len(layers)} layers occurred within {time_window_seconds}s window",
                risk_level=assess_risk_level(confidence, len(bucket_signals))
            ))

        return correlations

    def _correlate_cross_layer(self) -> List[CorrelationResult]:
        """Correlate signals across different OPSEC layers"""
        correlations = []

        # Group signals by layer
        layer_signals = defaultdict(list)
        for signal in self.signals:
            layer_signals[signal.layer].append(signal)

        # Check for specific cross-layer correlation patterns
        
        # Pattern 1: DNS + Network correlation (resolver AS != VPN AS)
        dns_signals = layer_signals.get(OpsecLayer.DNS, [])
        network_signals = layer_signals.get(OpsecLayer.NETWORK, [])
        
        dns_resolver_signals = [s for s in dns_signals if 'resolver' in s.signal_id or 'public_resolver' in s.signal_id]
        as_signals = [s for s in network_signals if 'as' in s.signal_id.lower()]

        if dns_resolver_signals and as_signals:
            combined = dns_resolver_signals + as_signals
            score = calculate_correlation_score(combined)
            confidence = assess_attribution_confidence(score)

            correlations.append(CorrelationResult(
                signals=combined,
                correlation_score=score,
                attribution_confidence=confidence,
                correlation_type="DNS_NETWORK_CORRELATION",
                explanation="DNS resolver and network AS signals enable infrastructure correlation",
                risk_level=assess_risk_level(confidence, len(combined))
            ))

        # Pattern 2: Userland + Metadata correlation (timezone/timing)
        userland_signals = layer_signals.get(OpsecLayer.USERLAND, [])
        metadata_signals = layer_signals.get(OpsecLayer.METADATA, [])

        timezone_signals = [s for s in userland_signals if 'timezone' in s.signal_id or 'locale' in s.signal_id]
        timing_signals = [s for s in metadata_signals if 'time' in s.signal_id or 'timing' in s.signal_id]

        if timezone_signals and timing_signals:
            combined = timezone_signals + timing_signals
            score = calculate_correlation_score(combined)
            confidence = assess_attribution_confidence(score)

            correlations.append(CorrelationResult(
                signals=combined,
                correlation_score=score,
                attribution_confidence=confidence,
                correlation_type="TIMEZONE_TIMING_CORRELATION",
                explanation="Timezone and activity timing signals enable geographic/human attribution",
                risk_level=assess_risk_level(confidence, len(combined))
            ))

        return correlations

    def _correlate_multi_signal(self) -> List[CorrelationResult]:
        """Identify high-risk correlation of 3+ signals"""
        correlations = []

        # Find combinations of signals from different layers
        layer_groups = defaultdict(list)
        for signal in self.signals:
            layer_groups[signal.layer].append(signal)

        # Get one signal from each layer (if we have 3+ layers)
        if len(layer_groups) >= 3:
            # Take top signal from each layer
            representative_signals = []
            for layer, signals in layer_groups.items():
                # Prioritize SOLO and PAIR correlation potential
                sorted_signals = sorted(
                    signals,
                    key=lambda s: ['WEAK', 'MULTI', 'PAIR', 'SOLO'].index(s.correlation_potential.value)
                )
                representative_signals.append(sorted_signals[0])

            if len(representative_signals) >= 3:
                score = calculate_correlation_score(representative_signals)
                confidence = assess_attribution_confidence(score)

                correlations.append(CorrelationResult(
                    signals=representative_signals,
                    correlation_score=score,
                    attribution_confidence=confidence,
                    correlation_type="MULTI_LAYER_CONVERGENCE",
                    explanation=f"Signals from {len(representative_signals)} different layers converge for high-confidence attribution",
                    risk_level=assess_risk_level(confidence, len(representative_signals))
                ))

        return correlations

    def get_critical_correlations(self) -> List[CorrelationResult]:
        """Get only CRITICAL risk correlations"""
        return [c for c in self.correlations if c.attribution_confidence == "CRITICAL"]

    def get_high_risk_correlations(self) -> List[CorrelationResult]:
        """Get HIGH or CRITICAL risk correlations"""
        return [c for c in self.correlations if c.attribution_confidence in ["HIGH", "CRITICAL"]]

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive correlation report"""
        
        # Count signals by layer
        layer_counts = defaultdict(int)
        for signal in self.signals:
            layer_counts[signal.layer.value] += 1

        # Count correlations by risk level
        risk_counts = defaultdict(int)
        for corr in self.correlations:
            risk_counts[corr.attribution_confidence] += 1

        # Find highest risk correlation
        highest_risk = None
        if self.correlations:
            highest_risk = max(self.correlations, key=lambda c: c.correlation_score)

        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_signals': len(self.signals),
                'signals_by_layer': dict(layer_counts),
                'total_correlations': len(self.correlations),
                'correlations_by_confidence': dict(risk_counts)
            },
            'highest_risk_correlation': highest_risk.to_dict() if highest_risk else None,
            'critical_correlations': [c.to_dict() for c in self.get_critical_correlations()],
            'all_correlations': [c.to_dict() for c in self.correlations],
            'all_signals': [s.to_dict() for s in self.signals]
        }

        return report

    def export_report_json(self, filepath: str):
        """Export report to JSON file"""
        report = self.generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

    def get_mitigation_recommendations(self) -> List[Dict[str, str]]:
        """Generate mitigation recommendations based on correlations"""
        recommendations = []

        # Check for high-risk correlation types
        for corr in self.get_high_risk_correlations():
            if corr.correlation_type == "DNS_NETWORK_CORRELATION":
                recommendations.append({
                    'priority': 'CRITICAL',
                    'issue': 'DNS resolver and network AS mismatch',
                    'recommendation': 'Use DNS resolver in same AS as VPN exit, or deploy private recursive resolver',
                    'layers': ['DNS', 'NETWORK']
                })

            elif corr.correlation_type == "TIMEZONE_TIMING_CORRELATION":
                recommendations.append({
                    'priority': 'HIGH',
                    'issue': 'Timezone and activity timing correlation',
                    'recommendation': 'Automate operations with randomized timing, or operate across multiple timezones',
                    'layers': ['USERLAND', 'METADATA']
                })

            elif corr.correlation_type == "MULTI_LAYER_CONVERGENCE":
                recommendations.append({
                    'priority': 'CRITICAL',
                    'issue': f'Signals from {len(corr.signals)} layers correlate',
                    'recommendation': 'Break correlation chains by isolating operational layers and adding noise/diversity',
                    'layers': list(set(s.layer.value for s in corr.signals))
                })

        # Deduplicate recommendations
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            key = (rec['priority'], rec['issue'])
            if key not in seen:
                seen.add(key)
                unique_recommendations.append(rec)

        return unique_recommendations
