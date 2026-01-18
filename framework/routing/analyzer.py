"""
Routing & Network Plane OPSEC Analysis Module

Detects OPSEC failures in:
- AS-path exposure
- BGP routing behavior
- Traffic analysis patterns
- Path asymmetry & MTU fingerprinting
"""

import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework import (
    Signal, OpsecLayer, CorrelationStrength, DetectabilityLevel, OpsecAnalyzer
)


class ASPathAnalyzer(OpsecAnalyzer):
    """Analyze AS-path for OPSEC risks"""

    # Known high-risk/bulletproof hosting AS numbers
    HIGH_RISK_ASNS = {
        '0000': 'Example High-Risk ASN',
        # Add actual high-risk ASNs from threat intel
    }

    def __init__(self):
        super().__init__(OpsecLayer.NETWORK)

    def analyze(self, routing_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze BGP AS-path for attribution risks

        Expected data format:
        {
            'as_path': ['AS64512', 'AS6939', 'AS174', ...],
            'origin_as': 'AS64512',
            'destination_as': 'AS15169',
            'geographic_path': ['SE', 'DE', 'US']
        }
        """
        signals = []

        if 'as_path' not in routing_data:
            return signals

        as_path = routing_data['as_path']
        origin_as = routing_data.get('origin_as', as_path[0] if as_path else None)

        # Check origin AS reputation
        if origin_as in self.HIGH_RISK_ASNS:
            signals.append(Signal(
                signal_id=f"high_risk_as_{origin_as}",
                layer=OpsecLayer.NETWORK,
                description=f"Traffic originates from high-risk AS",
                value=origin_as,
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.TRIVIAL,
                metadata={
                    'as': origin_as,
                    'reputation': self.HIGH_RISK_ASNS[origin_as],
                    'risk': 'AS reputation can trigger threat intelligence alerts'
                }
            ))

        # AS-path length analysis (geolocation estimation)
        if len(as_path) > 1:
            signals.append(Signal(
                signal_id="as_path_length",
                layer=OpsecLayer.NETWORK,
                description="AS-path length",
                value=len(as_path),
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.TRIVIAL,
                metadata={
                    'hop_count': len(as_path),
                    'as_path': as_path,
                    'risk': 'Path length enables geographic distance estimation'
                }
            ))

        # Geographic path analysis
        if 'geographic_path' in routing_data:
            geo_path = routing_data['geographic_path']
            signals.append(Signal(
                signal_id="geographic_routing",
                layer=OpsecLayer.NETWORK,
                description="Geographic routing path",
                value=' → '.join(geo_path),
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.PAIR,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'path': geo_path,
                    'risk': 'Routing path reveals infrastructure geography'
                }
            ))

        self.signals.extend(signals)
        return signals


class RouteAsymmetryDetector(OpsecAnalyzer):
    """Detect routing asymmetry (different inbound/outbound paths)"""

    def __init__(self):
        super().__init__(OpsecLayer.NETWORK)

    def analyze(self, path_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze routing path asymmetry

        Expected data format:
        {
            'inbound_path': ['AS1', 'AS2', 'AS3'],
            'outbound_path': ['AS3', 'AS4', 'AS5'],
            'inbound_geo': ['US', 'DE', 'SE'],
            'outbound_geo': ['SE', 'FR', 'US']
        }
        """
        signals = []

        inbound = set(path_data.get('inbound_path', []))
        outbound = set(path_data.get('outbound_path', []))

        # Check for AS asymmetry
        if inbound and outbound:
            symmetric_ases = inbound & outbound
            asymmetric_ratio = 1.0 - (len(symmetric_ases) / max(len(inbound), len(outbound)))

            if asymmetric_ratio > 0.5:  # >50% path difference
                signals.append(Signal(
                    signal_id="route_asymmetry",
                    layer=OpsecLayer.NETWORK,
                    description="Significant routing path asymmetry detected",
                    value=f"{asymmetric_ratio:.0%} path difference",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.HARD,
                    metadata={
                        'inbound_path': path_data.get('inbound_path'),
                        'outbound_path': path_data.get('outbound_path'),
                        'asymmetry_ratio': asymmetric_ratio,
                        'risk': 'Asymmetry can reveal true location vs. VPN exit'
                    }
                ))

        # Geographic asymmetry
        inbound_geo = path_data.get('inbound_geo', [])
        outbound_geo = path_data.get('outbound_geo', [])
        if inbound_geo and outbound_geo:
            if inbound_geo[0] != outbound_geo[-1]:  # Different origin/destination
                signals.append(Signal(
                    signal_id="geographic_asymmetry",
                    layer=OpsecLayer.NETWORK,
                    description="Geographic routing asymmetry",
                    value=f"In: {inbound_geo[0]}, Out: {outbound_geo[-1]}",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.HARD,
                    metadata={
                        'inbound_countries': inbound_geo,
                        'outbound_countries': outbound_geo,
                        'risk': 'Geographic mismatch can expose VPN/proxy usage'
                    }
                ))

        self.signals.extend(signals)
        return signals


class TrafficPatternAnalyzer(OpsecAnalyzer):
    """Analyze network traffic patterns for fingerprinting"""

    def __init__(self):
        super().__init__(OpsecLayer.NETWORK)

    def analyze(self, traffic_data: List[Dict[str, Any]]) -> List[Signal]:
        """
        Analyze traffic patterns

        Expected data format:
        [
            {
                'timestamp': datetime,
                'packet_size': 1420,
                'direction': 'outbound',
                'protocol': 'TCP',
                'duration_ms': 150
            },
            ...
        ]
        """
        signals = []

        if len(traffic_data) < 10:
            return signals

        # Packet size distribution analysis
        sizes = [p['packet_size'] for p in traffic_data]
        avg_size = sum(sizes) / len(sizes)
        
        # Check for unusual packet size patterns
        size_variance = sum((s - avg_size) ** 2 for s in sizes) / len(sizes)
        if size_variance < 100:  # Very consistent packet sizes
            signals.append(Signal(
                signal_id="consistent_packet_sizes",
                layer=OpsecLayer.NETWORK,
                description="Highly consistent packet sizes detected",
                value=f"avg={avg_size:.0f}B, var={size_variance:.1f}",
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'avg_size': avg_size,
                    'variance': size_variance,
                    'risk': 'Packet size patterns can fingerprint application/protocol'
                }
            ))

        # Inter-packet timing analysis
        timestamps = [p['timestamp'] for p in traffic_data]
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(delta)

        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            # Check for periodic behavior (beaconing)
            if 0.9 < avg_interval / (sum(intervals) / len(intervals)) < 1.1:
                signals.append(Signal(
                    signal_id="periodic_traffic",
                    layer=OpsecLayer.NETWORK,
                    description="Periodic traffic pattern detected (potential beaconing)",
                    value=f"{avg_interval:.2f}s interval",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'avg_interval_sec': avg_interval,
                        'packet_count': len(traffic_data),
                        'risk': 'Beaconing patterns strongly fingerprint C2 behavior'
                    }
                ))

        self.signals.extend(signals)
        return signals


class MTUFingerprintAnalyzer(OpsecAnalyzer):
    """Analyze MTU and fragmentation for path fingerprinting"""

    # Common MTU values and their implications
    MTU_SIGNATURES = {
        1500: 'Ethernet (default)',
        1492: 'PPPoE (DSL)',
        1480: 'VPN overhead reduced',
        1420: 'VPN + IPv6/GRE overhead',
        1280: 'IPv6 minimum MTU',
        576: 'Internet minimum MTU'
    }

    def __init__(self):
        super().__init__(OpsecLayer.NETWORK)

    def analyze(self, mtu_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze MTU configuration

        Expected data format:
        {
            'observed_mtu': 1420,
            'fragmentation_seen': True,
            'fragment_sizes': [1420, 800]
        }
        """
        signals = []

        mtu = mtu_data.get('observed_mtu')
        if mtu and mtu in self.MTU_SIGNATURES:
            signals.append(Signal(
                signal_id=f"mtu_{mtu}",
                layer=OpsecLayer.NETWORK,
                description=f"MTU fingerprint detected",
                value=f"{mtu} bytes",
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'mtu': mtu,
                    'signature': self.MTU_SIGNATURES[mtu],
                    'risk': 'MTU reveals network path type (VPN, DSL, etc.)'
                }
            ))

        if mtu_data.get('fragmentation_seen'):
            signals.append(Signal(
                signal_id="fragmentation_detected",
                layer=OpsecLayer.NETWORK,
                description="IP fragmentation observed",
                value=str(mtu_data.get('fragment_sizes', [])),
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'fragment_sizes': mtu_data.get('fragment_sizes', []),
                    'risk': 'Fragmentation patterns fingerprint network equipment'
                }
            ))

        self.signals.extend(signals)
        return signals
