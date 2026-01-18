"""
DNS OPSEC Analysis Module

Detects OPSEC failures in:
- Resolver correlation
- DNS sinkhole detection
- Query timing & ordering
- Passive DNS reconstruction risks
"""

import hashlib
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
import json

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework import (
    Signal, OpsecLayer, CorrelationStrength, DetectabilityLevel, OpsecAnalyzer
)


class DNSResolverAnalyzer(OpsecAnalyzer):
    """Analyze DNS resolver configuration for OPSEC risks"""

    # Known public DNS resolvers
    PUBLIC_RESOLVERS = {
        '8.8.8.8': {'name': 'Google Public DNS', 'as': 'AS15169', 'geo': 'Global'},
        '8.8.4.4': {'name': 'Google Public DNS', 'as': 'AS15169', 'geo': 'Global'},
        '1.1.1.1': {'name': 'Cloudflare DNS', 'as': 'AS13335', 'geo': 'Global'},
        '1.0.0.1': {'name': 'Cloudflare DNS', 'as': 'AS13335', 'geo': 'Global'},
        '9.9.9.9': {'name': 'Quad9', 'as': 'AS19281', 'geo': 'Global'},
        '208.67.222.222': {'name': 'OpenDNS', 'as': 'AS36692', 'geo': 'USA'},
        '208.67.220.220': {'name': 'OpenDNS', 'as': 'AS36692', 'geo': 'USA'},
    }

    def __init__(self):
        super().__init__(OpsecLayer.DNS)

    def analyze(self, resolver_config: Dict[str, Any]) -> List[Signal]:
        """
        Analyze DNS resolver configuration

        Expected data format:
        {
            'resolvers': ['8.8.8.8', '1.1.1.1'],
            'vpn_as': 'AS64512',  # Optional: VPN exit AS for correlation
            'doh_enabled': False,
            'dnssec_enabled': True
        }
        """
        signals = []

        if not resolver_config or 'resolvers' not in resolver_config:
            return signals

        for resolver in resolver_config['resolvers']:
            # Check if public resolver
            if resolver in self.PUBLIC_RESOLVERS:
                info = self.PUBLIC_RESOLVERS[resolver]
                signals.append(Signal(
                    signal_id=f"public_resolver_{resolver.replace('.', '_')}",
                    layer=OpsecLayer.DNS,
                    description=f"Using public DNS resolver: {info['name']}",
                    value=resolver,
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={
                        'resolver': resolver,
                        'name': info['name'],
                        'as': info['as'],
                        'risk': 'Queries logged, potential correlation with other layers'
                    }
                ))

                # Check for AS mismatch with VPN
                if 'vpn_as' in resolver_config:
                    if info['as'] != resolver_config['vpn_as']:
                        signals.append(Signal(
                            signal_id="dns_vpn_as_mismatch",
                            layer=OpsecLayer.DNS,
                            description="DNS resolver AS differs from VPN AS",
                            value=f"DNS:{info['as']}, VPN:{resolver_config['vpn_as']}",
                            timestamp=datetime.now(),
                            correlation_potential=CorrelationStrength.PAIR,
                            detectability=DetectabilityLevel.TRIVIAL,
                            metadata={
                                'dns_as': info['as'],
                                'vpn_as': resolver_config['vpn_as'],
                                'risk': 'HIGH - AS mismatch enables infrastructure correlation'
                            }
                        ))

        # Check DoH status
        if not resolver_config.get('doh_enabled', False):
            signals.append(Signal(
                signal_id="doh_disabled",
                layer=OpsecLayer.DNS,
                description="DNS over HTTPS (DoH) not enabled",
                value="disabled",
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.TRIVIAL,
                metadata={'risk': 'DNS queries visible to network observers'}
            ))

        self.signals.extend(signals)
        return signals


class DNSSinkholeDetector(OpsecAnalyzer):
    """Detect queries to sinkholed domains (threat intelligence feeds)"""

    def __init__(self, sinkhole_list_path: Optional[str] = None):
        super().__init__(OpsecLayer.DNS)
        self.sinkholed_domains: Set[str] = set()
        if sinkhole_list_path:
            self._load_sinkhole_list(sinkhole_list_path)

    def _load_sinkhole_list(self, path: str):
        """Load list of known sinkholed domains"""
        try:
            with open(path, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        self.sinkholed_domains.add(domain)
        except Exception:
            pass

    def add_sinkhole_domain(self, domain: str):
        """Add a sinkholed domain to the detector"""
        self.sinkholed_domains.add(domain.lower())

    def analyze(self, dns_queries: List[Dict[str, Any]]) -> List[Signal]:
        """
        Analyze DNS queries for sinkhole hits

        Expected data format:
        [
            {'domain': 'malicious-example.com', 'timestamp': datetime, 'source_ip': '...'},
            ...
        ]
        """
        signals = []

        for query in dns_queries:
            domain = query.get('domain', '').lower()
            if domain in self.sinkholed_domains:
                signals.append(Signal(
                    signal_id=f"sinkhole_hit_{hashlib.md5(domain.encode()).hexdigest()[:8]}",
                    layer=OpsecLayer.DNS,
                    description=f"Query to sinkholed domain detected",
                    value=domain,
                    timestamp=query.get('timestamp', datetime.now()),
                    correlation_potential=CorrelationStrength.SOLO,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={
                        'domain': domain,
                        'source_ip': query.get('source_ip'),
                        'risk': 'CRITICAL - Infrastructure tagged by threat intelligence',
                        'mitigation': 'Review query source, check for compromised systems'
                    }
                ))

        self.signals.extend(signals)
        return signals


class DNSQueryPatternAnalyzer(OpsecAnalyzer):
    """Analyze DNS query patterns for timing/ordering correlation"""

    def __init__(self):
        super().__init__(OpsecLayer.DNS)

    def analyze(self, dns_queries: List[Dict[str, Any]]) -> List[Signal]:
        """
        Analyze DNS query patterns

        Expected data format:
        [
            {'domain': 'example.com', 'timestamp': datetime, 'query_type': 'A'},
            ...
        ]
        """
        signals = []

        if len(dns_queries) < 2:
            return signals

        # Check for consistent query ordering (application fingerprinting)
        domain_sequence = [q['domain'] for q in dns_queries[:5]]
        if len(domain_sequence) == len(set(domain_sequence)):  # All unique, potential pattern
            signals.append(Signal(
                signal_id="dns_query_ordering",
                layer=OpsecLayer.DNS,
                description="Consistent DNS query ordering detected",
                value=','.join(domain_sequence),
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'sequence': domain_sequence,
                    'risk': 'Query ordering can fingerprint application behavior'
                }
            ))

        # Check query timing (temporal correlation risk)
        time_intervals = []
        for i in range(1, len(dns_queries)):
            delta = (dns_queries[i]['timestamp'] - dns_queries[i-1]['timestamp']).total_seconds()
            time_intervals.append(delta)

        if time_intervals:
            avg_interval = sum(time_intervals) / len(time_intervals)
            if avg_interval < 1.0 and len(time_intervals) > 5:
                signals.append(Signal(
                    signal_id="dns_rapid_queries",
                    layer=OpsecLayer.DNS,
                    description="Rapid DNS queries detected (< 1s average interval)",
                    value=f"{avg_interval:.3f}s average",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'avg_interval_sec': avg_interval,
                        'query_count': len(dns_queries),
                        'risk': 'Timing patterns enable flow correlation'
                    }
                ))

        self.signals.extend(signals)
        return signals


class PassiveDNSRiskAnalyzer(OpsecAnalyzer):
    """Analyze passive DNS exposure risks"""

    def __init__(self):
        super().__init__(OpsecLayer.DNS)

    def analyze(self, infrastructure_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze passive DNS risks for infrastructure

        Expected data format:
        {
            'domains': [
                {
                    'domain': 'example.com',
                    'ips': ['203.0.113.1', '203.0.113.2'],
                    'first_seen': datetime,
                    'last_seen': datetime
                },
                ...
            ]
        }
        """
        signals = []

        if 'domains' not in infrastructure_data:
            return signals

        domains = infrastructure_data['domains']

        # Check for IP co-location (multiple domains on same IP)
        ip_to_domains = defaultdict(list)
        for domain_info in domains:
            for ip in domain_info['ips']:
                ip_to_domains[ip].append(domain_info['domain'])

        for ip, domain_list in ip_to_domains.items():
            if len(domain_list) > 1:
                signals.append(Signal(
                    signal_id=f"ip_colocation_{ip.replace('.', '_')}",
                    layer=OpsecLayer.DNS,
                    description=f"Multiple domains share IP {ip}",
                    value=f"{len(domain_list)} domains",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'ip': ip,
                        'domains': domain_list,
                        'risk': 'Passive DNS enables infrastructure clustering via shared IPs'
                    }
                ))

        # Check for temporal clustering (domains registered/active around same time)
        if len(domains) > 1:
            first_seens = [d['first_seen'] for d in domains if 'first_seen' in d]
            if len(first_seens) > 1:
                time_spread = max(first_seens) - min(first_seens)
                if time_spread < timedelta(days=7):
                    signals.append(Signal(
                        signal_id="temporal_clustering",
                        layer=OpsecLayer.DNS,
                        description="Domains first seen within 7-day window",
                        value=f"{len(first_seens)} domains in {time_spread.days} days",
                        timestamp=datetime.now(),
                        correlation_potential=CorrelationStrength.PAIR,
                        detectability=DetectabilityLevel.MODERATE,
                        metadata={
                            'domain_count': len(first_seens),
                            'time_spread_days': time_spread.days,
                            'risk': 'Temporal clustering suggests campaign setup'
                        }
                    ))

        self.signals.extend(signals)
        return signals
