"""DNS OPSEC Analysis Module"""

from .analyzer import (
    DNSResolverAnalyzer,
    DNSSinkholeDetector,
    DNSQueryPatternAnalyzer,
    PassiveDNSRiskAnalyzer
)

__all__ = [
    'DNSResolverAnalyzer',
    'DNSSinkholeDetector',
    'DNSQueryPatternAnalyzer',
    'PassiveDNSRiskAnalyzer'
]
