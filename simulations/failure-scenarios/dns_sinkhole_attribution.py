"""
Simulation: DNS Sinkhole Attribution

Demonstrates how a single DNS sinkhole hit can expose entire infrastructure
through passive DNS correlation
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random

sys.path.append(str(Path(__file__).parent.parent.parent))

from framework import Signal
from framework.dns import DNSSinkholeDetector, PassiveDNSRiskAnalyzer
from framework.correlation_engine import CorrelationEngine


def simulate_dns_sinkhole_scenario():
    """
    Scenario: Operator queries a sinkholed domain, exposing infrastructure
    """
    
    print("=" * 70)
    print("SIMULATION: DNS Sinkhole Attribution Attack")
    print("=" * 70)
    print()
    
    print("Scenario:")
    print("  An operator's malware queries a C2 domain that has been sinkholed")
    print("  by threat intelligence. This triggers a cascade of attribution...")
    print()
    
    # Initialize analyzers
    sinkhole_detector = DNSSinkholeDetector()
    passive_dns_analyzer = PassiveDNSRiskAnalyzer()
    engine = CorrelationEngine()
    
    # Add known sinkholed domains
    sinkholed_domains = [
        'malicious-c2-domain.com',
        'evil-command-server.net',
        'bad-actor-infrastructure.org'
    ]
    
    for domain in sinkholed_domains:
        sinkhole_detector.add_sinkhole_domain(domain)
    
    print("[*] Step 1: DNS Query to Sinkholed Domain")
    print("    Malware on infected system queries: malicious-c2-domain.com\n")
    
    # Simulate DNS queries including sinkhole hit
    dns_queries = [
        {'domain': 'google.com', 'timestamp': datetime.now(), 'source_ip': '203.0.113.42'},
        {'domain': 'malicious-c2-domain.com', 'timestamp': datetime.now(), 'source_ip': '203.0.113.42'},  # SINKHOLE HIT
        {'domain': 'github.com', 'timestamp': datetime.now(), 'source_ip': '203.0.113.42'},
    ]
    
    sinkhole_signals = sinkhole_detector.analyze(dns_queries)
engine.add_signals(sinkhole_signals)
    
    if sinkhole_signals:
        print("    ⚠️  SINKHOLE HIT DETECTED!")
        for signal in sinkhole_signals:
            print(f"        - Domain: {signal.value}")
            print(f"        - Source IP: {signal.metadata.get('source_ip')}")
            print(f"        - Risk: {signal.metadata.get('risk')}\n")
    
    print("[*] Step 2: Passive DNS Pivot")
    print("    Threat hunters query passive DNS for source IP 203.0.113.42...")
    print("    Historical DNS data reveals additional infrastructure:\n")
    
    # Simulate passive DNS findings
    infrastructure_data = {
        'domains': [
            {
                'domain': 'malicious-c2-domain.com',
                'ips': ['203.0.113.42'],
                'first_seen': datetime.now() - timedelta(days=30),
                'last_seen': datetime.now()
            },
            {
                'domain': 'backup-c2-server.com',
                'ips': ['203.0.113.42', '203.0.113.43'],
                'first_seen': datetime.now() - timedelta(days=28),
                'last_seen': datetime.now() - timedelta(days=1)
            },
            {
                'domain': 'phishing-landing-page.com',
                'ips': ['203.0.113.43'],
                'first_seen': datetime.now() - timedelta(days=25),
                'last_seen': datetime.now() - timedelta(days=2)
            },
            {
                'domain': 'data-exfil-server.net',
                'ips': ['203.0.113.44'],
                'first_seen': datetime.now() - timedelta(days=27),
                'last_seen': datetime.now()
            }
        ]
    }
    
    passive_dns_signals = passive_dns_analyzer.analyze(infrastructure_data)
    engine.add_signals(passive_dns_signals)
    
    print("    Discovered domains via passive DNS pivot:")
    for domain_info in infrastructure_data['domains']:
        print(f"      - {domain_info['domain']}")
        print(f"        IPs: {', '.join(domain_info['ips'])}")
        days_ago = (datetime.now() - domain_info['first_seen']).days
        print(f"        First seen: {days_ago} days ago\n")
    
    print("[*] Step 3: Infrastructure Clustering")
    print("    Analysis shows IP co-location and temporal clustering:\n")
    
    for signal in passive_dns_signals:
        print(f"    - {signal.description}")
        print(f"      Value: {signal.value}")
        print(f"      Risk: {signal.metadata.get('risk', 'N/A')}\n")
    
    print("[*] Step 4: Correlation Analysis")
    correlations = engine.correlate_all()
    
    print(f"    Total correlations identified: {len(correlations)}\n")
    
    print("=" * 70)
    print("ATTRIBUTION RESULT")
    print("=" * 70)
    print()
    print("✓ Single sinkhole hit exposed:")
    print("  - 4 related domains")
    print("  - 3 IP addresses (inferred from passive DNS)")
    print("  - Temporal clustering (all registered within 1 week)")
    print("  - IP co-location (multiple domains share IPs)")
    print()
    print("✓ Adversary can now:")
    print("  - Block all discovered infrastructure")
    print("  - Monitor passive DNS for new domains in same IP range")
    print("  - Track campaign evolution over time")
    print()
    print("⚠️  OPSEC Lesson:")
    print("    One sinkholed domain query → Full infrastructure enumeration")
    print("    Passive DNS creates permanent historical linkage")
    print()
    print("=" * 70)


if __name__ == "__main__":
    simulate_dns_sinkhole_scenario()
