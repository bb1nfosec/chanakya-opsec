"""
CHANAKYA OPSEC Framework Example

Demonstrates multi-layer OPSEC analysis and correlation
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add framework to path
sys.path.append(str(Path(__file__).parent.parent))

from framework import Signal, OpsecLayer
from framework.userland import BinaryAnalyzer, EnvironmentAnalyzer
from framework.dns import DNSResolverAnalyzer, DNSSinkholeDetector, DNSQueryPatternAnalyzer
from framework.routing import ASPathAnalyzer, TrafficPatternAnalyzer
from framework.metadata import ActivityTimingAnalyzer, OperationalCadenceAnalyzer
from framework.correlation_engine import CorrelationEngine


def example_opsec_audit():
    """
    Example: Comprehensive OPSEC audit of a hypothetical operation
    """
    
    print("=" * 70)
    print("CHANAKYA OPSEC AUDIT EXAMPLE")
    print("=" * 70)
    print()

    # Initialize analyzers
    env_analyzer = EnvironmentAnalyzer()
    dns_resolver_analyzer = DNSResolverAnalyzer()
    dns_query_analyzer = DNSQueryPatternAnalyzer()
    as_path_analyzer = ASPathAnalyzer()
    activity_analyzer = ActivityTimingAnalyzer()
    
    # Initialize correlation engine
    engine = CorrelationEngine()

    print("[*] Step 1: Analyzing Userland Environment...")
    env_signals = env_analyzer.analyze()
    engine.add_signals(env_signals)
    print(f"    Found {len(env_signals)} userland signals")

    print("\n[*] Step 2: Analyzing DNS Configuration...")
    dns_config = {
        'resolvers': ['8.8.8.8'],
        'vpn_as': 'AS64512',  # Example VPN AS
        'doh_enabled': False
    }
    dns_signals = dns_resolver_analyzer.analyze(dns_config)
    engine.add_signals(dns_signals)
    print(f"    Found {len(dns_signals)} DNS configuration signals")

    print("\n[*] Step 3: Analyzing DNS Query Patterns...")
    # Simulate DNS queries
    base_time = datetime.now()
    dns_queries = [
        {'domain': 'api.example.com', 'timestamp': base_time, 'query_type': 'A'},
        {'domain': 'cdn.example.com', 'timestamp': base_time + timedelta(milliseconds=100), 'query_type': 'A'},
        {'domain': 'auth.example.com', 'timestamp': base_time + timedelta(milliseconds=200), 'query_type': 'A'},
    ]
    query_signals = dns_query_analyzer.analyze(dns_queries)
    engine.add_signals(query_signals)
    print(f"    Found {len(query_signals)} DNS query pattern signals")

    print("\n[*] Step 4: Analyzing Network Routing...")
    routing_data = {
        'as_path': ['AS64512', 'AS6939', 'AS174', 'AS15169'],
        'origin_as': 'AS64512',
        'destination_as': 'AS15169',
        'geographic_path': ['SE', 'DE', 'US']
    }
    routing_signals = as_path_analyzer.analyze(routing_data)
    engine.add_signals(routing_signals)
    print(f"    Found {len(routing_signals)} network routing signals")

    print("\n[*] Step 5: Analyzing Activity Timing...")
    # Simulate activity times (all during 18:00-02:00 UTC, weekdays only)
    activity_data = []
    for day in range(10):  # 10 weekdays
        for hour in [18, 19, 20, 21, 22, 23, 0, 1]:
            activity_data.append({
                'timestamp': datetime(2024, 3, 1 + day) + timedelta(hours=hour),
                'activity_type': 'operation',
                'description': 'operational activity'
            })
    
    activity_signals = activity_analyzer.analyze(activity_data)
    engine.add_signals(activity_signals)
    print(f"    Found {len(activity_signals)} activity timing signals")

    print("\n" + "=" * 70)
    print("CORRELATION ANALYSIS")
    print("=" * 70)
    print()

    print("[*] Running multi-layer correlation analysis...")
    correlations = engine.correlate_all()
    print(f"    Identified {len(correlations)} correlation patterns\n")

    # Display correlations by severity
    critical = engine.get_critical_correlations()
    high_risk = [c for c in engine.get_high_risk_correlations() if c.attribution_confidence == "HIGH"]

    if critical:
        print("⚠️  CRITICAL CORRELATIONS:")
        for i, corr in enumerate(critical, 1):
            print(f"\n    {i}. {corr.correlation_type}")
            print(f"       Confidence: {corr.attribution_confidence}")
            print(f"       Risk Level: {corr.risk_level}")
            print(f"       Explanation: {corr.explanation}")
            print(f"       Signals: {len(corr.signals)} ({', '.join(set(s.layer.value for s in corr.signals))})")

    if high_risk:
        print("\n⚠️  HIGH-RISK CORRELATIONS:")
        for i, corr in enumerate(high_risk, 1):
            print(f"\n    {i}. {corr.correlation_type}")
            print(f"       Confidence: {corr.attribution_confidence}")
            print(f"       Risk Level: {corr.risk_level}")
            print(f"       Explanation: {corr.explanation}")

    print("\n" + "=" * 70)
    print("MITIGATION RECOMMENDATIONS")
    print("=" * 70)
    print()

    recommendations = engine.get_mitigation_recommendations()
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. [{rec['priority']}] {rec['issue']}")
            print(f"   → {rec['recommendation']}")
            print(f"   Layers affected: {', '.join(rec['layers'])}\n")
    else:
        print("No high-priority mitigations identified.")

    print("\n" + "=" * 70)
    print("FULL REPORT")
    print("=" * 70)
    print()

    report = engine.generate_report()
    print(f"Total Signals: {report['summary']['total_signals']}")
    print(f"Total Correlations: {report['summary']['total_correlations']}")
    print(f"\nSignals by Layer:")
    for layer, count in report['summary']['signals_by_layer'].items():
        print(f"  - {layer}: {count}")
    print(f"\nCorrelations by Confidence:")
    for confidence, count in report['summary']['correlations_by_confidence'].items():
        print(f"  - {confidence}: {count}")

    # Export full report
    report_path = Path(__file__).parent / "opsec_audit_report.json"
    engine.export_report_json(str(report_path))
    print(f"\n📄 Full report exported to: {report_path}")

    print("\n" + "=" * 70)
    print("AUDIT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    example_opsec_audit()
