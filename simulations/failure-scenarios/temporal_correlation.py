"""
Simulation: Temporal Correlation Attack

Demonstrates how timing patterns across layers enable attribution
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.append(str(Path(__file__).parent.parent.parent))

from framework.userland import EnvironmentAnalyzer
from framework.metadata import ActivityTimingAnalyzer
from framework.correlation_engine import CorrelationEngine


def simulate_temporal_correlation():
    """
    Scenario: Operator's activity timing correlates across multiple platforms
    """
    
    print("=" * 70)
    print("SIMULATION: Temporal Correlation Attribution Attack")
    print("=" * 70)
    print()
    
    print("Scenario:")
    print("  An anonymous operator maintains infrastructure AND contributes to")
    print("  GitHub. Both activities have timing patterns that correlate...")
    print()
    
    # Initialize analyzers
    env_analyzer = EnvironmentAnalyzer()
    activity_analyzer = ActivityTimingAnalyzer()
    engine = CorrelationEngine()
    
    print("[*] Observable 1: Infrastructure Access Timing")
    print("    Analyzing SSH login timestamps to operational servers...\n")
    
    # Simulate infrastructure access (always 18:00-02:00 UTC)
    infrastructure_activity = []
    for day in range(15):  # 15 weekdays
        if day % 7 < 5:  # Weekdays only
            for hour in [18, 19, 20, 21, 22, 23, 0, 1]:
                infrastructure_activity.append({
                    'timestamp': datetime(2024, 3, 1 + day) + timedelta(hours=hour),
                    'activity_type': 'ssh_login',
                    'description': 'Server access'
                })
    
    infra_signals = activity_analyzer.analyze(infrastructure_activity)
    engine.add_signals(infra_signals)
    
    print("    Infrastructure access pattern:")
    for signal in infra_signals:
        if 'time_window' in signal.signal_id:
            print(f"      - {signal.description}: {signal.value}")
            print(f"        Risk: {signal.metadata.get('risk')}")
        elif 'timezone' in signal.signal_id:
            print(f"      - {signal.description}: {signal.value}")
    print()
    
    print("[*] Observable 2: GitHub Commit Timing")
    print("    GitHub account 'anonymous_dev' commit pattern...\n")
    
    # Same timing pattern on GitHub (18:00-02:00 UTC)
    github_activity = []
    for day in range(15):
        if day % 7 < 5:  # Weekdays only
            for hour in [18, 19, 20, 21, 22, 23, 0, 1]:
                github_activity.append({
                    'timestamp': datetime(2024, 3, 1 + day) + timedelta(hours=hour),
                    'activity_type': 'git_commit',
                    'description': 'Code commit'
                })
    
    # Create new analyzer instance for GitHub activity
    github_analyzer = ActivityTimingAnalyzer()
    github_signals = github_analyzer.analyze(github_activity)
    engine.add_signals(github_signals)
    
    print("    GitHub commit pattern:")
    for signal in github_signals:
        if 'time_window' in signal.signal_id:
            print(f"      - {signal.description}: {signal.value}")
    print()
    
    print("[*] Observable 3: System Environment")
    print("    Infrastructure server timezone configuration...\n")
    
    env_signals = env_analyzer.analyze()
    engine.add_signals(env_signals)
    
    for signal in env_signals:
        if 'timezone' in signal.signal_id:
            print(f"      - {signal.description}: {signal.value}")
    print()
    
    print("[*] Step 4: Correlation Analysis")
    correlations = engine.correlate_all()
    
    print("=" * 70)
    print("CORRELATION RESULT")
    print("=" * 70)
    print()
    print("✓ Temporal Correlation Detected:")
    print("  - Infrastructure access: 18:00-02:00 UTC (weekdays only)")
    print("  - GitHub commits: 18:00-02:00 UTC (weekdays only)")
    print("  - System timezone: UTC+1 or UTC+2 likely")
    print()
    print("✓ Attribution Logic:")
    print("  1. Both activities occur same time window (18:00-02:00 UTC)")
    print("  2. 18:00 UTC ≈ 19:00-20:00 local time (assuming UTC+1/+2)")
    print("  3. Evening/night activity suggests hobby/after-work project")
    print("  4. Weekday-only pattern suggests human, not automated")
    print("")
    print("✓ Adversary can:")
    print("  - Link 'anonymous_dev' GitHub account to infrastructure")
    print("  - Narrow geographic location to Central/Eastern Europe")
    print("  - Pivot to GitHub account for additional OSINT:")
    print("    → Email address, real name, LinkedIn profile, etc.")
    print()
    print("⚠️  OPSEC Lesson:")
    print("    Temporal patterns are fingerprints. Human habits leak through timing.")
    print("    Solution: Automate operations with randomized timing, or work")
    print("            across multiple timezones to break correlation.")
    print()
    print("=" * 70)


if __name__ == "__main__":
    simulate_temporal_correlation()
