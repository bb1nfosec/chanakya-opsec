"""
Metadata & Temporal OPSEC Analysis Module

Detects OPSEC failures in:
- Activity timing patterns
- Operational cadence
- Behavioral fingerprints
- Timezone correlation
"""

import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework import (
    Signal, OpsecLayer, CorrelationStrength, DetectabilityLevel, OpsecAnalyzer
)


class ActivityTimingAnalyzer(OpsecAnalyzer):
    """Analyze activity timing patterns for timezone/schedule correlation"""

    def __init__(self):
        super().__init__(OpsecLayer.METADATA)

    def analyze(self, activity_data: List[Dict[str, Any]]) -> List[Signal]:
        """
        Analyze activity timing patterns

        Expected data format:
        [
            {'timestamp': datetime, 'activity_type': 'commit', 'description': '...'},
            ...
        ]
        """
        signals = []

        if len(activity_data) < 5:
            return signals

        timestamps = [a['timestamp'] for a in activity_data]

        # Analyze hour-of-day distribution
        hours = [t.hour for t in timestamps]
        hour_distribution = Counter(hours)

        # Find primary activity window
        if hour_distribution:
            most_common_hours = hour_distribution.most_common(8)  # Top 8 hours
            active_hours = [h for h, count in most_common_hours]
            
            # Check if activity is clustered in specific window
            if len(active_hours) == 8 and max(active_hours) - min(active_hours) <= 10:
                start_hour = min(active_hours)
                end_hour = max(active_hours)
                
                signals.append(Signal(
                    signal_id="activity_time_window",
                    layer=OpsecLayer.METADATA,
                    description="Activity concentrated in specific time window",
                    value=f"{start_hour:02d}:00-{end_hour:02d}:00 UTC",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={
                        'start_hour': start_hour,
                        'end_hour': end_hour,
                        'hour_distribution': dict(hour_distribution),
                        'risk': 'Activity window correlates to human timezone/schedule'
                    }
                ))

                # Estimate timezone
                # Most activity likely during working hours (09:00-17:00 local time)
                estimated_tz_offset = start_hour - 9  # Assume start correlates to 09:00 local
                signals.append(Signal(
                    signal_id="estimated_timezone",
                    layer=OpsecLayer.METADATA,
                    description="Estimated operator timezone",
                    value=f"UTC{estimated_tz_offset:+.1f}",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'estimated_offset_hours': estimated_tz_offset,
                        'confidence': 'MEDIUM',
                        'risk': 'Timezone estimation enables geographic attribution'
                    }
                ))

        # Weekday vs. weekend analysis
        weekdays = [t.weekday() for t in timestamps]  # 0=Monday, 6=Sunday
        weekend count = sum(1 for d in weekdays if d >= 5)
        weekday_count = len(weekdays) - weekend_count

        if weekday_count > 0 and weekend_count == 0 and len(timestamps) > 10:
            signals.append(Signal(
                signal_id="no_weekend_activity",
                layer=OpsecLayer.METADATA,
                description="No weekend activity detected",
                value=f"{len(timestamps)} events, all weekdays",
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    'total_events': len(timestamps),
                    'weekend_events': weekend_count,
                    'risk': 'Weekday-only pattern suggests manual operation (not automated)'
                }
            ))

        self.signals.extend(signals)
        return signals


class OperationalCadenceAnalyzer(OpsecAnalyzer):
    """Analyze operational cadence and update patterns"""

    def __init__(self):
        super().__init__(OpsecLayer.METADATA)

    def analyze(self, operational_events: List[Dict[str, Any]]) -> List[Signal]:
        """
        Analyze operational cadence

        Expected data format:
        [
            {
                'timestamp': datetime,
                'event_type': 'infrastructure_update',
                'description': '...'
            },
            ...
        ]
        """
        signals = []

        if len(operational_events) < 3:
            return signals

        timestamps = sorted([e['timestamp'] for e in operational_events])

        # Calculate intervals between events
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600  # hours
            intervals.append(delta)

        if intervals:
            avg_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

            # Check for periodic updates
            coefficient_of_variation = (std_interval / avg_interval) if avg_interval > 0 else 1
            
            if coefficient_of_variation < 0.3:  # Low variance = predictable cadence
                signals.append(Signal(
                    signal_id="predictable_cadence",
                    layer=OpsecLayer.METADATA,
                    description="Predictable operational cadence detected",
                    value=f"Every {avg_interval:.1f}h ± {std_interval:.1f}h",
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'avg_interval_hours': avg_interval,
                        'std_dev_hours': std_interval,
                        'coefficient_of_variation': coefficient_of_variation,
                        'risk': 'Predictable cadence enables temporal correlation across operations'
                    }
                ))

            # Check for specific day-of-week patterns
            update_days = [t.weekday() for t in timestamps]
            day_distribution = Counter(update_days)
            most_common_day = day_distribution.most_common(1)[0]
            
            if most_common_day[1] >= len(timestamps) * 0.5:  # >50% on same weekday
                day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                signals.append(Signal(
                    signal_id="preferred_update_day",
                    layer=OpsecLayer.METADATA,
                    description="Updates concentrated on specific weekday",
                    value=day_names[most_common_day[0]],
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'preferred_day': day_names[most_common_day[0]],
                        'occurrence_rate': most_common_day[1] / len(timestamps),
                        'risk': 'Consistent update timing fingerprints operational procedures'
                    }
                ))

        self.signals.extend(signals)
        return signals


class BehavioralFingerprintAnalyzer(OpsecAnalyzer):
    """Analyze behavioral patterns across operations"""

    def __init__(self):
        super().__init__(OpsecLayer.METADATA)

    def analyze(self, behavioral_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze behavioral fingerprints

        Expected data format:
        {
            'session_durations': [3600, 7200, 5400, ...],  # seconds
            'response_latencies': [120, 180, 95, ...],  # seconds
            'error_patterns': [...],
            'operational_tempo': {'commits_per_day': 3.5, 'avg_session_length_hours': 2.1}
        }
        """
        signals = []

        # Session duration analysis
        if 'session_durations' in behavioral_data:
            durations = behavioral_data['session_durations']
            if len(durations) >= 5:
                avg_duration = statistics.mean(durations) / 3600  # to hours
                std_duration = statistics.stdev(durations) / 3600 if len(durations) > 1 else 0

                # Consistent 8-hour sessions = likely human work shift
                if 6 <= avg_duration <= 10 and std_duration < 2:
                    signals.append(Signal(
                        signal_id="work_shift_pattern",
                        layer=OpsecLayer.METADATA,
                        description="Session durations match work shift pattern",
                        value=f"{avg_duration:.1f}h average",
                        timestamp=datetime.now(),
                        correlation_potential=CorrelationStrength.PAIR,
                        detectability=DetectabilityLevel.MODERATE,
                        metadata={
                            'avg_duration_hours': avg_duration,
                            'std_dev_hours': std_duration,
                            'risk': 'Human work shift patterns enable behavioral attribution'
                        }
                    ))

        # Response latency analysis
        if 'response_latencies' in behavioral_data:
            latencies = behavioral_data['response_latencies']
            if len(latencies) >= 5:
                avg_latency = statistics.mean(latencies)
                
                # Very fast responses (< 30s avg) = automation
                # Medium responses (30s - 5min) = human monitoring with automation
                # Slow responses (> 5min) = manual operation
                
                if avg_latency < 30:
                    automation_level = "HIGH"
                elif avg_latency < 300:
                    automation_level = "MEDIUM"
                else:
                    automation_level = "LOW"

                signals.append(Signal(
                    signal_id="automation_level",
                    layer=OpsecLayer.METADATA,
                    description="Estimated automation level",
                    value=automation_level,
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={
                        'avg_response_latency_sec': avg_latency,
                        'automation_level': automation_level,
                        'risk': 'Automation level reveals operational maturity and resources'
                    }
                ))

        # Operational tempo
        if 'operational_tempo' in behavioral_data:
            tempo = behavioral_data['operational_tempo']
            signals.append(Signal(
                signal_id="operational_tempo",
                layer=OpsecLayer.METADATA,
                description="Operational tempo fingerprint",
                value=str(tempo),
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.MULTI,
                detectability=DetectabilityLevel.MODERATE,
                metadata={
                    **tempo,
                    'risk': 'Operational tempo consistent across campaigns enables linking'
                }
            ))

        self.signals.extend(signals)
        return signals
