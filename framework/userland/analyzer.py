"""
Userland OPSEC Analysis Module

Detects OPSEC failures in:
- Binary fingerprinting
- Environment leakage
- Process behavior
- TLS fingerprinting
"""

import hashlib
import os
import platform
import subprocess
import struct
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent))

from framework import (
    Signal, OpsecLayer, CorrelationStrength, DetectabilityLevel, OpsecAnalyzer
)


class BinaryAnalyzer(OpsecAnalyzer):
    """Analyze binary files for OPSEC failures"""

    def __init__(self):
        super().__init__(OpsecLayer.USERLAND)

    def analyze(self, binary_path: str) -> List[Signal]:
        """Analyze binary for fingerprinting risks"""
        signals = []

        if not os.path.exists(binary_path):
            return signals

        # File entropy (potential packing/obfuscation detection)
        entropy_signal = self._analyze_entropy(binary_path)
        if entropy_signal:
            signals.append(entropy_signal)

        # PE/ELF header analysis
        header_signals = self._analyze_headers(binary_path)
        signals.extend(header_signals)

        # String extraction (potential info leaks)
        string_signals = self._analyze_strings(binary_path)
        signals.extend(string_signals)

        self.signals.extend(signals)
        return signals

    def _analyze_entropy(self, binary_path: str) -> Optional[Signal]:
        """Calculate file entropy"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            if not data:
                return None

            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * (probability.bit_length() if probability > 0 else 0)

            # High entropy (> 7.0) suggests packing/encryption
            if entropy > 7.0:
                return Signal(
                    signal_id=f"entropy_{Path(binary_path).name}",
                    layer=OpsecLayer.USERLAND,
                    description="High binary entropy detected (possible packing/obfuscation)",
                    value=round(entropy, 2),
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.MULTI,
                    detectability=DetectabilityLevel.MODERATE,
                    metadata={'file': binary_path, 'entropy': entropy}
                )
        except Exception as e:
            return None

        return None

    def _analyze_headers(self, binary_path: str) -> List[Signal]:
        """Analyze PE/ELF headers for metadata leakage"""
        signals = []

        try:
            with open(binary_path, 'rb') as f:
                header = f.read(4)

            # PE file (Windows)
            if header[:2] == b'MZ':
                pe_signals = self._analyze_pe_header(binary_path)
                signals.extend(pe_signals)

            # ELF file (Linux/Unix)
            elif header == b'\x7fELF':
                elf_signals = self._analyze_elf_header(binary_path)
                signals.extend(elf_signals)

        except Exception:
            pass

        return signals

    def _analyze_pe_header(self, binary_path: str) -> List[Signal]:
        """Analyze PE (Windows executable) headers"""
        signals = []

        try:
            with open(binary_path, 'rb') as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset + 8)
                timestamp = struct.unpack('<I', f.read(4))[0]

            if timestamp > 0:
                compile_time = datetime.fromtimestamp(timestamp)

                # Check if timestamp is suspiciously recent or follows a pattern
                signals.append(Signal(
                    signal_id=f"pe_timestamp_{Path(binary_path).name}",
                    layer=OpsecLayer.USERLAND,
                    description="PE compilation timestamp",
                    value=compile_time.isoformat(),
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={
                        'file': binary_path,
                        'compile_time': compile_time.isoformat(),
                        'hour': compile_time.hour,
                        'weekday': compile_time.strftime('%A')
                    }
                ))

        except Exception:
            pass

        return signals

    def _analyze_elf_header(self, binary_path: str) -> List[Signal]:
        """Analyze ELF (Linux binary) headers"""
        signals = []

        # ELF analysis would go here (similar to PE)
        # For now, just note the file type

        signals.append(Signal(
            signal_id=f"elf_detected_{Path(binary_path).name}",
            layer=OpsecLayer.USERLAND,
            description="ELF binary detected",
            value="ELF",
            timestamp=datetime.now(),
            correlation_potential=CorrelationStrength.WEAK,
            detectability=DetectabilityLevel.TRIVIAL,
            metadata={'file': binary_path, 'format': 'ELF'}
        ))

        return signals

    def _analyze_strings(self, binary_path: str, min_length: int = 8) -> List[Signal]:
        """Extract and analyze strings from binary"""
        signals = []

        try:
            # Look for suspicious patterns
            suspicious_patterns = [
                ('email', r'[\w\.-]+@[\w\.-]+\.\w+'),
                ('path', r'[A-Z]:\\[\w\\]+'),
                ('url', r'https?://[\w\./]+'),
                ('username', r'/home/\w+/'),
            ]

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Simple string extraction
            current_string = b''
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                elif len(current_string) >= min_length:
                    string_value = current_string.decode('ascii', errors='ignore')

                    # Check for suspicious patterns
                    for pattern_name, pattern in suspicious_patterns:
                        if pattern_name == 'path' and ('\\Users\\' in string_value or '\\home\\' in string_value):
                            signals.append(Signal(
                                signal_id=f"path_leak_{hashlib.md5(string_value.encode()).hexdigest()[:8]}",
                                layer=OpsecLayer.USERLAND,
                                description=f"Build path leakage detected",
                                value=string_value[:100],
                                timestamp=datetime.now(),
                                correlation_potential=CorrelationStrength.SOLO,
                                detectability=DetectabilityLevel.TRIVIAL,
                                metadata={'file': binary_path, 'type': 'path'}
                            ))
                            break

                    current_string = b''

        except Exception:
            pass

        return signals[:10]  # Limit to 10 signals


class EnvironmentAnalyzer(OpsecAnalyzer):
    """Analyze runtime environment for OPSEC leaks"""

    def __init__(self):
        super().__init__(OpsecLayer.USERLAND)

    def analyze(self, data: Any = None) -> List[Signal]:
        """Analyze current environment for leakage"""
        signals = []

        # Timezone detection
        timezone_signal = self._analyze_timezone()
        if timezone_signal:
            signals.append(timezone_signal)

        # Locale detection
        locale_signal = self._analyze_locale()
        if locale_signal:
            signals.append(locale_signal)

        # OS fingerprint
        os_signal = self._analyze_os()
        if os_signal:
            signals.append(os_signal)

        # Environment variables
        env_signals = self._analyze_env_vars()
        signals.extend(env_signals)

        self.signals.extend(signals)
        return signals

    def _analyze_timezone(self) -> Optional[Signal]:
        """Detect timezone configuration"""
        try:
            import time
            tz_offset = -time.timezone / 3600
            tz_name = time.tzname[0]

            return Signal(
                signal_id="timezone",
                layer=OpsecLayer.USERLAND,
                description="System timezone configuration",
                value=f"{tz_name} (UTC{tz_offset:+.1f})",
                timestamp=datetime.now(),
                correlation_potential=CorrelationStrength.PAIR,
                detectability=DetectabilityLevel.TRIVIAL,
                metadata={'offset_hours': tz_offset, 'name': tz_name}
            )
        except Exception:
            return None

    def _analyze_locale(self) -> Optional[Signal]:
        """Detect locale configuration"""
        locale_vars = ['LANG', 'LC_ALL', 'LC_MESSAGES']
        for var in locale_vars:
            if var in os.environ:
                return Signal(
                    signal_id="locale",
                    layer=OpsecLayer.USERLAND,
                    description="System locale configuration",
                    value=os.environ[var],
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={'env_var': var, 'value': os.environ[var]}
                )
        return None

    def _analyze_os(self) -> Optional[Signal]:
        """Detect OS fingerprint"""
        os_info = platform.platform()
        return Signal(
            signal_id="os_platform",
            layer=OpsecLayer.USERLAND,
            description="Operating system fingerprint",
            value=os_info,
            timestamp=datetime.now(),
            correlation_potential=CorrelationStrength.MULTI,
            detectability=DetectabilityLevel.TRIVIAL,
            metadata={
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version()
            }
        )

    def _analyze_env_vars(self) -> List[Signal]:
        """Detect sensitive environment variable leakage"""
        signals = []
        sensitive_vars = ['USER', 'USERNAME', 'HOME', 'USERPROFILE', 'HOSTNAME', 'COMPUTERNAME']

        for var in sensitive_vars:
            if var in os.environ:
                signals.append(Signal(
                    signal_id=f"env_{var.lower()}",
                    layer=OpsecLayer.USERLAND,
                    description=f"Environment variable '{var}' detected",
                    value=os.environ[var],
                    timestamp=datetime.now(),
                    correlation_potential=CorrelationStrength.PAIR,
                    detectability=DetectabilityLevel.TRIVIAL,
                    metadata={'env_var': var, 'value': os.environ[var]}
                ))

        return signals


class TLSFingerprintAnalyzer(OpsecAnalyzer):
    """Analyze TLS client fingerprinting (conceptual - requires packet capture)"""

    def __init__(self):
        super().__init__(OpsecLayer.USERLAND)

    def analyze(self, tls_handshake_data: Dict[str, Any]) -> List[Signal]:
        """
        Analyze TLS Client Hello for fingerprinting

        Expected data format:
        {
            'cipher_suites': [0xc02f, 0xc030, ...],
            'extensions': [0x0000, 0x000d, ...],
            'curves': [0x001d, 0x0017, ...],
            'signature_algorithms': [0x0401, 0x0501, ...]
        }
        """
        signals = []

        if not tls_handshake_data:
            return signals

        # Create JA3-like fingerprint
        ja3_string = self._create_ja3_string(tls_handshake_data)
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        signals.append(Signal(
            signal_id="tls_fingerprint",
            layer=OpsecLayer.USERLAND,
            description="TLS client fingerprint (JA3-style)",
            value=ja3_hash,
            timestamp=datetime.now(),
            correlation_potential=CorrelationStrength.PAIR,
            detectability=DetectabilityLevel.TRIVIAL,
            metadata={'ja3_string': ja3_string, 'ja3_hash': ja3_hash}
        ))

        self.signals.extend(signals)
        return signals

    def _create_ja3_string(self, handshake: Dict[str, Any]) -> str:
        """Create JA3 fingerprint string"""
        cipher_suites = ','.join(str(c) for c in handshake.get('cipher_suites', []))
        extensions = ','.join(str(e) for e in handshake.get('extensions', []))
        curves = ','.join(str(c) for c in handshake.get('curves', []))
        sig_algs = ','.join(str(s) for s in handshake.get('signature_algorithms', []))

        return f"{cipher_suites},{extensions},{curves},{sig_algs}"
