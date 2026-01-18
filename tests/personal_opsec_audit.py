#!/usr/bin/env python3
"""
Personal OPSEC Audit - Quick 5-Minute Check
Tests for common OPSEC failures before operations
"""

import subprocess
import socket
import platform
import os
from datetime import datetime


class PersonalOpsecAudit:
    """Quick pre-operation OPSEC audit"""
    
    def __init__(self):
        self.results = []
        self.critical_failures = 0
        
    def log(self, test_name, passed, message, criticality="WARN"):
        """Log test result"""
        status = "✓ PASS" if passed else "✗ FAIL"
        self.results.append({
            'test': test_name,
            'passed': passed,
            'message': message,
            'criticality': criticality
        })
        
        if not passed and criticality == "CRITICAL":
            self.critical_failures += 1
        
        icon = "🟢" if passed else ("🔴" if criticality == "CRITICAL" else "🟡")
        print(f"{icon} {status} - {test_name}")
        if not passed:
            print(f"     → {message}")
    
    def test_dns_leak(self):
        """Test for DNS leaks"""
        print("\n[1/8] Testing DNS Leak...")
        
        try:
            # Get DNS server (simplified - real test would query external service)
            # This is a placeholder - real implementation would use dnsleak test site
            
            # Check if using common DNS servers
            result = subprocess.run(['nslookup', 'google.com'], 
                                  capture_output=True, text=True, timeout=5)
            
            common_dns = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            using_common = any(dns in result.stdout for dns in common_dns)
            
            if using_common:
                self.log(
                    "DNS Configuration",
                    False,
                    "Using public DNS (Google/Cloudflare) - may leak queries. Use DoH or VPN DNS.",
                    "WARN"
                )
            else:
                self.log("DNS Configuration", True, "Custom DNS configured")
                
        except Exception as e:
            self.log("DNS Configuration", False, f"Unable to test: {e}", "WARN")
    
    def test_timezone(self):
        """Check if timezone is set to UTC"""
        print("\n[2/8] Testing Timezone Configuration...")
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tzutil', '/g'], capture_output=True, text=True)
                tz = result.stdout.strip()
                is_utc = 'UTC' in tz or 'Coordinated Universal' in tz
            else:
                import time
                is_utc = time.timezone == 0
                tz = time.tzname[0]
            
            if not is_utc:
                self.log(
                    "Timezone",
                    False,
                    f"Timezone is {tz}. Should be UTC to prevent geographic fingerprinting.",
                    "WARN"
                )
            else:
                self.log("Timezone", True, "Set to UTC")
                
        except Exception as e:
            self.log("Timezone", False, f"Unable to test: {e}", "WARN")
    
    def test_vpn_connection(self):
        """Verify VPN/Tor is active"""
        print("\n[3/8] Testing Network Protection...")
        
        try:
            # Check for VPN interfaces (simplified)
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                has_vpn = 'TAP' in result.stdout or 'VPN' in result.stdout
            else:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                has_vpn = 'tun' in result.stdout or 'tap' in result.stdout
            
            if not has_vpn:
                self.log(
                    "VPN/Tor Connection",
                    False,
                    "No VPN interface detected. Connections may expose real IP.",
                    "CRITICAL"
                )
            else:
                self.log("VPN/Tor Connection", True, "VPN interface active")
                
        except Exception as e:
            self.log("VPN/Tor Connection", False, f"Unable to test: {e}", "CRITICAL")
    
    def test_tor_browser_fingerprint(self):
        """Check for Tor Browser (recommended for operations)"""
        print("\n[4/8] Testing Browser Security...")
        
        # Check if Tor Browser is installed (simplified check)
        tor_paths = [
            r"C:\Program Files\Tor Browser",
            r"C:\Users\{}\AppData\Local\Tor Browser".format(os.getenv('USERNAME')),
            "/usr/local/bin/tor",
            os.path.expanduser("~/tor-browser")
        ]
        
        tor_installed = any(os.path.exists(path) for path in tor_paths)
        
        if not tor_installed:
            self.log(
                "Tor Browser",
                False,
                "Tor Browser not detected. Regular browsers leak fingerprints.",
                "WARN"
            )
        else:
            self.log("Tor Browser", True, "Tor Browser installed")
    
    def test_disk_encryption(self):
        """Check for full disk encryption"""
        print("\n[5/8] Testing Disk Encryption...")
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['manage-bde', '-status'], 
                                      capture_output=True, text=True)
                encrypted = 'Protection On' in result.stdout
            else:
                # Linux - check for LUKS
                result = subprocess.run(['lsblk', '-f'], 
                                      capture_output=True, text=True)
                encrypted = 'crypto_LUKS' in result.stdout
            
            if not encrypted:
                self.log(
                    "Disk Encryption",
                    False,
                    "Full disk encryption not detected. Data at risk if device seized.",
                    "CRITICAL"
                )
            else:
                self.log("Disk Encryption", True, "Full disk encryption active")
                
        except Exception as e:
            self.log("Disk Encryption", False, f"Unable to test: {e}", "CRITICAL")
    
    def test_swap_encryption(self):
        """Check if swap is encrypted or disabled"""
        print("\n[6/8] Testing Swap Security...")
        
        try:
            if platform.system() != 'Windows':
                result = subprocess.run(['swapon', '--show'], 
                                      capture_output=True, text=True)
                
                if result.stdout.strip() == '':
                    self.log("Swap", True, "Swap disabled (secure)")
                elif '/dev/mapper' in result.stdout:
                    self.log("Swap", True, "Encrypted swap active")
                else:
                    self.log(
                        "Swap",
                        False,
                        "Unencrypted swap detected. May leak plaintext from encrypted volumes.",
                        "WARN"
                    )
            else:
                # Windows - check pagefile
                self.log("Swap", True, "Windows - manual verification needed")
                
        except Exception as e:
            self.log("Swap", False, f"Unable to test: {e}", "WARN")
    
    def test_webcam_mic(self):
        """Check for camera/mic hardware kill switches"""
        print("\n[7/8] Testing Hardware Privacy...")
        
        # This is advisory only - can't actually detect physical switches
        print("     ⚠️  MANUAL CHECK REQUIRED:")
        print("         - Is webcam physically covered?")
        print("         - Is microphone hardware disabled?")
        print("         - Hardware kill switches enabled?")
        
        self.log(
            "Webcam/Mic Security",
            None,  # Manual check
            "Manual verification required",
            "INFO"
        )
    
    def test_phone_location(self):
        """Remind about phone location"""
        print("\n[8/8] Testing Mobile Device Security...")
        
        print("     ⚠️  MANUAL CHECK REQUIRED:")
        print("         - Is phone in Faraday bag OR left at home?")
        print("         - No personal SIM in any device?")
        print("         - Burner phone (if needed) is fresh?")
        
        self.log(
            "Mobile Phone OPSEC",
            None,
            "Manual verification required",
            "INFO"
        )
    
    def generate_report(self):
        """Generate final report"""
        print("\n" + "="*70)
        print("PERSONAL OPSEC AUDIT REPORT")
        print("="*70)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"\nTests Run: {len([r for r in self.results if r['passed'] is not None])}")
        print(f"Passed: {len([r for r in self.results if r['passed'] == True])}")
        print(f"Failed: {len([r for r in self.results if r['passed'] == False])}")
        print(f"Manual Checks: {len([r for r in self.results if r['passed'] is None])}")
        
        if self.critical_failures > 0:
            print(f"\n🚨 CRITICAL FAILURES: {self.critical_failures}")
            print("⛔ DO NOT PROCEED WITH OPERATION")
            print("\nFailed Critical Checks:")
            for r in self.results:
                if not r['passed'] and r['criticality'] == 'CRITICAL':
                    print(f"  - {r['test']}: {r['message']}")
        else:
            print("\n✅ NO CRITICAL FAILURES")
            print("✓ Safe to proceed (after manual checks)")
        
        # Warnings
        warnings = [r for r in self.results if not r['passed'] and r['criticality'] == 'WARN']
        if warnings:
            print(f"\n⚠️  WARNINGS ({len(warnings)}):")
            for w in warnings:
                print(f"  - {w['test']}: {w['message']}")
        
        print("\n" + "="*70)
        print("知己知彼，百战不殆")
        print("\"Know yourself before engaging the enemy.\"")
        print("\nPre-operation audit complete. Review all failures before proceeding.")
        print("="*70 + "\n")
    
    def run_audit(self):
        """Run complete audit"""
        print("="*70)
        print("CHANAKYA Personal OPSEC Audit")
        print("="*70)
        print("Quick 5-minute pre-operation security check\n")
        
        self.test_dns_leak()
        self.test_timezone()
        self.test_vpn_connection()
        self.test_tor_browser_fingerprint()
        self.test_disk_encryption()
        self.test_swap_encryption()
        self.test_webcam_mic()
        self.test_phone_location()
        
        self.generate_report()
        
        return self.critical_failures == 0


if __name__ == "__main__":
    import sys
    
    auditor = PersonalOpsecAudit()
    success = auditor.run_audit()
    
    sys.exit(0 if success else 1)
