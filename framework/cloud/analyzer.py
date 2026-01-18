"""
Cloud & DevSecOps OPSEC Analyzer
Detects cloud metadata leakage, IAM misconfigurations, and CI/CD attribution vectors
"""

import json
import re
from datetime import datetime

class CloudOpsecAnalyzer:
    """Analyzes cloud-specific OPSEC failures"""
    
    def __init__(self):
        self.signals = []
    
    def analyze_aws_metadata_exposure(self, metadata_response):
        """
        Analyze AWS IMDS exposure risk
        
        Args:
            metadata_response: dict from IMDS query
        
        Returns:
            dict with attribution analysis
        """
        risk_signals = []
        
        # Check for IAM credential exposure
        if 'iam' in metadata_response:
            risk_signals.append('IAM credentials exposed via IMDS')
            aw_base = 0.90
        else:
            aw_base = 0.50
        
        # Check metadata version
        if metadata_response.get('imds_version') == 'v1':
            risk_signals.append('Using IMDSv1 (SSRF vulnerable)')
            aw_base += 0.05
        
        # Extract attribution vectors
        attribution_vectors = {
            'instance_id': metadata_response.get('instance-id'),
            'ami_id': metadata_response.get('ami-id'),
            'availability_zone': metadata_response.get('placement', {}).get('availability-zone'),
            'public_ip': metadata_response.get('public-ipv4')
        }
        
        return {
            'risk_signals': risk_signals,
            'attribution_vectors': attribution_vectors,
            'visibility': 1.0,
            'retention': 0.9,
            'correlation': 1.0,
            'attribution_weight': min(aw_base, 1.0),
            'risk': 'CRITICAL' if aw_base >= 0.8 else 'HIGH',
            'mitigation': 'Enforce IMDSv2, minimize IAM role permissions'
        }
    
    def analyze_cloudtrail_log(self, cloudtrail_event):
        """
        Analyze CloudTrail event for attribution vectors
        
        Args:
            cloudtrail_event: dict from CloudTrail log
        
        Returns:
            dict with attribution analysis
        """
        attribution = {}
        
        # Extract user identity
        user_identity = cloudtrail_event.get('userIdentity', {})
        attribution['principal_id'] = user_identity.get('principalId')
        attribution['user_name'] = user_identity.get('userName')
        attribution['account_id'] = user_identity.get('accountId')
        
        # Extract source IP
        attribution['source_ip'] = cloudtrail_event.get('sourceIPAddress')
        
        # Extract user agent (reveals tool/OS)
        user_agent = cloudtrail_event.get('userAgent', '')
        attribution['user_agent'] = user_agent
        
        # Parse user agent for details
        if 'aws-cli' in user_agent:
            match = re.search(r'aws-cli/([0-9.]+)\s+Python/([0-9.]+)\s+(\w+)', user_agent)
            if match:
                attribution['cli_version'] = match.group(1)
                attribution['python_version'] = match.group(2)
                attribution['os'] = match.group(3)
        
        # Calculate attribution weight
        aw = 1.0 * 1.0 * 0.95  # V=1.0 (logged), R=1.0 (permanent), C=0.95 (high)
        
        return {
            'attribution_vectors': attribution,
            'attribution_weight': aw,
            'risk': 'CRITICAL',
            'note': 'CloudTrail provides full audit trail with identity, IP, tool'
        }
    
    def analyze_docker_image_layers(self, image_history):
        """
        Analyze Docker image layers for attribution
        
        Args:
            image_history: list of layer metadata
        
        Returns:
            dict with attribution analysis
        """
        attribution_vectors = []
        
        for layer in image_history:
            created_by = layer.get('created_by', '')
            
            # Check for username in paths
            if '/home/' in created_by:
                username_match = re.search(r'/home/([^/]+)/', created_by)
                if username_match:
                    attribution_vectors.append({
                        'type': 'username',
                        'value': username_match.group(1),
                        'layer': layer.get('id')
                    })
            
            # Check for email addresses
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', created_by)
            if email_match:
                attribution_vectors.append({
                    'type': 'email',
                    'value': email_match.group(0),
                    'layer': layer.get('id')
                })
            
            # Check for hardcoded secrets
            if 'ENV' in created_by and ('KEY' in created_by or 'SECRET' in created_by or 'TOKEN' in created_by):
                attribution_vectors.append({
                    'type': 'hardcoded_secret',
                    'value': 'Potential secret in ENV',
                    'layer': layer.get('id')
                })
        
        # Calculate attribution weight
        if len(attribution_vectors) >= 3:
            aw = 0.80
            risk = 'HIGH'
        elif len(attribution_vectors) >= 1:
            aw = 0.60
            risk = 'MEDIUM'
        else:
            aw = 0.30
            risk = 'LOW'
        
        return {
            'attribution_vectors': attribution_vectors,
            'total_vectors': len(attribution_vectors),
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Use multi-stage builds, avoid hardcoding secrets, sanitize paths'
        }
    
    def analyze_git_commit_metadata(self, commit_data):
        """
        Analyze Git commit for attribution vectors
        
        Args:
            commit_data: dict with commit metadata
        
        Returns:
            dict with attribution analysis
        """
        attribution = {
            'author_name': commit_data.get('author_name'),
            'author_email': commit_data.get('author_email'),
            'committer_name': commit_data.get('committer_name'),
            'committer_email': commit_data.get('committer_email'),
            'commit_timestamp': commit_data.get('timestamp'),
            'timezone': commit_data.get('timezone')
        }
        
        # Infer timezone location
        tz_offset = commit_data.get('timezone', '+0000')
        timezone_mapping = {
            '+0000': 'UTC (UK, Portugal)',
            '+0100': 'CET (Western Europe)',
            '+0800': 'CST (China, Singapore, Australia West)',
            '+0530': 'IST (India)',
            '-0500': 'EST (US East Coast)',
            '-0800': 'PST (US West Coast)'
        }
        
        likely_location = timezone_mapping.get(tz_offset, 'Unknown')
        
        # Calculate attribution weight
        aw = 1.0 * 1.0 * 0.90  # V=1.0 (public repo), R=1.0 (git history permanent), C=0.90
        
        return {
            'attribution_vectors': attribution,
            'likely_location': likely_location,
            'attribution_weight': aw,
            'risk': 'CRITICAL',
            'mitigation': 'Use anonymous git config, randomize timezone, commit via GitHub web UI'
        }
    
    def calculate_cloud_opsec_score(self, metrics):
        """
        Calculate overall Cloud OPSEC score
        
        Formula: IAM_Hygiene × Metadata_Protection × Logging_Minimization × Secret_Management
        """
        iam = metrics.get('iam_hygiene', 0.5)
        metadata = metrics.get('metadata_protection', 0.5)
        logging = metrics.get('logging_minimization', 0.5)
        secrets = metrics.get('secret_management', 0.5)
        
        score = iam * metadata * logging * secrets
        
        if score > 0.6:
            classification = 'Strong'
            risk = 'LOW'
        elif score > 0.3:
            classification = 'Moderate'
            risk = 'MEDIUM'
        else:
            classification = 'Weak'
            risk = 'HIGH'
        
        return {
            'cloud_opsec_score': score,
            'classification': classification,
            'risk': risk,
            'components': {
                'iam_hygiene': iam,
                'metadata_protection': metadata,
                'logging_minimization': logging,
                'secret_management': secrets
            },
            'recommendations': self._generate_recommendations(metrics)
        }
    
    def _generate_recommendations(self, metrics):
        """Generate specific recommendations based on metrics"""
        recs = []
        
        if metrics.get('iam_hygiene', 1.0) < 0.7:
            recs.append('Enable MFA for all IAM users')
            recs.append('Use IAM roles instead of users')
            recs.append('Implement least privilege access')
        
        if metrics.get('metadata_protection', 1.0) < 0.7:
            recs.append('Enforce IMDSv2 on EC2 instances')
            recs.append('Disable public IPs where possible')
            recs.append('Use VPC endpoints for AWS services')
        
        if metrics.get('logging_minimization', 1.0) < 0.7:
            recs.append('Consider disabling non-essential logging (legal review)')
            recs.append('Implement log retention policies (shortest legally acceptable)')
        
        if metrics.get('secret_management', 1.0) < 0.7:
            recs.append('Use AWS Secrets Manager/Azure Key Vault')
            recs.append('Never hardcode secrets in code/images')
            recs.append('Rotate secrets regularly (90 days)')
        
        return recs
