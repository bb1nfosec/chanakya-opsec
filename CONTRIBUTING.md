# Contributing to CHANAKYA

## Git Workflow Guide

This document provides a detailed, reader-friendly guide for contributing to the CHANAKYA OPSEC framework.

---

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Development Workflow](#development-workflow)
3. [Committing Changes](#committing-changes)
4. [Pull Request Guidelines](#pull-request-guidelines)
5. [Documentation Standards](#documentation-standards)
6. [Testing Requirements](#testing-requirements)

---

## Initial Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# https://github.com/bb1nfosec/chanakya-opsec/fork

# Clone your fork
git clone https://github.com/YOUR_USERNAME/chanakya-opsec.git
cd chanakya-opsec

# Add upstream remote
git remote add upstream https://github.com/bb1nfosec/chanakya-opsec.git

# Verify remotes
git remote -v
# origin    https://github.com/YOUR_USERNAME/chanakya-opsec.git (fetch)
# origin    https://github.com/YOUR_USERNAME/chanakya-opsec.git (push)
# upstream  https://github.com/bb1nfosec/chanakya-opsec.git (fetch)
# upstream  https://github.com/bb1nfosec/chanakya-opsec.git (push)
```

### 2. Keep Your Fork Updated

```bash
# Fetch latest changes from upstream
git fetch upstream

# Merge upstream main into your main
git checkout main
git merge upstream/main

# Push to your fork
git push origin main
```

---

## Development Workflow

### Branch Naming Convention

```
feature/layer-name-enhancement    # New layer or major feature
fix/issue-description             # Bug fixes
docs/documentation-update         # Documentation improvements
research/topic-investigation      # Research additions
```

### Create Feature Branch

```bash
# Start from updated main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/dns-passive-analysis

# Work on your changes
# Edit files, test, document...

# Track your progress
git status
git diff
```

---

## Committing Changes

### Commit Message Format

```
Type: Brief summary (50 chars max)

Detailed description:
- What was added/changed/fixed
- Why the change was necessary
- Any breaking changes or important notes

Related: #issue_number (if applicable)
```

### Commit Types

```
Enhancement: New OPSEC layer or significant feature
Fix: Bug fixes or correction
Docs: Documentation updates
Research: New research integration
Refactor: Code restructuring without behavior change
Test: Adding or updating tests
```

### Example Commits

```bash
# Good commit message
git commit -m "Enhancement: Add SIGINT cellular tracking analysis

- Implemented IMSI catcher detection algorithms
- Added SS7 vulnerability documentation
- Integrated baseband isolation techniques
- Includes quantitative risk scores (V×R×C formula)

This addresses the gap in telecommunications OPSEC analysis."

# Stage specific files
git add docs/sigint-attribution-vectors.md
git add framework/sigint/cellular_analyzer.py
git commit -m "Enhancement: SIGINT cellular tracking layer"

# Amend last commit (if needed before push)
git commit --amend
```

---

## Pull Request Guidelines

### Before Submitting PR

```bash
# 1. Ensure all tests pass
python -m pytest tests/

# 2. Update documentation
# - README.md (if adding new layer)
# - Layer-specific docs
# - Code comments

# 3. Rebase on latest upstream
git fetch upstream
git rebase upstream/main

# 4. Push to your fork
git push origin feature/your-branch-name
```

### PR Template

```markdown
## Summary
Brief description of changes

## Motivation
Why is this enhancement needed?

## Changes
- [ ] Added new OPSEC layer: [Layer Name]
- [ ] Updated framework components
- [ ] Added documentation
- [ ] Added tests
- [ ] Updated README

## Testing
How were changes tested?

## References
- Research papers / Blog posts / GitHub repos
- Related issues: #123

## Checklist
- [ ] Code follows project style
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] Commit messages are clear
- [ ] No sensitive information exposed
```

### PR Review Process

1. **Automated Checks:** CI/CD runs tests
2. **Code Review:** Maintainers review for:
   - Technical accuracy
   - Documentation quality
   - Test coverage
   - Alignment with framework philosophy
3. **Feedback:** Address review comments
4. **Approval:** Merged after approval

---

## Documentation Standards

### Markdown Style

```markdown
# Title (H1) - Document title only

## Section (H2) - Major sections

### Subsection (H3) - Sub-topics

**Bold** for emphasis
*Italic* for foreign terms or variables
`code` for technical terms, commands, file paths

- Bullet lists for items
1. Numbered lists for procedures

> Quote blocks for important notes
```

### Code Examples

````markdown
```python
# Always include comments
def analyze_signal(data):
    """
    Analyzes OPSEC signal for attribution risk.
    
    Args:
        data: Signal metadata
        
    Returns:
        Attribution weight (0.0-1.0)
    """
    return calculate_attribution_weight(data)
```

```bash
# Shell commands with comments
# Install dependencies
pip install -r requirements.txt

# Run analyzer
python framework/dns/analyzer.py
```
````

### Attribution Weight Format

```markdown
**Attribution Weight**: V=0.9, R=0.8, C=0.85 → **AW=0.61 (HIGH)**

Where:
- V = Visibility (0.0-1.0)
- R = Retention (0.0-1.0)
- C = Correlation Potential (0.0-1.0)
- AW = V × R × C
```

---

## Testing Requirements

### Test Categories

1. **Unit Tests:** Individual component testing
2. **Integration Tests:** Multi-layer correlation
3. **Simulation Tests:** End-to-end scenarios
4. **Documentation Tests:** Code examples work

### Running Tests

```bash
# All tests
pytest

# Specific layer
pytest tests/test_dns_layer.py

# With coverage
pytest --cov=framework tests/

# Verbose output
pytest -v
```

### Writing Tests

```python
# tests/test_dns_layer.py
import pytest
from framework.dns.analyzer import DNSAnalyzer

class TestDNSAnalyzer:
    def setup_method(self):
        self.analyzer = DNSAnalyzer()
    
    def test_sinkhole_detection(self):
        """Test DNS sinkhole detection"""
        query = {
            'domain': 'malicious.com',
            'resolver': '8.8.8.8',
            'response_ip': '0.0.0.0'
        }
        
        result = self.analyzer.detect_sinkhole(query)
        
        assert result['sinkhole_detected'] == True
        assert result['attribution_weight'] > 0.8
    
    def test_attribution_weight_calculation(self):
        """Test V×R×C formula"""
        signal = {
            'visibility': 0.9,
            'retention': 0.8,
            'correlation': 0.7
        }
        
        aw = self.analyzer.calculate_attribution_weight(signal)
        
        assert aw == pytest.approx(0.504, 0.01)
        assert self.analyzer.risk_level(aw) == "HIGH"
```

---

## Layer Enhancement Checklist

When adding a new OPSEC layer:

```markdown
- [ ] **Documentation** (`docs/layer-name.md`)
  - [ ] Overview & threat model
  - [ ] Attack vectors with examples
  - [ ] Quantitative analysis (V×R×C scores)
  - [ ] Cross-INT correlations
  - [ ] Defensive techniques
  - [ ] References & resources

- [ ] **Framework Module** (`framework/layer/analyzer.py`)
  - [ ] Analyzer class extending OpsecAnalyzer
  - [ ] Signal detection methods
  - [ ] Attribution weight calculation
  - [ ] Cross-layer correlation hooks

- [ ] **Tests** (`tests/test_layer.py`)
  - [ ] Unit tests for each analyzer method
  - [ ] Integration tests with other layers
  - [ ] Edge cases and error handling

- [ ] **Examples** (`examples/layer_audit.py`)
  - [ ] Practical usage demonstration
  - [ ] Real-world scenario
  - [ ] Output interpretation

- [ ] **README Update**
  - [ ] Add layer to structure diagram
  - [ ] Update layer count
  - [ ] Add to quick start guide

- [ ] **Simulations** (if applicable)
  - [ ] Failure scenario demonstration
  - [ ] Attribution chain example
```

---

## Contribution Ideas

### High-Priority Areas

1. **Physical Security Layer**
   - Biometric leaks
   - Video surveillance correlation
   - Travel pattern analysis

2. **Social Engineering Layer**
   - Psychological profiling
   - Linguistic analysis
   - Pretext failure modes

3. **Hardware Implant Detection**
   - RF spectrum analysis scripts
   - PCB imaging comparison
   - Firmware integrity checking

4. **Cryptocurrency Privacy**
   - Chain analysis scripts
   - Mixer effectiveness testing
   - Monero ring signature analysis

5. **AI/ML Enhancements**
   - Behavioral clustering algorithms
   - Graph ML infrastructure correlation
   - LLM-based linguistic fingerprinting

---

## Code Style Guidelines

### Python

```python
# PEP 8 compliance
# - 4 spaces for indentation
# - Max line length: 100 characters
# - Docstrings for all public methods

class DNSAnalyzer(OpsecAnalyzer):
    """Analyzes DNS OPSEC failures and attribution risks."""
    
    def detect_sinkhole(self, query_data: dict) -> dict:
        """
        Detect DNS sinkhole responses.
        
        Args:
            query_data: Dictionary containing query metadata
            
        Returns:
            Detection result with attribution weight
        """
        # Implementation
        pass
```

### Shell Scripts

```bash
#!/usr/bin/env bash
# Script description

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.conf"

# Functions
main() {
    # Main logic
    echo "Processing..."
}

# Execute
main "$@"
```

---

## Quick Reference

### Common Commands

```bash
# Update your fork
git fetch upstream && git merge upstream/main

# Create feature branch
git checkout -b feature/my-enhancement

# Check what changed
git status
git diff

# Stage and commit
git add docs/new-layer.md
git commit -m "Enhancement: Add new layer documentation"

# Push to your fork
git push origin feature/my-enhancement

# Run tests
pytest

# Check code style
flake8 framework/
```

### Getting Help

- **Issues:** https://github.com/bb1nfosec/chanakya-opsec/issues
- **Discussions:** https://github.com/bb1nfosec/chanakya-opsec/discussions
- **Security:** See SECURITY.md for responsible disclosure

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

*知己知彼，百战不殆*

"Contribute with precision. Collaborate with care."

**Thank you for improving CHANAKYA!**
