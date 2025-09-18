# NPM Package Compromise Detection Tool

🚨 **CRITICAL SECURITY ALERT** 🚨

This tool detects compromised NPM packages from the **September 2025 supply chain attack** that affected numerous popular packages including `debug`, `chalk`, `ansi-styles`, and many others.

## 📋 Overview

On September 8, 2025, a sophisticated phishing attack compromised the NPM account of a major package maintainer (Qix-), leading to malicious versions being published for 18+ popular packages with **billions of weekly downloads**.

### 🎯 Attack Details
- **Attack Vector**: Sophisticated phishing email mimicking NPM 2FA reset
- **Target**: Browser-based applications handling cryptocurrency
- **Payload**: Crypto wallet stealing malware
- **Scope**: 18+ packages, 300+ million weekly downloads combined
- **Reference**: [GitHub Issue #1005](https://github.com/debug-js/debug/issues/1005)

## 🔍 Affected Packages

| Package | Compromised Version | Weekly Downloads |
|---------|-------------------|------------------|
| `ansi-styles` | 6.2.2 | 371.41M |
| `debug` | 4.4.2 | 357.6M |
| `chalk` | 5.6.1 | 299.99M |
| `supports-color` | 10.2.1 | 287.1M |
| `strip-ansi` | 7.1.1 | 261.17M |
| `ansi-regex` | 6.2.1 | 243.64M |
| `wrap-ansi` | 9.0.1 | 197.99M |
| `color-convert` | 3.1.1 | 193.5M |
| `color-name` | 2.0.1 | 191.71M |
| `is-arrayish` | 0.3.3 | 73.8M |
| `slice-ansi` | 7.1.1 | 59.8M |
| `color` | 5.0.1 | - |
| `color-string` | 2.1.1 | 27.48M |
| `simple-swizzle` | 0.2.3 | 26.26M |
| `supports-hyperlinks` | 4.1.1 | 19.2M |
| `has-ansi` | 6.0.1 | 12.1M |
| `chalk-template` | 1.1.1 | 3.9M |
| `backslash` | 0.2.1 | 0.26M |

## 🚀 Quick Usage

### Option 1: Shell Script (Fast)
```bash
# Scan current directory
./quick_check.sh

# Scan specific directory
./quick_check.sh /path/to/your/project
```

### Option 2: Python Tool (Comprehensive)
```bash
# Install Python 3.7+ first, then:

# Scan current directory
python3 npm_compromise_detector.py

# Scan specific directory with full options
python3 npm_compromise_detector.py /path/to/project --output report.txt --check-cache

# Enable FULL dependency tree analysis (slower but comprehensive)
python3 npm_compromise_detector.py /path/to/project --full-tree --output full-tree-report.txt

# Quiet mode (only show critical findings)
python3 npm_compromise_detector.py --quiet
```

## ⚡ Quick Command Guide

### 🔍 **Essential Security Scans**
```bash
# Basic scan with report
python3 npm_compromise_detector.py '/Users/username/Documents/my-project' --output security-report.txt

# Comprehensive security audit (recommended for production)
python3 npm_compromise_detector.py '/Users/username/Documents/my-frontend-app' --output audit-report.txt --check-cache --full-tree --show-locations

# Quick check with detailed locations
python3 npm_compromise_detector.py '/Users/username/Documents/my-react-app' --show-locations

# Development workflow scan
python3 npm_compromise_detector.py '/Users/username/Documents/my-project' --full-tree --list-packages
```

### 🎯 **Real-World Examples**
```bash
# Frontend project security audit
python3 npm_compromise_detector.py '/Users/username/Documents/GitHub/my-frontend' --output frontend-security.txt --check-cache --full-tree --show-locations

# Backend API security check
python3 npm_compromise_detector.py '/Users/username/Documents/GitHub/my-api' --output api-security.txt --full-tree

# Multiple project comparison
python3 npm_compromise_detector.py '/Users/username/Documents/project-a' --output project-a-scan.txt --full-tree
python3 npm_compromise_detector.py '/Users/username/Documents/project-b' --output project-b-scan.txt --full-tree

# CI/CD integration (quiet mode)
python3 npm_compromise_detector.py '/Users/username/Documents/GitHub/production-app' --quiet --output ci-scan.txt
```

### 📊 **Specialized Scans**
```bash
# Package inventory audit
python3 npm_compromise_detector.py '/Users/username/Documents/my-app' --list-packages --output package-inventory.txt

# Cache vulnerability check
python3 npm_compromise_detector.py '/Users/username/Documents/my-project' --check-cache --output cache-scan.txt

# Location-focused investigation
python3 npm_compromise_detector.py '/Users/username/Documents/suspicious-project' --show-locations --output investigation.txt
```

### 🚀 **Production-Ready Commands**
```bash
# Complete security assessment
python3 npm_compromise_detector.py '/Users/username/Documents/GitHub/production-frontend' --output complete-audit.txt --check-cache --full-tree --list-packages --show-locations

# Fast security check for daily use
python3 npm_compromise_detector.py '/Users/username/Documents/current-project' --show-locations

# Enterprise audit with all features
python3 npm_compromise_detector.py '/Users/username/Documents/enterprise-app' --output enterprise-security-audit.txt --full-tree --show-locations --check-cache
```

## 📊 Tool Features

### 🔍 Detection Capabilities
- ✅ **Package.json scanning** - Detects compromised versions in dependencies
- ✅ **Lock file analysis** - Scans `package-lock.json` and `yarn.lock`
- 🆕 **Full dependency tree analysis** - Uses `npm list` and `yarn list` for complete transitive dependency scanning
- 🆕 **Safe version detection** - Identifies packages using safe versions of potentially vulnerable packages
- ✅ **NPM cache checking** - Identifies cached malicious packages
- ✅ **Source code scanning** - Detects malicious URLs and crypto-related indicators
- ✅ **Recursive directory scanning** - Scans entire project trees
- ✅ **Comprehensive reporting** - Detailed findings with severity levels

### 📈 Output Formats
- **Console output** with color-coded severity levels
- **Detailed reports** with timestamps and context
- **JSON-compatible findings** for integration with CI/CD
- **Actionable recommendations** for remediation

## ⚡ Command Line Options

```bash
# Python tool options
python3 npm_compromise_detector.py [directory] [options]

Options:
  directory              Directory to scan (default: current)
  --output, -o FILE      Save report to file
  --no-recursive         Don't scan subdirectories
  --check-cache          Check npm cache for compromised packages
  --full-tree            Enable full dependency tree analysis (slower but comprehensive)
  --list-packages        Include detailed list of all scanned packages in report
  --show-locations       Show detailed location information for all findings
  --quiet, -q            Only show critical findings
  --help                 Show help message
```

## 🌳 Dependency Analysis Modes

### Standard Mode (Default)
- ✅ Scans **direct dependencies** in `package.json` files
- ✅ Scans **complete dependency tree** in lock files (`package-lock.json`, `yarn.lock`)
- ⚡ **Fast** - Good for most use cases

### Full Tree Mode (`--full-tree`)
- ✅ Everything from Standard Mode +
- 🆕 **Live dependency resolution** using `npm list` and `yarn list`
- 🆕 **Finds transitive dependencies** even without lock files
- 🆕 **Detects compromised packages** at any depth in the dependency tree
- 🐌 **Slower** - Requires npm/yarn to resolve dependencies
- 🎯 **Most comprehensive** - Recommended for security audits

### When to Use Full Tree Mode
- 🔍 **Security audits** - When you need complete coverage
- 📦 **Projects without lock files** - When only `package.json` exists
- 🕵️ **Deep dependency analysis** - To find hidden compromised packages
- 🚨 **Critical environments** - When security is paramount

## 🛡️ Safe Version Detection

The tool now automatically detects when you're using **safe versions** of potentially vulnerable packages:

### 📊 What Gets Reported
- ✅ **Compromised versions** - Packages using exact malicious versions (CRITICAL)
- ✅ **Safe versions** - Packages using non-compromised versions of vulnerable packages (INFO)
- 📈 **Statistics** - Count of safe vs compromised packages found
- 📋 **Summary** - Grouped overview of all safe versions detected

### 🔍 Example Output
```
✅ chalk
   Safe versions found: 4.0.0, 5.3.0
   Compromised version: 5.6.1
   Found in 15 location(s)

✅ debug  
   Safe versions found: 4.3.4, 4.1.1
   Compromised version: 4.4.2
   Found in 8 location(s)
```

This helps you understand your security posture and identify packages that could become vulnerable if updated to specific versions.

## 📍 Enhanced Location Reporting

Get detailed information about **where packages are found** in your project:

### 🔍 Location Details Include:
- 📁 **Full file paths** - Exact location of each package
- 🔗 **Dependency depth** - How deep in the dependency tree
- 🏷️ **Source type** - Direct, transitive, or lock file dependency
- 📂 **Package path** - Location within node_modules structure

### 💡 Usage Examples:
```bash
# Show detailed locations for all findings
python3 npm_compromise_detector.py --show-locations

# Comprehensive report with all package details
python3 npm_compromise_detector.py --list-packages --show-locations --output detailed-report.txt

# Focus on specific project with enhanced locations
python3 npm_compromise_detector.py /path/to/project --show-locations
```

### 📊 Enhanced Output Format:
```
✅ chalk
   Safe versions found: 4.0.0, 5.3.0
   Compromised version: 5.6.1
   Found in 15 location(s):
     v4.0.0 (12 locations):
       - 📁 .../node_modules/jest-util/package.json [safe_dependencies]
         Full path: test_demo/node_modules/jest-util/package.json
       - 📁 .../node_modules/jest-config/package.json [safe_dependencies]
         Full path: test_demo/node_modules/jest-config/package.json
       ... and 10 more location(s)
     v5.3.0 (3 locations):
       - 📁 package.json [safe_dependencies]
       - 📁 package-lock.json [safe_lock_file_v2_v3]
```

## 🐛 Recent Fixes

### ✅ **False Positive Fix** (v1.1)
**Issue**: The shell script (`quick_check.sh`) was producing false positives when checking `package-lock.json` files.

**Problem**: The original grep pattern `grep -A 5 -B 5 "\"$package\""` would match package names in `requires` sections and then incorrectly flag legitimate versions as compromised.

**Example False Positive**:
```json
"ansi-styles": {
  "requires": {
    "color-convert": "^2.0.1"  // This 2.0.1 was incorrectly flagged
  }
},
"color-convert": {
  "version": "2.0.1"  // Safe version, but script flagged as compromised 3.1.1
}
```

**Solution**: Updated to more precise patterns:
- **package-lock.json**: `grep -A 10 "\"$package\": {" OR "\"node_modules/$package\": {"` - Only matches actual package declarations
- **yarn.lock**: `grep -A 10 "^$package@" "$file" | grep -q "^  version \""` - Only matches actual version lines

**Validation**: ✅ Tested with `color-convert@2.0.1` (safe) vs `color-convert@3.1.1` (compromised)
- **Before**: Would incorrectly flag safe version 2.0.1 as compromised
- **After**: Correctly identifies only actual compromised versions

**Result**: ✅ Eliminates false positives while maintaining accurate detection of actual compromised packages.

## 🛠️ Installation & Setup

### Prerequisites
- **Python 3.7+** (for comprehensive tool)
- **Bash** (for quick check script)
- **NPM** (optional, for cache checking)

### Quick Setup
```bash
# Clone or download the tools
git clone <this-repo>
cd npm-crypto-stealer-detector

# Make shell script executable
chmod +x quick_check.sh

# Run quick check
./quick_check.sh

# Or run comprehensive scan
python3 npm_compromise_detector.py
```

## 🚨 If Compromised Packages Are Found

### ⚠️ IMMEDIATE ACTIONS REQUIRED:

1. **🛑 Stop Applications**
   ```bash
   # Stop all running Node.js applications
   pkill -f node
   ```

2. **🧹 Clear NPM Cache**
   ```bash
   npm cache clean --force
   # or
   yarn cache clean
   ```

3. **📦 Update Packages**
   Add to your `package.json`:
   ```json
   {
     "overrides": {
       "chalk": "5.3.0",
       "strip-ansi": "7.1.0",
       "color-convert": "2.0.1",
       "color-name": "1.1.4",
       "debug": "4.3.7",
       "ansi-styles": "6.2.1",
       "supports-color": "9.4.0"
     }
   }
   ```

4. **🔄 Reinstall Dependencies**
   ```bash
   rm -rf node_modules package-lock.json
   npm install
   # or
   rm -rf node_modules yarn.lock
   yarn install
   ```

5. **🔍 Security Audit**
   ```bash
   npm audit
   # Review logs for suspicious activity
   ```

6. **💰 Check Crypto Wallets**
   - If this was a browser-based application
   - Check all connected crypto wallets
   - Consider moving funds to new wallets
   - Review recent transactions

## 🔬 Technical Details

### Malware Analysis
- **Target Environment**: Browser (requires `window` object)
- **Payload Type**: Cryptocurrency wallet stealer
- **Activation**: Targets web3/crypto-related applications
- **Node.js Impact**: Limited (payload designed for browser)

### IOCs (Indicators of Compromise)
- **Malicious Domain**: `npmjs.help` (phishing domain)
- **Email**: `support@npmjs.help`
- **Package Versions**: See table above
- **File Indicators**: Crypto-related keywords in unexpected contexts

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: NPM Compromise Check
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Check for compromised packages
        run: |
          curl -O https://raw.githubusercontent.com/[repo]/quick_check.sh
          chmod +x quick_check.sh
          ./quick_check.sh
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('NPM Security Check') {
            steps {
                sh 'python3 npm_compromise_detector.py --quiet'
            }
        }
    }
}
```

## 📚 Additional Resources

- **GitHub Issue**: https://github.com/debug-js/debug/issues/1005
- **NPM Advisory**: [Check NPM security advisories]
- **MITRE ATT&CK**: Supply Chain Compromise (T1195.002)

## 🤝 Contributing

This is a critical security tool. Contributions welcome:

1. **Bug Reports**: Open issues for false positives/negatives
2. **New IOCs**: Submit additional indicators of compromise
3. **Tool Improvements**: Enhance detection capabilities
4. **Documentation**: Improve usage instructions

## ⚖️ License

This tool is provided under MIT License for emergency security response.

## 🆘 Support

For urgent security issues:
- Open a GitHub issue
- Contact your security team
- Report to NPM security team

---

**⚠️ This is an active security incident. Stay vigilant and keep your dependencies updated!**
