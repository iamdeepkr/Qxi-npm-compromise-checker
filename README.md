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

# Quiet mode (only show critical findings)
python3 npm_compromise_detector.py --quiet
```

## 📊 Tool Features

### 🔍 Detection Capabilities
- ✅ **Package.json scanning** - Detects compromised versions in dependencies
- ✅ **Lock file analysis** - Scans `package-lock.json` and `yarn.lock`
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
  --quiet, -q            Only show critical findings
  --help                 Show help message
```

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
