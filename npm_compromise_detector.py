#!/usr/bin/env python3
"""
NPM Package Compromise Detection Tool
Detects compromised NPM packages from the September 2025 supply chain attack
Affects packages: debug, chalk, ansi-styles, supports-color, and many others

Author: Malware Research Team
Date: September 2025
CVE Reference: https://github.com/debug-js/debug/issues/1005
"""

import json
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import argparse
from datetime import datetime

class NPMCompromiseDetector:
    def __init__(self):
        # Compromised packages and their malicious versions
        self.compromised_packages = {
            'ansi-styles': '6.2.2',
            'debug': '4.4.2', 
            'chalk': '5.6.1',
            'supports-color': '10.2.1',
            'strip-ansi': '7.1.1',
            'ansi-regex': '6.2.1',
            'wrap-ansi': '9.0.1',
            'color-convert': '3.1.1',
            'color-name': '2.0.1',
            'is-arrayish': '0.3.3',
            'slice-ansi': '7.1.1',
            'color': '5.0.1',
            'color-string': '2.1.1',
            'simple-swizzle': '0.2.3',
            'supports-hyperlinks': '4.1.1',
            'has-ansi': '6.0.1',
            'chalk-template': '1.1.1',
            'backslash': '0.2.1'
        }
        
        # Malicious URLs and domains associated with the compromise
        self.malicious_urls = [
            'npmjs.help',  # Phishing domain used in the attack
            'support@npmjs.help',  # Phishing email
        ]
        
        # Crypto-related keywords that might indicate malicious payload
        self.crypto_indicators = [
            'cryptocurrency',
            'wallet',
            'private key',
            'mnemonic',
            'seed phrase',
            'bitcoin',
            'ethereum',
            'crypto',
            'metamask',
            'web3',
            'blockchain'
        ]
        
        self.findings = []
        self.scanned_files = []
        
    def log_finding(self, severity: str, message: str, file_path: str = None, details: Dict = None):
        """Log a security finding"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'file': file_path,
            'details': details or {}
        }
        self.findings.append(finding)
        
    def scan_package_json(self, file_path: str) -> List[Dict]:
        """Scan package.json for compromised packages"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
                
            # Check dependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in package_data:
                    for package_name, version in package_data[dep_type].items():
                        if package_name in self.compromised_packages:
                            compromised_version = self.compromised_packages[package_name]
                            # Remove version prefixes like ^, ~, >=, etc.
                            clean_version = re.sub(r'^[^\d]*', '', version)
                            
                            if clean_version == compromised_version:
                                self.log_finding(
                                    'CRITICAL',
                                    f'Compromised package detected: {package_name}@{version}',
                                    file_path,
                                    {
                                        'package': package_name,
                                        'version': version,
                                        'dependency_type': dep_type,
                                        'compromised_version': compromised_version
                                    }
                                )
                                findings.append({
                                    'package': package_name,
                                    'version': version,
                                    'type': dep_type,
                                    'file': file_path
                                })
                                
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.log_finding('ERROR', f'Failed to parse {file_path}: {str(e)}', file_path)
            
        return findings
        
    def scan_lock_file(self, file_path: str) -> List[Dict]:
        """Scan package-lock.json or yarn.lock for compromised packages"""
        findings = []
        
        try:
            if file_path.endswith('package-lock.json'):
                findings.extend(self._scan_package_lock(file_path))
            elif file_path.endswith('yarn.lock'):
                findings.extend(self._scan_yarn_lock(file_path))
                
        except Exception as e:
            self.log_finding('ERROR', f'Failed to scan lock file {file_path}: {str(e)}', file_path)
            
        return findings
        
    def _scan_package_lock(self, file_path: str) -> List[Dict]:
        """Scan package-lock.json specifically"""
        findings = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lock_data = json.load(f)
            
        # Check packages in lockfile v2/v3 format
        if 'packages' in lock_data:
            for package_path, package_info in lock_data['packages'].items():
                if package_path.startswith('node_modules/'):
                    package_name = package_path.replace('node_modules/', '').split('/')[0]
                    if package_name in self.compromised_packages:
                        version = package_info.get('version', '')
                        if version == self.compromised_packages[package_name]:
                            self.log_finding(
                                'CRITICAL',
                                f'Compromised package in lock file: {package_name}@{version}',
                                file_path,
                                {'package': package_name, 'version': version, 'path': package_path}
                            )
                            findings.append({
                                'package': package_name,
                                'version': version,
                                'file': file_path
                            })
                            
        # Check dependencies in lockfile v1 format
        if 'dependencies' in lock_data:
            findings.extend(self._scan_dependencies_recursive(lock_data['dependencies'], file_path))
            
        return findings
        
    def _scan_dependencies_recursive(self, deps: Dict, file_path: str, prefix: str = '') -> List[Dict]:
        """Recursively scan dependencies in package-lock.json"""
        findings = []
        
        for package_name, package_info in deps.items():
            if package_name in self.compromised_packages:
                version = package_info.get('version', '')
                if version == self.compromised_packages[package_name]:
                    self.log_finding(
                        'CRITICAL',
                        f'Compromised package in dependencies: {package_name}@{version}',
                        file_path,
                        {'package': package_name, 'version': version}
                    )
                    findings.append({
                        'package': package_name,
                        'version': version,
                        'file': file_path
                    })
                    
            # Recursively check nested dependencies
            if 'dependencies' in package_info:
                findings.extend(self._scan_dependencies_recursive(
                    package_info['dependencies'], file_path, f"{prefix}{package_name}/"
                ))
                
        return findings
        
    def _scan_yarn_lock(self, file_path: str) -> List[Dict]:
        """Scan yarn.lock file"""
        findings = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse yarn.lock format
        for package_name in self.compromised_packages:
            compromised_version = self.compromised_packages[package_name]
            
            # Look for package entries in yarn.lock
            pattern = rf'^{re.escape(package_name)}@.*?:\s*\n(?:\s+.*\n)*?\s+version\s+"?{re.escape(compromised_version)}"?'
            matches = re.findall(pattern, content, re.MULTILINE)
            
            if matches:
                self.log_finding(
                    'CRITICAL',
                    f'Compromised package in yarn.lock: {package_name}@{compromised_version}',
                    file_path,
                    {'package': package_name, 'version': compromised_version}
                )
                findings.append({
                    'package': package_name,
                    'version': compromised_version,
                    'file': file_path
                })
                
        return findings
        
    def scan_source_files(self, file_path: str) -> List[Dict]:
        """Scan source files for malicious URLs and crypto-related indicators"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check for malicious URLs
            for url in self.malicious_urls:
                if url in content:
                    self.log_finding(
                        'HIGH',
                        f'Malicious URL detected: {url}',
                        file_path,
                        {'url': url, 'context': self._extract_context(content, url)}
                    )
                    findings.append({
                        'type': 'malicious_url',
                        'url': url,
                        'file': file_path
                    })
                    
            # Check for crypto-related indicators (potential payload)
            crypto_matches = []
            for indicator in self.crypto_indicators:
                if indicator.lower() in content.lower():
                    crypto_matches.append(indicator)
                    
            if crypto_matches:
                self.log_finding(
                    'MEDIUM',
                    f'Crypto-related keywords detected: {", ".join(crypto_matches)}',
                    file_path,
                    {'keywords': crypto_matches}
                )
                findings.append({
                    'type': 'crypto_indicators',
                    'keywords': crypto_matches,
                    'file': file_path
                })
                
        except Exception as e:
            self.log_finding('ERROR', f'Failed to scan source file {file_path}: {str(e)}', file_path)
            
        return findings
        
    def _extract_context(self, content: str, search_term: str, context_lines: int = 2) -> str:
        """Extract context around a found term"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if search_term in line:
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                return '\n'.join(lines[start:end])
        return ''
        
    def scan_directory(self, directory: str, recursive: bool = True) -> None:
        """Scan a directory for compromised packages and malicious content"""
        directory_path = Path(directory)
        
        if not directory_path.exists():
            self.log_finding('ERROR', f'Directory does not exist: {directory}')
            return
            
        # Find package.json files
        package_files = []
        if recursive:
            package_files = list(directory_path.rglob('package.json'))
        else:
            package_files = list(directory_path.glob('package.json'))
            
        for package_file in package_files:
            self.scanned_files.append(str(package_file))
            self.scan_package_json(str(package_file))
            
        # Find lock files
        lock_files = []
        if recursive:
            lock_files.extend(directory_path.rglob('package-lock.json'))
            lock_files.extend(directory_path.rglob('yarn.lock'))
        else:
            lock_files.extend(directory_path.glob('package-lock.json'))
            lock_files.extend(directory_path.glob('yarn.lock'))
            
        for lock_file in lock_files:
            self.scanned_files.append(str(lock_file))
            self.scan_lock_file(str(lock_file))
            
        # Scan JavaScript/TypeScript files for malicious content
        source_extensions = ['*.js', '*.ts', '*.jsx', '*.tsx', '*.mjs']
        source_files = []
        
        for ext in source_extensions:
            if recursive:
                source_files.extend(directory_path.rglob(ext))
            else:
                source_files.extend(directory_path.glob(ext))
                
        for source_file in source_files[:100]:  # Limit to first 100 files for performance
            self.scanned_files.append(str(source_file))
            self.scan_source_files(str(source_file))
            
    def check_npm_cache(self) -> None:
        """Check npm cache for compromised packages"""
        try:
            result = subprocess.run(['npm', 'cache', 'ls'], capture_output=True, text=True)
            if result.returncode == 0:
                cache_content = result.stdout
                for package_name, version in self.compromised_packages.items():
                    package_pattern = f"{package_name}-{version}"
                    if package_pattern in cache_content:
                        self.log_finding(
                            'HIGH',
                            f'Compromised package found in npm cache: {package_name}@{version}',
                            details={'package': package_name, 'version': version}
                        )
        except FileNotFoundError:
            self.log_finding('WARNING', 'npm not found in PATH, skipping cache check')
        except Exception as e:
            self.log_finding('ERROR', f'Failed to check npm cache: {str(e)}')
            
    def generate_report(self, output_file: str = None) -> str:
        """Generate a comprehensive security report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("NPM PACKAGE COMPROMISE DETECTION REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Files scanned: {len(self.scanned_files)}")
        report_lines.append(f"Total findings: {len(self.findings)}")
        report_lines.append("")
        
        # Summary by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        report_lines.append("SEVERITY SUMMARY:")
        report_lines.append("-" * 20)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'WARNING', 'ERROR']:
            if severity in severity_counts:
                report_lines.append(f"{severity}: {severity_counts[severity]}")
        report_lines.append("")
        
        # Detailed findings
        if self.findings:
            report_lines.append("DETAILED FINDINGS:")
            report_lines.append("-" * 20)
            
            for i, finding in enumerate(self.findings, 1):
                report_lines.append(f"{i}. [{finding['severity']}] {finding['message']}")
                if finding['file']:
                    report_lines.append(f"   File: {finding['file']}")
                if finding['details']:
                    for key, value in finding['details'].items():
                        report_lines.append(f"   {key}: {value}")
                report_lines.append("")
        else:
            report_lines.append("✅ No compromised packages detected!")
            report_lines.append("")
            
        # Recommendations
        report_lines.append("RECOMMENDATIONS:")
        report_lines.append("-" * 20)
        
        critical_findings = [f for f in self.findings if f['severity'] == 'CRITICAL']
        if critical_findings:
            report_lines.append("🚨 IMMEDIATE ACTION REQUIRED:")
            report_lines.append("1. Remove or update all compromised packages immediately")
            report_lines.append("2. Clear npm cache: npm cache clean --force")
            report_lines.append("3. Update package-lock.json/yarn.lock files")
            report_lines.append("4. Review application logs for suspicious activity")
            report_lines.append("5. If running in browser, check for crypto wallet compromise")
            report_lines.append("")
            
        report_lines.append("SAFE VERSION OVERRIDES (add to package.json):")
        report_lines.append('  "overrides": {')
        safe_versions = {
            'chalk': '5.3.0',
            'strip-ansi': '7.1.0', 
            'color-convert': '2.0.1',
            'color-name': '1.1.4',
            'debug': '4.3.7',
            'ansi-styles': '6.2.1',
            'supports-color': '9.4.0'
        }
        for package, version in safe_versions.items():
            report_lines.append(f'    "{package}": "{version}",')
        report_lines.append('  }')
        report_lines.append("")
        
        report_lines.append("REFERENCE:")
        report_lines.append("- GitHub Issue: https://github.com/debug-js/debug/issues/1005")
        report_lines.append("- Attack Vector: Phishing email to package maintainer")
        report_lines.append("- Impact: Crypto wallet stealing in browser environments")
        report_lines.append("")
        
        report_content = '\n'.join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"Report saved to: {output_file}")
            
        return report_content


def main():
    parser = argparse.ArgumentParser(description='NPM Package Compromise Detection Tool')
    parser.add_argument('directory', nargs='?', default='.', 
                       help='Directory to scan (default: current directory)')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--no-recursive', action='store_true', 
                       help='Do not scan subdirectories')
    parser.add_argument('--check-cache', action='store_true',
                       help='Check npm cache for compromised packages')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Only show critical findings')
    
    args = parser.parse_args()
    
    detector = NPMCompromiseDetector()
    
    print("🔍 Starting NPM compromise detection scan...")
    print(f"📁 Scanning directory: {os.path.abspath(args.directory)}")
    print()
    
    # Scan directory
    detector.scan_directory(args.directory, recursive=not args.no_recursive)
    
    # Check npm cache if requested
    if args.check_cache:
        print("🗂️  Checking npm cache...")
        detector.check_npm_cache()
    
    # Generate and display report
    report = detector.generate_report(args.output)
    
    if not args.quiet:
        print(report)
    else:
        critical_findings = [f for f in detector.findings if f['severity'] == 'CRITICAL']
        if critical_findings:
            print("🚨 CRITICAL FINDINGS DETECTED!")
            for finding in critical_findings:
                print(f"  - {finding['message']}")
                if finding['file']:
                    print(f"    File: {finding['file']}")
        else:
            print("✅ No critical findings detected")
    
    # Exit with error code if critical findings
    critical_count = len([f for f in detector.findings if f['severity'] == 'CRITICAL'])
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == '__main__':
    main()
