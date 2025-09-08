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
import tempfile
import shutil

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
        self.scanned_packages = []  # Track all packages found during scanning
        self.package_sources = {}   # Track where each package was found
        self.safe_packages = []     # Track packages that are safe versions of potentially compromised packages
        self.dependency_stats = {   # Track dependency analysis statistics
            'direct_dependencies': 0,
            'transitive_dependencies': 0,
            'lock_file_packages': 0,
            'tree_resolved_packages': 0,
            'safe_packages_found': 0,
            'compromised_packages_found': 0
        }
        self.full_tree_analysis = False
        
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
        
    def enable_full_tree_analysis(self, enable: bool = True):
        """Enable or disable full dependency tree analysis"""
        self.full_tree_analysis = enable
        
    def track_package(self, package_name: str, version: str, source: str, file_path: str = None, depth: int = 0):
        """Track a scanned package for reporting purposes"""
        package_key = f"{package_name}@{version}"
        
        # Add to scanned packages list if not already present
        if package_key not in [p['key'] for p in self.scanned_packages]:
            package_info = {
                'key': package_key,
                'name': package_name,
                'version': version,
                'source': source,
                'file_path': file_path,
                'depth': depth,
                'first_seen': datetime.now().isoformat()
            }
            self.scanned_packages.append(package_info)
            
        # Track source information
        if package_key not in self.package_sources:
            self.package_sources[package_key] = []
        
        source_info = {
            'source': source,
            'file_path': file_path,
            'depth': depth
        }
        
        # Avoid duplicate source entries
        if source_info not in self.package_sources[package_key]:
            self.package_sources[package_key].append(source_info)
            
    def track_safe_package(self, package_name: str, version: str, compromised_version: str, source: str, file_path: str = None, depth: int = 0):
        """Track a package that is a safe version of a potentially compromised package"""
        safe_package_info = {
            'name': package_name,
            'version': version,
            'compromised_version': compromised_version,
            'source': source,
            'file_path': file_path,
            'depth': depth,
            'found_at': datetime.now().isoformat()
        }
        
        # Check if we already have this exact safe package entry
        existing = any(
            p['name'] == package_name and 
            p['version'] == version and 
            p['file_path'] == file_path and
            p['source'] == source
            for p in self.safe_packages
        )
        
        if not existing:
            self.safe_packages.append(safe_package_info)
            self.dependency_stats['safe_packages_found'] += 1
        
    def get_npm_dependency_tree(self, package_json_dir: str) -> Dict:
        """Get full dependency tree using npm list"""
        try:
            # Change to the directory containing package.json
            original_cwd = os.getcwd()
            os.chdir(package_json_dir)
            
            # Run npm list to get full dependency tree
            result = subprocess.run(
                ['npm', 'list', '--json', '--all', '--prod'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            os.chdir(original_cwd)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                # Try without --prod flag in case of issues
                os.chdir(package_json_dir)
                result = subprocess.run(
                    ['npm', 'list', '--json', '--all'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                os.chdir(original_cwd)
                
                if result.returncode == 0:
                    return json.loads(result.stdout)
                    
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            self.log_finding('WARNING', f'Failed to get npm dependency tree: {str(e)}', package_json_dir)
        except Exception as e:
            os.chdir(original_cwd)
            self.log_finding('WARNING', f'Error getting npm dependency tree: {str(e)}', package_json_dir)
            
        return {}
        
    def get_yarn_dependency_tree(self, package_json_dir: str) -> Dict:
        """Get full dependency tree using yarn list"""
        try:
            # Change to the directory containing package.json
            original_cwd = os.getcwd()
            os.chdir(package_json_dir)
            
            # Run yarn list to get full dependency tree
            result = subprocess.run(
                ['yarn', 'list', '--json', '--production'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            os.chdir(original_cwd)
            
            if result.returncode == 0:
                # Parse yarn's line-delimited JSON output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    try:
                        data = json.loads(line)
                        if data.get('type') == 'tree':
                            return {'dependencies': self._parse_yarn_tree(data.get('data', {}).get('trees', []))}
                    except json.JSONDecodeError:
                        continue
                        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.log_finding('WARNING', f'Failed to get yarn dependency tree: {str(e)}', package_json_dir)
        except Exception as e:
            os.chdir(original_cwd)
            self.log_finding('WARNING', f'Error getting yarn dependency tree: {str(e)}', package_json_dir)
            
        return {}
        
    def _parse_yarn_tree(self, trees: List) -> Dict:
        """Parse yarn tree structure into npm-like format"""
        dependencies = {}
        
        for tree in trees:
            name = tree.get('name', '')
            if '@' in name:
                # Parse package@version format
                parts = name.rsplit('@', 1)
                if len(parts) == 2:
                    package_name = parts[0]
                    version = parts[1]
                    dependencies[package_name] = {
                        'version': version,
                        'dependencies': self._parse_yarn_tree(tree.get('children', []))
                    }
                    
        return dependencies
        
    def scan_dependency_tree_recursive(self, deps: Dict, file_path: str, depth: int = 0) -> List[Dict]:
        """Recursively scan dependency tree for compromised packages"""
        findings = []
        
        if depth > 50:  # Prevent infinite recursion
            return findings
            
        for package_name, package_info in deps.items():
            version = package_info.get('version', '')
            
            # Track all packages found in dependency tree
            if version:
                source_type = 'transitive_dependency' if depth > 0 else 'tree_resolved_dependency'
                self.track_package(package_name, version, source_type, file_path, depth)
                
                if depth > 0:
                    self.dependency_stats['transitive_dependencies'] += 1
                else:
                    self.dependency_stats['tree_resolved_packages'] += 1
            
            if package_name in self.compromised_packages:
                compromised_version = self.compromised_packages[package_name]
                if version == compromised_version:
                    self.log_finding(
                        'CRITICAL',
                        f'Compromised package in dependency tree: {package_name}@{version} (depth: {depth})',
                        file_path,
                        {
                            'package': package_name, 
                            'version': version, 
                            'depth': depth,
                            'tree_source': 'npm/yarn_list'
                        }
                    )
                    findings.append({
                        'package': package_name,
                        'version': version,
                        'file': file_path,
                        'depth': depth,
                        'source': 'dependency_tree'
                    })
                    self.dependency_stats['compromised_packages_found'] += 1
                else:
                    # Package is potentially vulnerable but using a safe version in dependency tree
                    self.track_safe_package(
                        package_name, version, compromised_version,
                        f'safe_tree_dependency', file_path, depth
                    )
                    self.log_finding(
                        'INFO',
                        f'Safe version in dependency tree: {package_name}@{version} (depth: {depth}, compromised: {compromised_version})',
                        file_path,
                        {
                            'package': package_name,
                            'safe_version': version,
                            'compromised_version': compromised_version,
                            'depth': depth,
                            'tree_source': 'npm/yarn_list'
                        }
                    )
                    
            # Recursively check nested dependencies
            if 'dependencies' in package_info and package_info['dependencies']:
                findings.extend(self.scan_dependency_tree_recursive(
                    package_info['dependencies'], file_path, depth + 1
                ))
                
        return findings

    def scan_package_json(self, file_path: str) -> List[Dict]:
        """Scan package.json for compromised packages"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
                
            # Check direct dependencies first
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in package_data:
                    for package_name, version in package_data[dep_type].items():
                        # Track all packages found
                        clean_version = re.sub(r'^[^\d]*', '', version)
                        self.track_package(package_name, clean_version, f'direct_{dep_type}', file_path, depth=0)
                        self.dependency_stats['direct_dependencies'] += 1
                        
                        if package_name in self.compromised_packages:
                            compromised_version = self.compromised_packages[package_name]
                            
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
                                self.dependency_stats['compromised_packages_found'] += 1
                            else:
                                # Package is potentially vulnerable but using a safe version
                                self.track_safe_package(
                                    package_name, clean_version, compromised_version, 
                                    f'safe_{dep_type}', file_path, depth=0
                                )
                                self.log_finding(
                                    'INFO',
                                    f'Safe version detected: {package_name}@{version} (compromised: {compromised_version})',
                                    file_path,
                                    {
                                        'package': package_name,
                                        'safe_version': version,
                                        'compromised_version': compromised_version,
                                        'dependency_type': dep_type
                                    }
                                )
            
            # If full tree analysis is enabled, also check the complete dependency tree
            if self.full_tree_analysis:
                package_dir = os.path.dirname(file_path)
                
                # Try to get dependency tree using npm or yarn
                dep_tree = {}
                
                # Check if yarn.lock exists (prefer yarn)
                if os.path.exists(os.path.join(package_dir, 'yarn.lock')):
                    print(f"🧶 Getting full dependency tree using yarn for {file_path}")
                    dep_tree = self.get_yarn_dependency_tree(package_dir)
                # Check if package-lock.json exists or node_modules (use npm)
                elif (os.path.exists(os.path.join(package_dir, 'package-lock.json')) or 
                      os.path.exists(os.path.join(package_dir, 'node_modules'))):
                    print(f"📦 Getting full dependency tree using npm for {file_path}")
                    dep_tree = self.get_npm_dependency_tree(package_dir)
                
                # Scan the full dependency tree if we got it
                if dep_tree and 'dependencies' in dep_tree:
                    tree_findings = self.scan_dependency_tree_recursive(
                        dep_tree['dependencies'], file_path, depth=1
                    )
                    findings.extend(tree_findings)
                    
                    if tree_findings:
                        self.log_finding(
                            'INFO',
                            f'Full dependency tree analysis found {len(tree_findings)} compromised packages',
                            file_path,
                            {'tree_findings_count': len(tree_findings)}
                        )
                                
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
                    version = package_info.get('version', '')
                    
                    # Track all packages found in lock file
                    if version:
                        depth = package_path.count('/') - 1  # Calculate depth from path
                        self.track_package(package_name, version, 'lock_file_v2_v3', file_path, depth)
                        self.dependency_stats['lock_file_packages'] += 1
                    
                    if package_name in self.compromised_packages:
                        compromised_version = self.compromised_packages[package_name]
                        if version == compromised_version:
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
                            self.dependency_stats['compromised_packages_found'] += 1
                        else:
                            # Package is potentially vulnerable but using a safe version
                            self.track_safe_package(
                                package_name, version, compromised_version,
                                'safe_lock_file_v2_v3', file_path, depth
                            )
                            self.log_finding(
                                'INFO',
                                f'Safe version in lock file: {package_name}@{version} (compromised: {compromised_version})',
                                file_path,
                                {
                                    'package': package_name,
                                    'safe_version': version,
                                    'compromised_version': compromised_version,
                                    'path': package_path
                                }
                            )
                            
        # Check dependencies in lockfile v1 format
        if 'dependencies' in lock_data:
            findings.extend(self._scan_dependencies_recursive(lock_data['dependencies'], file_path))
            
        return findings
        
    def _scan_dependencies_recursive(self, deps: Dict, file_path: str, prefix: str = '') -> List[Dict]:
        """Recursively scan dependencies in package-lock.json"""
        findings = []
        
        for package_name, package_info in deps.items():
            version = package_info.get('version', '')
            
            # Track all packages found in lock file
            if version:
                depth = len(prefix.split('/')) - 1 if prefix else 0
                self.track_package(package_name, version, 'lock_file_dependency', file_path, depth)
                self.dependency_stats['lock_file_packages'] += 1
            
            if package_name in self.compromised_packages:
                compromised_version = self.compromised_packages[package_name]
                if version == compromised_version:
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
                    self.dependency_stats['compromised_packages_found'] += 1
                else:
                    # Package is potentially vulnerable but using a safe version
                    depth = len(prefix.split('/')) - 1 if prefix else 0
                    self.track_safe_package(
                        package_name, version, compromised_version,
                        'safe_lock_file_dependency', file_path, depth
                    )
                    self.log_finding(
                        'INFO',
                        f'Safe version in lock dependencies: {package_name}@{version} (compromised: {compromised_version})',
                        file_path,
                        {
                            'package': package_name,
                            'safe_version': version,
                            'compromised_version': compromised_version
                        }
                    )
                    
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
        report_lines.append(f"Packages analyzed: {len(self.scanned_packages)}")
        report_lines.append("")
        
        # Summary by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        # Package analysis summary
        report_lines.append("PACKAGE ANALYSIS SUMMARY:")
        report_lines.append("-" * 30)
        report_lines.append(f"Direct dependencies: {self.dependency_stats['direct_dependencies']}")
        report_lines.append(f"Transitive dependencies: {self.dependency_stats['transitive_dependencies']}")
        report_lines.append(f"Lock file packages: {self.dependency_stats['lock_file_packages']}")
        if self.full_tree_analysis:
            report_lines.append(f"Tree resolved packages: {self.dependency_stats['tree_resolved_packages']}")
        report_lines.append(f"Compromised packages found: {self.dependency_stats['compromised_packages_found']}")
        report_lines.append(f"Safe versions found: {self.dependency_stats['safe_packages_found']}")
        report_lines.append("")
        
        # Package source breakdown
        source_counts = {}
        for package in self.scanned_packages:
            source = package['source']
            source_counts[source] = source_counts.get(source, 0) + 1
            
        if source_counts:
            report_lines.append("PACKAGE SOURCES:")
            report_lines.append("-" * 20)
            for source, count in sorted(source_counts.items()):
                report_lines.append(f"{source}: {count}")
            report_lines.append("")
        
        report_lines.append("SEVERITY SUMMARY:")
        report_lines.append("-" * 20)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'WARNING', 'ERROR', 'INFO']:
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
                    report_lines.append(f"   📁 Location: {finding['file']}")
                if finding['details']:
                    for key, value in finding['details'].items():
                        if key == 'depth' and value > 0:
                            report_lines.append(f"   🔗 Dependency depth: {value}")
                        elif key == 'dependency_type':
                            report_lines.append(f"   📦 Type: {value}")
                        elif key == 'tree_source':
                            report_lines.append(f"   🌳 Source: {value}")
                        elif key == 'path':
                            report_lines.append(f"   📂 Path: {value}")
                        elif key in ['package', 'version', 'compromised_version', 'safe_version']:
                            report_lines.append(f"   {key}: {value}")
                        else:
                            report_lines.append(f"   {key}: {value}")
                report_lines.append("")
        else:
            report_lines.append("✅ No compromised packages detected!")
            report_lines.append("")
            
        # Add safe packages summary
        if self.safe_packages:
            report_lines.append("SAFE VERSIONS OF POTENTIALLY VULNERABLE PACKAGES:")
            report_lines.append("-" * 50)
            
            # Group safe packages by name
            safe_by_name = {}
            for safe_pkg in self.safe_packages:
                name = safe_pkg['name']
                if name not in safe_by_name:
                    safe_by_name[name] = []
                safe_by_name[name].append(safe_pkg)
            
            for package_name in sorted(safe_by_name.keys()):
                safe_versions = safe_by_name[package_name]
                compromised_version = safe_versions[0]['compromised_version']
                unique_versions = list(set(pkg['version'] for pkg in safe_versions))
                
                report_lines.append(f"✅ {package_name}")
                report_lines.append(f"   Safe versions found: {', '.join(sorted(unique_versions))}")
                report_lines.append(f"   Compromised version: {compromised_version}")
                report_lines.append(f"   Found in {len(safe_versions)} location(s):")
                
                # Group by version and show locations
                versions_by_location = {}
                for pkg in safe_versions:
                    version = pkg['version']
                    if version not in versions_by_location:
                        versions_by_location[version] = []
                    
                    location_info = {
                        'file': pkg['file_path'],
                        'source': pkg['source'],
                        'depth': pkg['depth']
                    }
                    versions_by_location[version].append(location_info)
                
                for version in sorted(versions_by_location.keys()):
                    locations = versions_by_location[version]
                    report_lines.append(f"     v{version} ({len(locations)} location{'s' if len(locations) > 1 else ''}):")
                    
                    # Show locations (limit based on show_locations setting)
                    max_locations = len(locations) if hasattr(self, 'show_locations') and self.show_locations else 5
                    
                    for i, loc in enumerate(locations[:max_locations]):
                        depth_info = f" (depth: {loc['depth']})" if loc['depth'] > 0 else ""
                        source_info = f" [{loc['source']}]"
                        
                        # Add more detailed info if show_locations is enabled
                        if hasattr(self, 'show_locations') and self.show_locations:
                            # Extract directory structure for better readability
                            file_parts = loc['file'].split('/')
                            if len(file_parts) > 3:
                                short_path = f".../{'/'.join(file_parts[-3:])}"
                            else:
                                short_path = loc['file']
                            report_lines.append(f"       - 📁 {short_path}{depth_info}{source_info}")
                            if loc['file'] != short_path:
                                report_lines.append(f"         Full path: {loc['file']}")
                        else:
                            report_lines.append(f"       - {loc['file']}{depth_info}{source_info}")
                    
                    if len(locations) > max_locations:
                        report_lines.append(f"       ... and {len(locations) - max_locations} more location(s)")
                
                report_lines.append("")
            
        # Add detailed package list if requested
        if hasattr(self, 'include_package_list') and self.include_package_list and self.scanned_packages:
            report_lines.append("DETAILED PACKAGE LIST:")
            report_lines.append("-" * 25)
            
            # Sort packages by name for better readability
            sorted_packages = sorted(self.scanned_packages, key=lambda x: x['name'].lower())
            
            for package in sorted_packages:
                report_lines.append(f"📦 {package['name']}@{package['version']}")
                report_lines.append(f"   🏷️  Source: {package['source']}")
                if package['file_path']:
                    report_lines.append(f"   📁 File: {package['file_path']}")
                if package['depth'] > 0:
                    report_lines.append(f"   🔗 Depth: {package['depth']}")
                
                # Show all sources where this package was found
                package_key = package['key']
                if package_key in self.package_sources and len(self.package_sources[package_key]) > 1:
                    report_lines.append("   📍 Also found in:")
                    max_additional = 10 if hasattr(self, 'show_locations') and self.show_locations else 3
                    additional_sources = self.package_sources[package_key][1:max_additional + 1]
                    
                    for source_info in additional_sources:
                        depth_info = f" (depth: {source_info['depth']})" if source_info['depth'] > 0 else ""
                        report_lines.append(f"     - {source_info['source']}: {source_info['file_path']}{depth_info}")
                    
                    remaining = len(self.package_sources[package_key]) - 1 - len(additional_sources)
                    if remaining > 0:
                        report_lines.append(f"     ... and {remaining} more location(s)")
                
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
    parser.add_argument('--full-tree', action='store_true',
                       help='Enable full dependency tree analysis (slower but comprehensive)')
    parser.add_argument('--list-packages', action='store_true',
                       help='Include detailed list of all scanned packages in report')
    parser.add_argument('--show-locations', action='store_true',
                       help='Show detailed location information for all findings')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Only show critical findings')
    
    args = parser.parse_args()
    
    detector = NPMCompromiseDetector()
    
    # Enable full tree analysis if requested
    if args.full_tree:
        detector.enable_full_tree_analysis(True)
        print("🌳 Full dependency tree analysis enabled")
    
    # Enable package listing if requested
    if args.list_packages:
        detector.include_package_list = True
        print("📋 Detailed package listing enabled")
    
    # Enable detailed location information if requested
    if args.show_locations:
        detector.show_locations = True
        print("📍 Detailed location information enabled")
    
    print("🔍 Starting NPM compromise detection scan...")
    print(f"📁 Scanning directory: {os.path.abspath(args.directory)}")
    if args.full_tree:
        print("⚠️  Full tree analysis may take longer but will find all transitive dependencies")
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
