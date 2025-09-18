#!/bin/bash

# Quick NPM Compromise Detection Script
# Checks for compromised packages from September 2025 supply chain attack
# Reference: https://github.com/debug-js/debug/issues/1005

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Compromised packages and versions (space-separated pairs)
COMPROMISED_PACKAGES="
ansi-styles:6.2.2
debug:4.4.2
chalk:5.6.1
supports-color:10.2.1
strip-ansi:7.1.1
ansi-regex:6.2.1
wrap-ansi:9.0.1
color-convert:3.1.1
color-name:2.0.1
is-arrayish:0.3.3
slice-ansi:7.1.1
color:5.0.1
color-string:2.1.1
simple-swizzle:0.2.3
supports-hyperlinks:4.1.1
has-ansi:6.0.1
chalk-template:1.1.1
backslash:0.2.1
"

FOUND_COMPROMISED=0
SCAN_DIR="${1:-.}"

echo -e "${BLUE}🔍 NPM Compromise Detection - Quick Check${NC}"
echo -e "${BLUE}===========================================${NC}"
echo "Scanning directory: $(realpath "$SCAN_DIR")"
echo "Reference: https://github.com/debug-js/debug/issues/1005"
echo ""

# Function to check package.json files
check_package_json() {
    local file="$1"
    echo "📦 Checking: $file"
    
    while IFS=: read -r package compromised_version; do
        if [ -n "$package" ] && [ -n "$compromised_version" ]; then
            # Check if package exists in dependencies with exact version
            if grep -q "\"$package\".*\".*$compromised_version" "$file" 2>/dev/null; then
                echo -e "${RED}🚨 CRITICAL: Found compromised package $package@$compromised_version in $file${NC}"
                FOUND_COMPROMISED=1
            fi
        fi
    done <<< "$COMPROMISED_PACKAGES"
}

# Function to check lock files
check_lock_file() {
    local file="$1"
    echo "🔒 Checking lock file: $file"
    
    while IFS=: read -r package compromised_version; do
        if [ -n "$package" ] && [ -n "$compromised_version" ]; then
            if [[ "$file" == *"package-lock.json" ]]; then
                # Check package-lock.json format - more precise pattern to avoid false positives
                # Handle both old format ("package": {) and new format ("node_modules/package": {)
                if { grep -A 10 "\"$package\": {" "$file" || grep -A 10 "\"node_modules/$package\": {" "$file"; } 2>/dev/null | grep -q "\"version\": \"$compromised_version\"" 2>/dev/null; then
                    echo -e "${RED}🚨 CRITICAL: Found compromised package $package@$compromised_version in $file${NC}"
                    FOUND_COMPROMISED=1
                fi
            elif [[ "$file" == *"yarn.lock" ]]; then
                # Check yarn.lock format - look for package@version or package@^version patterns
                # More precise: check if the exact compromised version appears in a version line under this package
                if grep -A 10 "^$package@" "$file" | grep -q "^  version \"$compromised_version\"" 2>/dev/null; then
                    echo -e "${RED}🚨 CRITICAL: Found compromised package $package@$compromised_version in $file${NC}"
                    FOUND_COMPROMISED=1
                fi
            fi
        fi
    done <<< "$COMPROMISED_PACKAGES"
}

# Function to check npm cache
check_npm_cache() {
    echo "🗂️  Checking npm cache..."
    
    if ! command -v npm &> /dev/null; then
        echo -e "${YELLOW}⚠️  npm not found, skipping cache check${NC}"
        return
    fi
    
    local cache_output
    if cache_output=$(npm cache ls 2>/dev/null); then
        while IFS=: read -r package compromised_version; do
            if [ -n "$package" ] && [ -n "$compromised_version" ]; then
                if echo "$cache_output" | grep -q "$package-$compromised_version"; then
                    echo -e "${RED}🚨 CRITICAL: Found compromised package $package@$compromised_version in npm cache${NC}"
                    FOUND_COMPROMISED=1
                fi
            fi
        done <<< "$COMPROMISED_PACKAGES"
    else
        echo -e "${YELLOW}⚠️  Could not access npm cache${NC}"
    fi
}

# Function to check for malicious URLs
check_malicious_urls() {
    local file="$1"
    local malicious_urls=("npmjs.help" "support@npmjs.help")
    
    for url in "${malicious_urls[@]}"; do
        if grep -q "$url" "$file" 2>/dev/null; then
            echo -e "${RED}🚨 HIGH: Found malicious URL '$url' in $file${NC}"
            FOUND_COMPROMISED=1
        fi
    done
}

# Main scanning logic
echo "🔍 Scanning for package.json files..."
while IFS= read -r -d '' file; do
    check_package_json "$file"
done < <(find "$SCAN_DIR" -name "package.json" -type f -print0 2>/dev/null)

echo ""
echo "🔍 Scanning for lock files..."
while IFS= read -r -d '' file; do
    check_lock_file "$file"
done < <(find "$SCAN_DIR" \( -name "package-lock.json" -o -name "yarn.lock" \) -type f -print0 2>/dev/null)

echo ""
echo "🔍 Scanning for malicious URLs in source files..."
while IFS= read -r -d '' file; do
    check_malicious_urls "$file"
done < <(find "$SCAN_DIR" \( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.mjs" \) -type f -print0 2>/dev/null | head -c 10000)

echo ""
check_npm_cache

echo ""
echo -e "${BLUE}===========================================${NC}"

if [ $FOUND_COMPROMISED -eq 1 ]; then
    echo -e "${RED}🚨 COMPROMISED PACKAGES DETECTED!${NC}"
    echo ""
    echo -e "${YELLOW}IMMEDIATE ACTIONS REQUIRED:${NC}"
    echo "1. 🛑 Stop any running applications"
    echo "2. 🧹 Clear npm cache: npm cache clean --force"
    echo "3. 📦 Update compromised packages to safe versions"
    echo "4. 🔍 Review application logs for suspicious activity"
    echo "5. 💰 If browser-based, check crypto wallets for compromise"
    echo ""
    echo -e "${YELLOW}Safe version overrides (add to package.json):${NC}"
    echo '  "overrides": {'
    echo '    "chalk": "5.3.0",'
    echo '    "strip-ansi": "7.1.0",'
    echo '    "color-convert": "2.0.1",'
    echo '    "color-name": "1.1.4",'
    echo '    "debug": "4.3.7",'
    echo '    "ansi-styles": "6.2.1",'
    echo '    "supports-color": "9.4.0"'
    echo '  }'
    echo ""
    exit 1
else
    echo -e "${GREEN}✅ No compromised packages detected!${NC}"
    echo -e "${GREEN}Your repository appears to be clean.${NC}"
    exit 0
fi
