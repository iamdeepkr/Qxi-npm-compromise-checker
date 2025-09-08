#!/bin/bash

# Demo script to show NPM compromise detection tools in action
# This script demonstrates both the quick check and comprehensive tools

set -e

echo "🎯 NPM Compromise Detection Tool Demo"
echo "====================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}📁 Demo files created in: $SCRIPT_DIR/test_demo/${NC}"
echo "   - package.json (with compromised packages)"
echo "   - suspicious_file.js (with malicious indicators)"
echo ""

echo -e "${YELLOW}🚀 Running Quick Check Tool...${NC}"
echo "----------------------------------------"
echo ""
cd "$SCRIPT_DIR"
./quick_check.sh test_demo/

echo ""
echo -e "${YELLOW}🔬 Running Comprehensive Python Tool...${NC}"
echo "------------------------------------------------"
echo ""
python3 npm_compromise_detector.py test_demo/ --output demo_report.txt

echo ""
echo -e "${GREEN}✅ Demo completed!${NC}"
echo ""
echo "📊 Check the generated report: demo_report.txt"
echo "🔍 Examine the test files in test_demo/ directory"
echo ""
echo -e "${RED}⚠️  Remember: These are test files with simulated malicious content.${NC}"
echo -e "${RED}   Use these tools on your real projects to detect actual threats!${NC}"
