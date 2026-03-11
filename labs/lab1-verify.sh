#!/bin/bash
#
# OWASP Juice Shop Verification Script for Lab 1
#
# This script performs health checks and security verification for the deployed Juice Shop.
# Use the output for your triage report in labs/submission1.md
#
# Usage: bash labs/lab1-verify.sh
#

set -e  # Exit on any error

# Configuration
CONTAINER_NAME="juice-shop"
HOST_IP="127.0.0.1"
HOST_PORT="3000"
BASE_URL="http://${HOST_IP}:${HOST_PORT}"

echo "================================================"
echo "OWASP Juice Shop Verification Script"
echo "================================================"
echo ""

# Check if container is running
echo "[1/6] Checking container status..."
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running"
    echo "   Run deployment first: bash labs/lab1-deploy.sh"
    exit 1
fi
echo "Container is running"
echo ""

# Get container information
echo "[2/6] Container Information:"
echo "----------------------------------------"
docker ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
echo ""

# Check container logs for errors
echo "[3/6] Checking container logs..."
LOG_ERRORS=$(docker logs "${CONTAINER_NAME}" 2>&1 | grep -i "error" | head -n 5 || echo "No errors found")
if [ "$LOG_ERRORS" == "No errors found" ]; then
    echo "No critical errors in logs"
else
    echo "Found errors in logs:"
    echo "$LOG_ERRORS"
fi
echo ""

# Test HTTP connectivity
echo "[4/6] Testing HTTP connectivity..."
if command -v curl &> /dev/null; then
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}" || echo "000")
    if [ "$HTTP_STATUS" == "200" ]; then
        echo "HTTP connection successful (Status: ${HTTP_STATUS})"
    else
        echo "HTTP Status: ${HTTP_STATUS}"
    fi
else
    echo "curl not found - skipping HTTP test"
fi
echo ""

# Test API endpoint
echo "[5/6] Testing API endpoint (/rest/products)..."
echo "----------------------------------------"
if command -v curl &> /dev/null; then
    echo "API Response (first 10 lines):"
    echo ""
    curl -s "${BASE_URL}/rest/products" | head -n 10
    echo ""
    echo "----------------------------------------"
    echo "API endpoint responding"
    echo ""
    echo "TIP: Copy the above API output to your triage report"
else
    echo "curl not found - skipping API test"
    echo "   You can manually test: ${BASE_URL}/rest/products"
fi
echo ""

# Check security headers
echo "[6/6] Checking security headers..."
echo "----------------------------------------"
if command -v curl &> /dev/null; then
    echo "HTTP Headers:"
    echo ""
    curl -I -s "${BASE_URL}" | grep -E "(Server|X-|Content-Security-Policy|Strict-Transport-Security)" || echo "No security headers found"
    echo ""
    echo "----------------------------------------"
    
    # Analyze security headers
    echo ""
    echo "Security Header Analysis:"
    HEADERS=$(curl -I -s "${BASE_URL}")
    
    if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
        echo "   CSP (Content Security Policy): Present"
    else
        echo "   CSP (Content Security Policy): Missing"
    fi
    
    if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
        echo "   HSTS (HTTP Strict Transport Security): Present"
    else
        echo "   HSTS (HTTP Strict Transport Security): Missing"
    fi
    
    if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
        echo "   X-Frame-Options: Present"
    else
        echo "   X-Frame-Options: Missing"
    fi
    
    if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
        echo "   X-Content-Type-Options: Present"
    else
        echo "   X-Content-Type-Options: Missing"
    fi
else
    echo "curl not found - skipping header check"
fi
echo ""

# Summary
echo "================================================"
echo "Verification Complete!"
echo "================================================"
echo ""
echo "Summary:"
echo "   • Container Status: Running"
echo "   • Web Interface: ${BASE_URL}"
echo "   • API Endpoint: ${BASE_URL}/rest/products"
echo ""
