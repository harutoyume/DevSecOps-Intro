#!/bin/bash
#
# OWASP Juice Shop Cleanup Script for Lab 1
#
# This script removes the Juice Shop container and optionally the image.
# Use this after completing the lab to free up system resources.
#
# Usage: bash labs/lab1-cleanup.sh [--remove-image]
#

set -e  # Exit on any error

# Configuration
CONTAINER_NAME="juice-shop"
IMAGE_NAME="bkimminich/juice-shop"
IMAGE_TAG="v19.0.0"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
REMOVE_IMAGE=false

# Parse arguments
if [ "$1" == "--remove-image" ]; then
    REMOVE_IMAGE=true
fi

echo "================================================"
echo "OWASP Juice Shop Cleanup Script"
echo "================================================"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

# Stop and remove container
echo "[1/2] Removing Juice Shop container..."
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "   Found container: ${CONTAINER_NAME}"
    
    # Stop if running
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "   Stopping running container..."
        docker stop "${CONTAINER_NAME}" &> /dev/null
    fi
    
    # Remove container
    echo "   Removing container..."
    docker rm "${CONTAINER_NAME}" &> /dev/null
    echo "Container removed successfully"
else
    echo "No container named '${CONTAINER_NAME}' found (already clean)"
fi
echo ""

# Remove image if requested
if [ "$REMOVE_IMAGE" == true ]; then
    echo "[2/2] Removing Juice Shop image..."
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${FULL_IMAGE}$"; then
        echo "   Found image: ${FULL_IMAGE}"
        echo "   Removing image..."
        docker rmi "${FULL_IMAGE}" &> /dev/null
        echo "Image removed successfully"
    else
        echo "Image '${FULL_IMAGE}' not found (already removed or never pulled)"
    fi
else
    echo "[2/2] Keeping Docker image"
    echo "   Image '${FULL_IMAGE}' preserved for future use"
    echo "   To remove image, run: bash labs/lab1-cleanup.sh --remove-image"
fi
echo ""

echo "================================================"
echo "Cleanup Complete!"
echo "================================================"
echo ""
echo "What was cleaned:"
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "   Container: Still exists (unexpected)"
else
    echo "   Container: Removed"
fi

if [ "$REMOVE_IMAGE" == true ]; then
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${FULL_IMAGE}$"; then
        echo "   Image: Still exists (unexpected)"
    else
        echo "   Image: Removed"
    fi
else
    echo "   Image: Preserved (not removed)"
fi
echo ""
