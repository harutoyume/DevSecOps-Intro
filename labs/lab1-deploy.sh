#!/bin/bash
#
# OWASP Juice Shop Deployment Script for Lab 1
# 
# This script deploys OWASP Juice Shop v19.0.0 locally for security testing.
# The container is bound to 127.0.0.1 only to prevent external exposure.
#
# Usage: bash labs/lab1-deploy.sh
#

set -e  # Exit on any error

# Configuration
CONTAINER_NAME="juice-shop"
IMAGE_NAME="bkimminich/juice-shop"
IMAGE_TAG="v19.0.0"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
HOST_IP="127.0.0.1"
HOST_PORT="3000"
CONTAINER_PORT="3000"

echo "================================================"
echo "OWASP Juice Shop Deployment Script"
echo "================================================"
echo ""

# Check if Docker is installed and running
echo "[1/5] Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo "   Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "ERROR: Docker daemon is not running"
    echo "   Please start Docker Desktop and try again"
    exit 1
fi
echo "Docker is installed and running"
echo ""

# Check if container already exists
echo "[2/5] Checking for existing Juice Shop container..."
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Container '${CONTAINER_NAME}' already exists"
    echo "   Removing existing container..."
    docker rm -f "${CONTAINER_NAME}" &> /dev/null
    echo "Existing container removed"
else
    echo "No existing container found"
fi
echo ""

# Pull the image
echo "[3/5] Pulling OWASP Juice Shop image..."
echo "   Image: ${FULL_IMAGE}"
docker pull "${FULL_IMAGE}"
echo "Image pulled successfully"
echo ""

# Get image digest for triage report
echo "[4/5] Retrieving image digest..."
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${FULL_IMAGE}" 2>/dev/null || echo "N/A")
echo "   Digest: ${IMAGE_DIGEST}"
echo ""

# Deploy the container
echo "[5/5] Deploying Juice Shop container..."
echo "   Container name: ${CONTAINER_NAME}"
echo "   Network binding: ${HOST_IP}:${HOST_PORT}"
echo "   Security: Bound to localhost only (no external exposure)"
echo ""

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${HOST_IP}:${HOST_PORT}:${CONTAINER_PORT}" \
  "${FULL_IMAGE}"

# Wait for container to start
echo "Waiting for container to start (5 seconds)..."
sleep 5

# Verify container is running
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Container deployed successfully!"
else
    echo "ERROR: Container failed to start"
    echo "   Check logs with: docker logs ${CONTAINER_NAME}"
    exit 1
fi

echo ""
echo "================================================"
echo "Deployment Complete!"
echo "================================================"
echo ""
echo "Deployment Summary:"
echo "   • Container: ${CONTAINER_NAME}"
echo "   • Image: ${FULL_IMAGE}"
echo "   • Digest: ${IMAGE_DIGEST}"
echo "   • Access URL: http://${HOST_IP}:${HOST_PORT}"
echo "   • Status: Running"
echo ""
