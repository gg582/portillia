#!/usr/bin/env bash
set -e

# benchmark.sh - Measures RSS of the Portal relay in a Docker container.

# Ensure we are in the project root
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

IMAGE_NAME="portillia-benchmark"
CONTAINER_NAME="portillia-benchmark-$(date +%s)"

echo "Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

echo "Starting container: $CONTAINER_NAME"
CONTAINER_ID=$(docker run -d --name "$CONTAINER_NAME" "$IMAGE_NAME")

# Function to cleanup
cleanup() {
    echo "Stopping and removing container..."
    docker stop "$CONTAINER_ID" > /dev/null 2>&1 || true
    docker rm "$CONTAINER_ID" > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Waiting for application to start (5 seconds)..."
sleep 5

# Check if container is still running
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" != "true" ]; then
    echo "Error: Container is not running. Check 'docker logs $CONTAINER_ID' for details."
    exit 1
fi

# Get PID of the process inside the container from the host's perspective
PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_ID")

if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
    echo "Error: Failed to retrieve PID from container."
    exit 1
fi

# Measure RSS using ps
RSS_KB=$(ps -p "$PID" -o rss= | tr -d ' ')

echo ""
echo "========================================"
echo " PORTILLIA BENCHMARK (RSS)"
echo "========================================"
echo " Container ID: ${CONTAINER_ID:0:12}"
echo " Host PID:     $PID"
echo " RSS Usage:    ${RSS_KB} KB"

# Optional MB conversion if bc or awk is available
if command -v bc > /dev/null; then
    RSS_MB=$(echo "scale=2; $RSS_KB / 1024" | bc)
    echo " RSS Usage:    ${RSS_MB} MB"
elif command -v awk > /dev/null; then
    RSS_MB=$(awk "BEGIN {printf \"%.2f\", $RSS_KB/1024}")
    echo " RSS Usage:    ${RSS_MB} MB"
fi
echo "========================================"
echo ""

# Exit will trigger cleanup trap
