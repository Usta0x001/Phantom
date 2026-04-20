#!/bin/bash
set -e

# FIX: Export TOOL_SERVER_PORT before using
export TOOL_SERVER_PORT="${TOOL_SERVER_PORT:-48081}"

# Call original entrypoint with all args
exec /usr/local/bin/docker-entrypoint.sh "$@"
