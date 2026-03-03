"""Cleanup Docker disk space and report status."""
import subprocess
import sys

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return r.stdout + r.stderr

print("=== DOCKER DISK USAGE (BEFORE) ===")
print(run(["docker", "system", "df"]))

print("=== PRUNING UNUSED CONTAINERS/IMAGES/NETWORKS ===")
print(run(["docker", "system", "prune", "-f"]))

print("=== PRUNING UNUSED VOLUMES ===")
print(run(["docker", "volume", "prune", "-f"]))

print("=== PRUNING UNUSED IMAGES (ALL) ===")
print(run(["docker", "image", "prune", "-a", "-f"]))

print("=== DOCKER DISK USAGE (AFTER) ===")
print(run(["docker", "system", "df"]))

print("=== RUNNING CONTAINERS ===")
print(run(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}"]))

print("DONE")
