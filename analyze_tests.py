import subprocess, os, sys
from pathlib import Path

base = Path(r"C:\Users\Gadouri\Desktop\New folder (2)\phantom")
os.chdir(base)

failing_files = [
    "tests/test_all_modules.py",
    "tests/test_e2e_system.py",
    "tests/test_integration.py",
    "tests/test_p0_fixes.py",
    "tests/test_p1_fixes.py",
    "tests/test_scan_quality_fixes.py",
    "tests/test_security_fixes.py",
    "tests/test_v0910_coverage.py",
    "tests/test_v0912_wiring.py",
    "tests/test_v0913_fixes.py",
    "tests/test_v0915_security.py",
    "tests/test_v0916_hardening.py",
    "tests/test_v0917_fixes.py",
    "tests/test_v0918_features.py",
    "tests/test_v0920_audit_fixes.py",
    "tests/test_v093_security.py",
    "tests/test_v0940_dynamic_provider.py",
    "tests/test_v096_discovery.py",
    "tests/test_v098_features.py",
    "tests/test_v099_fixes.py",
]

for f in failing_files:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f, "-q", "--tb=no"],
        capture_output=True, text=True, cwd=base
    )
    # Get last non-empty line
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    summary = lines[-1] if lines else "(no output)"
    print(f"{f:<44} {summary}")
